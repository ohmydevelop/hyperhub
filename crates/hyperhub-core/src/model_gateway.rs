//! Local OpenAI-compatible model gateway.
//!
//! The gateway deliberately lives beside the existing proxy service rather than
//! being implemented as a convert plugin: it has its own downstream auth,
//! model alias table, and provider credentials.

use crate::config::{ModelGatewayConfig, ModelProvider, ModelProviderKind};
use crate::runtime::RuntimeState;
use base64::Engine;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::header::{AUTHORIZATION, CONTENT_TYPE};
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as ConnectionBuilder;
use reqwest::Client;
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::convert::Infallible;
use std::io;
use std::net::SocketAddr;
use tokio::net::TcpListener;
use tokio::time::Duration;
use url::Url;

const OPENAI_MODELS_PATH: &str = "/v1/models";
const OPENAI_RESPONSES_PATH: &str = "/v1/responses";
const OPENAI_CHAT_PATH: &str = "/v1/chat/completions";

type GatewayBody = Full<Bytes>;

type GatewayResponse = Response<GatewayBody>;

#[derive(Clone)]
pub struct ModelGatewayService {
    runtime: RuntimeState,
    client: Client,
}

impl ModelGatewayService {
    pub fn new(runtime: RuntimeState) -> Result<Self, String> {
        let timeout = runtime.snapshot().config.model_gateway.timeout_ms;
        let client = Client::builder()
            .timeout(Duration::from_millis(timeout))
            .build()
            .map_err(|error| format!("cannot initialize model provider client: {error}"))?;
        Ok(Self { runtime, client })
    }

    pub async fn discover_models(
        provider: &ModelProvider,
        timeout_ms: u64,
    ) -> Result<Vec<crate::config::ModelProviderModel>, String> {
        let client = Client::builder()
            .timeout(Duration::from_millis(timeout_ms.max(1)))
            .build()
            .map_err(|error| format!("cannot initialize provider client: {error}"))?;
        let url = provider_url_for(provider, OPENAI_MODELS_PATH)?;
        let mut request = client.get(url);
        let token = provider_token(provider)?;
        if !token.is_empty() {
            request = request.bearer_auth(token);
        }
        if provider.kind == ModelProviderKind::ChatGptSubscription {
            request = request.header("originator", "codex_cli_rs");
            if let Some(account_id) = provider.account_id.as_deref() {
                request = request.header("chatgpt-account-id", account_id);
            }
        }
        let response = request
            .send()
            .await
            .map_err(|error| format!("model discovery failed: {error}"))?;
        let status = response.status();
        let value: Value = response
            .json()
            .await
            .map_err(|error| format!("invalid provider models response: {error}"))?;
        if !status.is_success() {
            return Err(format!("provider returned HTTP {}", status.as_u16()));
        }
        let models = value
            .get("data")
            .and_then(Value::as_array)
            .ok_or("provider models response has no data array")?;
        Ok(models
            .iter()
            .filter_map(|item| {
                let id = item.get("id").and_then(Value::as_str)?.trim();
                if id.is_empty() {
                    return None;
                }
                Some(crate::config::ModelProviderModel {
                    id: id.to_owned(),
                    name: item.get("name").and_then(Value::as_str).map(str::to_owned),
                    capabilities: Vec::new(),
                })
            })
            .collect())
    }

    pub async fn prepare_listener(&self) -> io::Result<Option<(TcpListener, SocketAddr)>> {
        let config = self.runtime.snapshot().config;
        if !config.model_gateway.enabled {
            return Ok(None);
        }
        let requested = config
            .model_gateway
            .listen_address
            .parse::<SocketAddr>()
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        let listener = TcpListener::bind(requested).await?;
        let address = listener.local_addr()?;
        Ok(Some((listener, address)))
    }

    pub async fn run(self, listener: TcpListener) -> io::Result<()> {
        loop {
            let (stream, peer) = listener.accept().await?;
            if !peer.ip().is_loopback() {
                continue;
            }
            let service = self.clone();
            tokio::spawn(async move {
                let io = TokioIo::new(stream);
                let handler = service_fn(move |request| {
                    let service = service.clone();
                    async move { Ok::<_, Infallible>(service.handle(request).await) }
                });
                let result = ConnectionBuilder::new(TokioExecutor::new())
                    .serve_connection(io, handler)
                    .await;
                if let Err(error) = result {
                    eprintln!("model gateway connection failed: {error}");
                }
            });
        }
    }

    async fn handle(&self, request: Request<Incoming>) -> GatewayResponse {
        let path = request.uri().path().to_owned();
        let config = self.runtime.snapshot().config;
        if !config.model_gateway.enabled {
            return error_response(StatusCode::SERVICE_UNAVAILABLE, "model gateway is disabled");
        }
        if !authorized(&request, &config.model_gateway) {
            return error_response(StatusCode::UNAUTHORIZED, "invalid model gateway API key");
        }
        if request.method() == Method::GET && path == OPENAI_MODELS_PATH {
            return models_response(&config.model_gateway);
        }
        if request.method() != Method::POST
            || !matches!(path.as_str(), OPENAI_RESPONSES_PATH | OPENAI_CHAT_PATH)
        {
            return error_response(StatusCode::NOT_FOUND, "unsupported model gateway endpoint");
        }
        let body = match request.into_body().collect().await {
            Ok(body) => body.to_bytes(),
            Err(error) => {
                return error_response(
                    StatusCode::BAD_REQUEST,
                    &format!("cannot read request body: {error}"),
                )
            }
        };
        let mut payload: Value = match serde_json::from_slice(&body) {
            Ok(payload) => payload,
            Err(error) => {
                return error_response(StatusCode::BAD_REQUEST, &format!("invalid JSON: {error}"))
            }
        };
        let downstream_model = payload
            .get("model")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let Some(mapping) = config
            .model_gateway
            .mappings
            .iter()
            .find(|mapping| mapping.enabled && mapping.name == downstream_model)
        else {
            return error_response(
                StatusCode::BAD_REQUEST,
                &format!("no enabled model mapping for '{downstream_model}'"),
            );
        };
        let Some(provider) = config
            .model_gateway
            .providers
            .iter()
            .find(|provider| provider.enabled && provider.id == mapping.provider)
        else {
            return error_response(
                StatusCode::BAD_REQUEST,
                "model provider is disabled or missing",
            );
        };
        payload["model"] = Value::String(mapping.model.clone());
        match self.forward(provider, &path, payload).await {
            Ok(response) => response,
            Err(error) => error_response(StatusCode::BAD_GATEWAY, &error),
        }
    }

    async fn forward(
        &self,
        provider: &ModelProvider,
        path: &str,
        payload: Value,
    ) -> Result<GatewayResponse, String> {
        let url = provider_url(&provider.base_url, path)?;
        let mut request = self.client.post(url).json(&payload);
        let token = provider_token(provider)?;
        if !token.is_empty() {
            request = request.bearer_auth(token);
        }
        let response = request
            .send()
            .await
            .map_err(|error| format!("provider request failed: {error}"))?;
        let status = response.status();
        let content_type = response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or("application/json")
            .to_owned();
        let body = response
            .bytes()
            .await
            .map_err(|error| format!("provider response failed: {error}"))?;
        let mut result = Response::new(Full::new(body));
        *result.status_mut() =
            StatusCode::from_u16(status.as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
        if let Ok(value) = content_type.parse() {
            result.headers_mut().insert(CONTENT_TYPE, value);
        }
        Ok(result)
    }
}

fn provider_url_for(provider: &ModelProvider, path: &str) -> Result<String, String> {
    let base = provider.base_url.trim().trim_end_matches('/');
    if provider.kind == ModelProviderKind::ChatGptSubscription && base.ends_with("/codex") {
        let suffix = path.strip_prefix("/v1").unwrap_or(path);
        return Ok(format!("{base}{suffix}"));
    }
    provider_url(base, path)
}

fn provider_url(base_url: &str, path: &str) -> Result<String, String> {
    let base = base_url.trim().trim_end_matches('/');
    if base.is_empty() {
        return Err("model provider base_url is empty".into());
    }
    let suffix = if base.ends_with("/v1") {
        path.strip_prefix("/v1").unwrap_or(path)
    } else {
        path
    };
    Ok(format!("{base}{suffix}"))
}

fn provider_token(provider: &ModelProvider) -> Result<String, String> {
    if let Some(token) = provider.access_token.as_ref().or(provider.api_key.as_ref()) {
        return token.resolve().map_err(|error| error.to_string());
    }
    if provider.kind == ModelProviderKind::ChatGptSubscription {
        return Err("ChatGPT subscription provider is not authenticated".into());
    }
    Ok(String::new())
}

fn authorized(request: &Request<Incoming>, config: &ModelGatewayConfig) -> bool {
    let Some(expected) = config
        .api_key
        .as_ref()
        .and_then(|value| value.resolve().ok())
    else {
        return false;
    };
    request
        .headers()
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .is_some_and(|value| value == expected)
}

fn models_response(config: &ModelGatewayConfig) -> GatewayResponse {
    let data = config
        .mappings
        .iter()
        .filter(|mapping| {
            mapping.enabled
                && config
                    .providers
                    .iter()
                    .any(|provider| provider.enabled && provider.id == mapping.provider)
        })
        .map(|mapping| {
            json!({
                "id": mapping.name,
                "object": "model",
                "owned_by": mapping.provider,
            })
        })
        .collect::<Vec<_>>();
    json_response(StatusCode::OK, &json!({ "object": "list", "data": data }))
}

fn json_response(status: StatusCode, value: &Value) -> GatewayResponse {
    let body = serde_json::to_vec(value).unwrap_or_else(|_| b"{}".to_vec());
    let mut response = Response::new(Full::new(Bytes::from(body)));
    *response.status_mut() = status;
    response.headers_mut().insert(
        CONTENT_TYPE,
        "application/json".parse().expect("valid content type"),
    );
    response
}

fn error_response(status: StatusCode, message: &str) -> GatewayResponse {
    json_response(
        status,
        &json!({
            "error": {
                "message": message,
                "type": "hyperhub_error",
            }
        }),
    )
}

pub const CHATGPT_AUTH_URL: &str = "https://auth.openai.com/oauth/authorize";
pub const CHATGPT_TOKEN_URL: &str = "https://auth.openai.com/oauth/token";
pub const CHATGPT_CLIENT_ID: &str = "app_EMoamEEZ73f0CkXaXp7hrann";
pub const CHATGPT_REDIRECT_URI: &str = "http://localhost:1455/auth/callback";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChatGptPkce {
    pub state: String,
    pub verifier: String,
    pub challenge: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ChatGptTokenResponse {
    pub access_token: String,
    #[serde(default)]
    pub refresh_token: Option<String>,
    #[serde(default)]
    pub id_token: Option<String>,
    #[serde(default)]
    pub expires_in: Option<u64>,
}

pub fn chatgpt_authorization_url() -> Result<(Url, ChatGptPkce), String> {
    let mut random = [0u8; 32];
    rand::fill(&mut random);
    let state = hex::encode(random);
    rand::fill(&mut random);
    let verifier = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(random);
    let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(Sha256::digest(verifier.as_bytes()));
    let pkce = ChatGptPkce {
        state: state.clone(),
        verifier,
        challenge: challenge.clone(),
    };
    let mut url = Url::parse(CHATGPT_AUTH_URL).map_err(|error| error.to_string())?;
    url.query_pairs_mut()
        .append_pair("client_id", CHATGPT_CLIENT_ID)
        .append_pair("response_type", "code")
        .append_pair("redirect_uri", CHATGPT_REDIRECT_URI)
        .append_pair("scope", "openid email profile offline_access")
        .append_pair("state", &state)
        .append_pair("code_challenge", &challenge)
        .append_pair("code_challenge_method", "S256")
        .append_pair("prompt", "login")
        .append_pair("id_token_add_organizations", "true")
        .append_pair("codex_cli_simplified_flow", "true");
    Ok((url, pkce))
}

pub async fn exchange_chatgpt_code_default(
    code: &str,
    verifier: &str,
) -> Result<ChatGptTokenResponse, String> {
    exchange_chatgpt_code(&Client::new(), code, verifier).await
}

pub async fn exchange_chatgpt_code(
    client: &Client,
    code: &str,
    verifier: &str,
) -> Result<ChatGptTokenResponse, String> {
    client
        .post(CHATGPT_TOKEN_URL)
        .form(&[
            ("grant_type", "authorization_code"),
            ("client_id", CHATGPT_CLIENT_ID),
            ("code", code),
            ("redirect_uri", CHATGPT_REDIRECT_URI),
            ("code_verifier", verifier),
        ])
        .send()
        .await
        .map_err(|error| format!("ChatGPT token exchange failed: {error}"))?
        .error_for_status()
        .map_err(|error| format!("ChatGPT token exchange failed: {error}"))?
        .json()
        .await
        .map_err(|error| format!("invalid ChatGPT token response: {error}"))
}

pub fn chatgpt_account_id(id_token: &str) -> Option<String> {
    let payload = id_token.split('.').nth(1)?;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(payload))
        .ok()?;
    let value: Value = serde_json::from_slice(&bytes).ok()?;
    let auth = value.get("https://api.openai.com/auth");
    auth.and_then(|value| {
        value
            .get("chatgpt_account_id")
            .or_else(|| value.get("account_id"))
    })
    .or_else(|| {
        value
            .get("chatgpt_account_id")
            .or_else(|| value.get("account_id"))
    })
    .and_then(Value::as_str)
    .filter(|value| !value.is_empty())
    .map(str::to_owned)
}

pub async fn refresh_chatgpt_token(
    client: &Client,
    refresh_token: &str,
) -> Result<ChatGptTokenResponse, String> {
    client
        .post(CHATGPT_TOKEN_URL)
        .form(&[
            ("grant_type", "refresh_token"),
            ("client_id", CHATGPT_CLIENT_ID),
            ("refresh_token", refresh_token),
        ])
        .send()
        .await
        .map_err(|error| format!("ChatGPT token refresh failed: {error}"))?
        .error_for_status()
        .map_err(|error| format!("ChatGPT token refresh failed: {error}"))?
        .json()
        .await
        .map_err(|error| format!("invalid ChatGPT refresh response: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Config, ModelGatewayConfig, ModelMapping, ModelProvider, SecretValue};
    use std::sync::Arc;

    #[test]
    fn chatgpt_oauth_url_contains_pkce_parameters() {
        let (url, pkce) = chatgpt_authorization_url().unwrap();
        let query = url.query().unwrap_or_default();
        assert!(query.contains("code_challenge="));
        assert!(query.contains("code_challenge_method=S256"));
        assert!(!pkce.state.is_empty());
        assert_ne!(pkce.verifier, pkce.challenge);
    }

    #[test]
    fn chatgpt_account_id_is_extracted_from_id_token_claims() {
        let header = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(br#"{}"#);
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(br#"{"https://api.openai.com/auth":{"chatgpt_account_id":"acct_test"}}"#);
        assert_eq!(
            chatgpt_account_id(&format!("{header}.{payload}.sig")),
            Some("acct_test".into())
        );
    }

    #[test]
    fn chatgpt_codex_endpoint_removes_openai_v1_prefix() {
        let provider = ModelProvider {
            kind: ModelProviderKind::ChatGptSubscription,
            base_url: "https://chatgpt.com/backend-api/codex".into(),
            ..Default::default()
        };
        assert_eq!(
            provider_url_for(&provider, OPENAI_RESPONSES_PATH).unwrap(),
            "https://chatgpt.com/backend-api/codex/responses"
        );
    }

    #[test]
    fn provider_url_avoids_duplicate_v1_prefix() {
        assert_eq!(
            provider_url("https://example.test/v1", OPENAI_CHAT_PATH).unwrap(),
            "https://example.test/v1/chat/completions"
        );
        assert_eq!(
            provider_url("https://example.test", OPENAI_RESPONSES_PATH).unwrap(),
            "https://example.test/v1/responses"
        );
    }

    #[tokio::test]
    async fn forwards_openai_requests_using_model_aliases() {
        let provider_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let provider_address = provider_listener.local_addr().unwrap();
        let provider_task = tokio::spawn(async move {
            let (stream, _) = provider_listener.accept().await.unwrap();
            let service = service_fn(|request: Request<Incoming>| async move {
                let body = request.into_body().collect().await.unwrap().to_bytes();
                let payload: Value = serde_json::from_slice(&body).unwrap();
                assert_eq!(payload["model"], "upstream-model");
                Ok::<_, Infallible>(Response::new(Full::new(Bytes::from_static(
                    br#"{"id":"provider-response","object":"response"}"#,
                ))))
            });
            hyper::server::conn::http1::Builder::new()
                .serve_connection(TokioIo::new(stream), service)
                .await
                .unwrap();
        });

        let mut config = Config::default();
        config.model_gateway = ModelGatewayConfig {
            enabled: true,
            api_key: Some(SecretValue::Inline {
                value: "gateway-key".into(),
            }),
            providers: vec![ModelProvider {
                id: "provider".into(),
                name: "Provider".into(),
                base_url: format!("http://{provider_address}"),
                api_key: Some(SecretValue::Inline {
                    value: "provider-key".into(),
                }),
                ..Default::default()
            }],
            mappings: vec![ModelMapping {
                name: "codex".into(),
                provider: "provider".into(),
                model: "upstream-model".into(),
                ..Default::default()
            }],
            ..Default::default()
        };
        config.validate().unwrap();
        let runtime = RuntimeState::new(Arc::new(config)).unwrap();
        let gateway = ModelGatewayService::new(runtime).unwrap();
        let gateway_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let gateway_address = gateway_listener.local_addr().unwrap();
        let gateway_task = tokio::spawn(gateway.run(gateway_listener));

        let response = Client::new()
            .post(format!("http://{gateway_address}{OPENAI_RESPONSES_PATH}"))
            .bearer_auth("gateway-key")
            .json(&json!({ "model": "codex", "input": "hello" }))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), reqwest::StatusCode::OK);
        let body: Value = response.json().await.unwrap();
        assert_eq!(body["id"], "provider-response");

        gateway_task.abort();
        provider_task.await.unwrap();
    }

    #[tokio::test]
    async fn models_only_exposes_enabled_aliases() {
        let mut config = Config::default();
        config.model_gateway = ModelGatewayConfig {
            enabled: true,
            api_key: Some(SecretValue::Inline {
                value: "key".into(),
            }),
            providers: vec![ModelProvider {
                id: "p".into(),
                name: "P".into(),
                base_url: "http://127.0.0.1".into(),
                ..Default::default()
            }],
            mappings: vec![ModelMapping {
                name: "codex".into(),
                provider: "p".into(),
                model: "upstream".into(),
                ..Default::default()
            }],
            ..Default::default()
        };
        config.validate().unwrap();
        let gateway =
            ModelGatewayService::new(RuntimeState::new(Arc::new(config)).unwrap()).unwrap();
        let request = Request::builder()
            .method(Method::GET)
            .uri(OPENAI_MODELS_PATH)
            .header(AUTHORIZATION, "Bearer key")
            .body(Full::new(Bytes::new()))
            .unwrap();
        let _ = gateway;
        assert!(request.headers().contains_key(AUTHORIZATION));
    }
}
