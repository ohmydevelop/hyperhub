use super::support::*;
use base64::Engine;
use hyperhub_core::config::{
    Config, PluginConfig, PluginKind, PluginProtocol, SecretValue, SshAccount, SshHostKey,
};
use russh::{client, server, Channel, ChannelId, ChannelMsg};
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::TcpListener;

struct Echo;
impl server::Handler for Echo {
    type Error = russh::Error;
    async fn auth_password(
        &mut self,
        user: &str,
        password: &str,
    ) -> Result<server::Auth, Self::Error> {
        Ok(
            if user == "fixture-user" && password == "local-upstream-password" {
                server::Auth::Accept
            } else {
                server::Auth::reject()
            },
        )
    }
    async fn channel_open_session(
        &mut self,
        _channel: Channel<server::Msg>,
        reply: server::ChannelOpenHandle,
        _session: &mut server::Session,
    ) -> Result<(), Self::Error> {
        reply.accept().await;
        Ok(())
    }
    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut server::Session,
    ) -> Result<(), Self::Error> {
        session.data(channel, data.to_vec())?;
        Ok(())
    }
}
struct CheckKey(Arc<Mutex<Option<russh::keys::PublicKey>>>);
impl client::Handler for CheckKey {
    type Error = russh::Error;
    async fn check_server_key(
        &mut self,
        key: &russh::keys::PublicKey,
    ) -> Result<bool, Self::Error> {
        let mut original = self.0.lock().unwrap();
        if let Some(original) = &*original {
            Ok(original == key)
        } else {
            *original = Some(key.clone());
            Ok(true)
        }
    }
}
async fn exchange(channel: &mut Channel<client::Msg>, bytes: &[u8]) {
    channel.data(bytes).await.unwrap();
    let mut observed = Vec::new();
    tokio::time::timeout(Duration::from_secs(10), async {
        while observed.len() < bytes.len() {
            match channel.wait().await {
                Some(ChannelMsg::Data { data }) => observed.extend_from_slice(&data),
                other => panic!("SSH echo ended: {other:?}"),
            }
        }
    })
    .await
    .unwrap();
    assert_eq!(observed, bytes);
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires built forwarding worker fixture or final CLI"]
async fn ssh_mitm_reuses_host_identity_and_keeps_authenticated_channels_across_workers() {
    let key =
        russh::keys::PrivateKey::random(&mut rand::rng(), russh::keys::Algorithm::Ed25519).unwrap();
    let public = key.public_key().clone();
    let config = Arc::new(server::Config {
        keys: vec![key],
        auth_rejection_time: Duration::ZERO,
        ..Default::default()
    });
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let address = listener.local_addr().unwrap();
    let origin = tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            let config = config.clone();
            tokio::spawn(async move {
                if let Ok(running) = server::run_stream(config, stream, Echo).await {
                    let _ = running.await;
                }
            });
        }
    });
    let mut config = Config::default();
    config.plugins.push(PluginConfig {
        id: "ssh-credential".into(),
        kind: PluginKind::Credential,
        protocols: vec![PluginProtocol::Ssh],
        ssh_accounts: vec![SshAccount {
            username: "fixture-user".into(),
            private_keys: vec![],
            passwords: vec![SecretValue::Inline {
                value: "local-upstream-password".into(),
            }],
        }],
        ..Default::default()
    });
    config.plugins.push(PluginConfig {
        id: "ssh-audit".into(),
        kind: PluginKind::Audit,
        protocols: vec![PluginProtocol::Ssh],
        ssh_transcript: true,
        ..Default::default()
    });
    config.default_route.plugins = vec!["ssh-credential".into(), "ssh-audit".into()];
    config.ssh_host_keys.push(SshHostKey {
        uuid: hyperhub_core::config::new_config_uuid(),
        host: address.to_string(),
        key_type: public.algorithm().to_string(),
        key_blob: base64::engine::general_purpose::STANDARD.encode(public.to_bytes().unwrap()),
        enabled: true,
    });
    let fixture = Fixture::start_with(config, vec![]).await;
    let expected = Arc::new(Mutex::new(None));
    let stream = fixture.connect(1, address).await;
    let mut old = tokio::time::timeout(
        Duration::from_secs(10),
        client::connect_stream(
            Arc::new(client::Config::default()),
            stream,
            CheckKey(expected.clone()),
        ),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(old
        .authenticate_none("fixture-user")
        .await
        .unwrap()
        .success());
    // Only the worker has the configured upstream password. An unauthenticated
    // passthrough cannot satisfy this none-authentication assertion.
    let mut old_channel = old.channel_open_session().await.unwrap();
    exchange(&mut old_channel, b"old-SSH-before-switch").await;
    let manager = fixture.manager.clone();
    let binary = executable();
    let hash = digest(&binary);
    tokio::task::spawn_blocking(move || manager.prepare("ssh-switch", &binary, &hash))
        .await
        .unwrap()
        .unwrap();
    fixture.manager.commit("ssh-switch").unwrap();
    fixture.manager.finalize("ssh-switch").unwrap();
    let stream = fixture.connect(2, address).await;
    let mut new = tokio::time::timeout(
        Duration::from_secs(10),
        client::connect_stream(
            Arc::new(client::Config::default()),
            stream,
            CheckKey(expected),
        ),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(new
        .authenticate_none("fixture-user")
        .await
        .unwrap()
        .success());
    let mut new_channel = new.channel_open_session().await.unwrap();
    for index in 0..16 {
        let bytes = format!("SSH-generation-echo-{index:04}");
        exchange(&mut old_channel, bytes.as_bytes()).await;
        exchange(&mut new_channel, bytes.as_bytes()).await;
    }
    assert_eq!(
        fixture.manager.query("ssh-switch").unwrap().phase,
        "draining"
    );
    old.disconnect(russh::Disconnect::ByApplication, "fixture finished", "")
        .await
        .unwrap();
    new.disconnect(russh::Disconnect::ByApplication, "fixture finished", "")
        .await
        .unwrap();
    drop((old_channel, new_channel, old, new));
    fixture.stop().await;
    origin.abort();
}
