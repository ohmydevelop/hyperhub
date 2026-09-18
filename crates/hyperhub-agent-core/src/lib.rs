//! Process-local state and Windows Frida Gum hooks for the injected Agent.

#[cfg(any(test, all(windows, feature = "gum-agent")))]
mod hook_runtime;
#[cfg(all(windows, feature = "gum-agent"))]
mod integrity;

mod abi;
mod control;
mod gateway;
#[cfg(all(windows, feature = "gum-agent"))]
mod lifecycle;
mod platform;
mod runtime;
mod sandbox;
#[cfg(all(target_os = "linux", feature = "gum-agent"))]
mod unix_gum;
#[cfg(all(windows, feature = "gum-agent"))]
mod windows_gum;

pub use abi::*;
pub(crate) use control::*;
pub(crate) use gateway::*;
#[cfg(all(windows, feature = "gum-agent"))]
pub(crate) use lifecycle::*;
pub(crate) use runtime::*;
pub(crate) use sandbox::*;

#[cfg(test)]
mod tests {
    use super::*;

    fn configured_core() -> AgentRuntime {
        AgentRuntime {
            session: SessionState {
                initialized: true,
                session_id: "session".into(),
                token: "token".into(),
                control_endpoint: "test".into(),
            },
            gateway: GatewayState {
                proxy: Some("127.0.0.1:18444".parse().unwrap()),
                next_connection_id: 7,
                ..GatewayState::default()
            },
            trust: TrustState {
                tls_ca_pem:
                    b"-----BEGIN CERTIFICATE-----\nhyperhub-root\n-----END CERTIFICATE-----\n"
                        .to_vec(),
                ..TrustState::default()
            },
            sandbox: SandboxState::default(),
        }
    }

    #[test]
    fn preserves_public_agent_abi_layout() {
        assert_eq!(ABI_VERSION, 0x0002_0000);
        assert_eq!(std::mem::size_of::<HhConnectPlan>(), 40);
        assert_eq!(HhConnectPlan::default().struct_size, 40);
    }

    #[test]
    fn accepts_resolved_name_control_response() {
        let response: AgentControlResponse = serde_json::from_str(
            r#"{"type":"resolved_name","address":"198.18.0.1","ttl_secs":60}"#,
        )
        .unwrap();
        assert!(matches!(
            response,
            AgentControlResponse::ResolvedName { ref address, .. }
                if address == "198.18.0.1"
        ));
    }

    #[test]
    fn accepts_public_trust_bootstrap() {
        let response: AgentControlResponse = serde_json::from_str(
            r#"{"type":"trust_bootstrap","socks_address":"127.0.0.1:18444","agent_flags":{"observe":true},"environment":[{"name":"CURRENT_TOKEN","value":"latest"}],"tls_ca_pem":"-----BEGIN CERTIFICATE-----\nroot\n-----END CERTIFICATE-----\n"}"#,
        )
        .unwrap();
        assert!(matches!(
            response,
            AgentControlResponse::TrustBootstrap {
                ref socks_address,
                ref agent_flags,
                ref environment,
                ref tls_ca_pem,
                ..
            } if socks_address == "127.0.0.1:18444"
                && agent_flags.observe
                && environment[0].name == "CURRENT_TOKEN"
                && environment[0].value == "latest"
                && tls_ca_pem.contains("BEGIN CERTIFICATE")
        ));
    }

    #[test]
    fn accepts_firewall_snapshot_from_trust_bootstrap() {
        let response: AgentControlResponse = serde_json::from_str(
            r#"{"type":"trust_bootstrap","socks_address":"127.0.0.1:18444","agent_flags":{"observe":false},"environment":[],"tls_ca_pem":"-----BEGIN CERTIFICATE-----\nroot\n-----END CERTIFICATE-----\n","firewall":{"version":7,"default_action":"pass","rules":[{"id":"deny-example","action":"deny","endpoints":[{"target":{"kind":"domain","value":"example.com"},"port":443},{"target":{"kind":"network","value":"10.0.0.0/8"},"port":443}]}]}}"#,
        )
        .unwrap();
        assert!(matches!(
            response,
            AgentControlResponse::TrustBootstrap {
                firewall: Some(FirewallSnapshot { version: 7, ref rules, .. }),
                ..
            } if rules[0].id == "deny-example"
        ));
    }

    #[cfg(all(windows, feature = "gum-agent"))]
    #[test]
    fn accepts_process_hook_decision_response() {
        let response: AgentControlResponse = serde_json::from_str(
            r#"{"type":"process_hook_decision","hook":false,"rule_id":"skip-helper","source":"rule","version":12}"#,
        )
        .unwrap();
        assert!(matches!(
            response,
            AgentControlResponse::ProcessHookDecision {
                hook: false,
                _rule_id: Some(ref rule_id),
                ref _source,
                _version: 12,
            } if rule_id == "skip-helper" && _source == "rule"
        ));
    }

    #[cfg(all(windows, feature = "gum-agent"))]
    #[test]
    fn accepts_firewall_refresh_response() {
        let response: AgentControlResponse = serde_json::from_str(
            r#"{"type":"firewall_refresh","version":9,"changed":true,"firewall":null}"#,
        )
        .unwrap();
        assert!(matches!(
            response,
            AgentControlResponse::FirewallRefresh {
                version: 9,
                changed: true,
                firewall: None,
            }
        ));
    }

    #[test]
    fn invalid_firewall_snapshot_degrades_to_none() {
        let response: AgentControlResponse = serde_json::from_str(
            r#"{"type":"trust_bootstrap","socks_address":"127.0.0.1:18444","agent_flags":{"observe":false},"environment":[],"tls_ca_pem":"-----BEGIN CERTIFICATE-----\nroot\n-----END CERTIFICATE-----\n","firewall":{"version":"invalid"}}"#,
        )
        .unwrap();
        assert!(matches!(
            response,
            AgentControlResponse::TrustBootstrap { firewall: None, .. }
        ));
    }

    #[cfg(all(windows, feature = "gum-agent"))]
    #[test]
    fn accepts_inherited_child_bootstrap() {
        let response: AgentControlResponse = serde_json::from_str(
            r#"{"type":"agent_bootstrap","socks_address":"127.0.0.1:18444","control_endpoint":"\\\\.\\pipe\\hyperhub-control","session_id":"parent","token":"secret","tls_ca_pem":"-----BEGIN CERTIFICATE-----\nroot\n-----END CERTIFICATE-----\n","agent_flags":{"observe":false},"environment":[{"name":"GH_TOKEN","value":"configured"}]}"#,
        )
        .unwrap();
        assert!(matches!(
            response,
            AgentControlResponse::AgentBootstrap { ref session_id, ref environment, .. }
                if session_id == "parent" && environment[0].name == "GH_TOKEN"
        ));
        assert_eq!(
            serde_json::to_string(&AgentControlRequest::BootstrapChild).unwrap(),
            r#"{"type":"bootstrap_child"}"#
        );
    }

    #[test]
    fn appends_server_root_to_a_file_ca_bundle() {
        let source = std::env::temp_dir().join(format!(
            "hyperhub-agent-test-{}-{}.pem",
            std::process::id(),
            stable_hash(b"appends-server-root")
        ));
        std::fs::write(
            &source,
            b"-----BEGIN CERTIFICATE-----\nexisting\n-----END CERTIFICATE-----\n",
        )
        .unwrap();
        let mut core = configured_core();
        let replacement = core
            .trust
            .redirect_ca_bundle(&source.to_string_lossy())
            .unwrap();
        let merged = std::fs::read(&replacement).unwrap();
        assert!(merged
            .windows(core.trust.tls_ca_pem.len())
            .any(|window| window == core.trust.tls_ca_pem.as_slice()));
        let _ = std::fs::remove_file(source);
        let _ = std::fs::remove_file(replacement);
    }

    #[test]
    fn composes_existing_and_hyperhub_ca_without_duplicates() {
        let existing =
            vec![b"-----BEGIN CERTIFICATE-----\nexisting\n-----END CERTIFICATE-----".to_vec()];
        let root = b"-----BEGIN CERTIFICATE-----\nhyperhub\n-----END CERTIFICATE-----\n";
        let bundle = compose_ca_bundle(&existing, root);
        assert!(bundle
            .windows(existing[0].len())
            .any(|window| window == existing[0]));
        assert_eq!(
            bundle
                .windows(root.len())
                .filter(|window| *window == root)
                .count(),
            1
        );
        let bundle = compose_ca_bundle(&[bundle], root);
        assert_eq!(
            bundle
                .windows(root.len())
                .filter(|window| *window == root)
                .count(),
            1
        );
    }

    #[test]
    fn builds_domain_socks_handshake() {
        let mut core = configured_core();
        core.gateway
            .dns
            .insert((2, vec![192, 0, 2, 1]), "github.com".into());
        let plan = core.prepare_connect(42, 2, &[192, 0, 2, 1], 22).unwrap();
        assert_eq!(plan.connection_id, 7);
        assert_eq!(core.handshake(42, 0).unwrap(), [5, 1, 2]);
        assert!(String::from_utf8(core.handshake(42, 1).unwrap())
            .unwrap()
            .contains("hh2:session:"));
        assert_eq!(
            core.handshake(42, 2).unwrap(),
            [5, 1, 0, 3, 10, b'g', b'i', b't', b'h', b'u', b'b', b'.', b'c', b'o', b'm', 0, 22]
        );
    }

    #[test]
    fn bypasses_the_proxy_endpoint() {
        let mut core = configured_core();
        let plan = core.prepare_connect(42, 2, &[127, 0, 0, 1], 18444).unwrap();
        assert_eq!(plan.should_intercept, 0);
        assert!(core.gateway.sockets.is_empty());
    }

    #[test]
    fn intercepts_other_loopback_endpoints() {
        let mut core = configured_core();
        let plan = core.prepare_connect(42, 2, &[127, 0, 0, 1], 7897).unwrap();
        assert_eq!(plan.should_intercept, 1);
        assert_eq!(plan.proxy_port, 18444);
        assert!(core.gateway.sockets.contains_key(&42));
    }
}
