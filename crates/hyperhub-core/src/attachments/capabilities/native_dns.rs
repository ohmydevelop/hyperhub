//! Only destination selectors require knowledge of the original connection
//! name. Upstream names, rewrites and file/process patterns are not selectors.
use crate::config::{parse_route_target, Config, RouteTarget};

/// The configuration validator owns syntax errors. This capability check
/// classifies enabled, parsed destination predicates without guessing from a
/// scheme, port number, or an unrelated hostname string.
pub(super) fn unsupported(config: &Config) -> Vec<String> {
    let mut reasons = Vec::new();
    for rule in config.rules.iter().filter(|rule| rule.enabled) {
        for endpoint in &rule.endpoints {
            if matches!(
                parse_route_target(&endpoint.target),
                Ok(RouteTarget::Domain { .. })
            ) {
                reasons.push(format!(
                    "route {}: destination '{}' requires a connection hostname that external native DNS answers cannot prove",
                    rule.id, endpoint.target,
                ));
            }
        }
    }
    if config.firewall.enabled {
        for rule in config.firewall.rules.iter().filter(|rule| rule.enabled) {
            for endpoint in &rule.endpoints {
                if matches!(
                    parse_route_target(&endpoint.target),
                    Ok(RouteTarget::Domain { .. })
                ) {
                    reasons.push(format!(
                        "firewall rule {}: destination '{}' requires a connection hostname that external native DNS answers cannot prove",
                        rule.id, endpoint.target,
                    ));
                }
            }
        }
    }
    reasons
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attachments::{
        dynamic_capabilities, dynamic_capabilities_for_origin, Backend, Origin,
    };
    use crate::config::{FirewallAction, FirewallRule, RouteRule, RuleAction};
    use serde_json::json;

    fn route(target: &str, action: RuleAction, port: Option<u16>) -> RouteRule {
        serde_json::from_value(json!({"id":"destination","action":action,"endpoints":[{"target":target,"port":port}],"protection":if action==RuleAction::Smart{Some("check")}else{None}})).unwrap()
    }
    fn firewall(target: &str, action: FirewallAction, port: Option<u16>) -> FirewallRule {
        serde_json::from_value(json!({"id":"destination","action":action,"endpoints":[{"target":target,"port":port}],"protection":if action==FirewallAction::Smart{Some("check")}else{None}})).unwrap()
    }
    fn config() -> Config {
        let mut config = Config::default();
        config.protections.push(
            serde_json::from_value(
                json!({"id":"check","data":{"enabled":false},"intelligence":{"enabled":false}}),
            )
            .unwrap(),
        );
        config
    }
    fn assert_external_only(config: &Config) {
        let mut config = config.clone();
        config.ensure_item_uuids();
        config.validate().unwrap();
        let config = &config;
        for backend in [Backend::Gum, Backend::Ptrace] {
            let external = dynamic_capabilities_for_origin(config, backend, Origin::Attach);
            assert_eq!(external, dynamic_capabilities(config, backend));
            assert_eq!(external.unsupported_required.len(), 1, "{external:?}");
            assert!(external
                .require_supported()
                .unwrap_err()
                .contains("connection hostname"));
            let owned = dynamic_capabilities_for_origin(config, backend, Origin::Run);
            assert!(owned.require_supported().is_ok(), "{owned:?}");
        }
    }

    #[test]
    fn domain_route_matrix_requires_connection_identity_for_every_action() {
        for target in [
            "example.test",
            "*.example.test",
            "http://example.test/path",
            "https://example.test/path",
        ] {
            for action in [RuleAction::Pass, RuleAction::Deny, RuleAction::Smart] {
                for port in [None, Some(443)] {
                    let mut config = config();
                    config.rules.push(route(target, action, port));
                    assert_external_only(&config);
                }
            }
        }
    }

    #[test]
    fn domain_firewall_matrix_is_not_mistaken_for_dns_only_policy() {
        for target in ["example.test", "*.example.test"] {
            for action in [
                FirewallAction::Pass,
                FirewallAction::Deny,
                FirewallAction::Smart,
            ] {
                for port in [None, Some(443)] {
                    let mut config = config();
                    config.firewall.enabled = true;
                    config.firewall.rules.push(firewall(target, action, port));
                    assert_external_only(&config);
                }
            }
        }
    }

    #[test]
    fn disabled_domains_do_not_add_requirements_but_mixed_predicates_do() {
        let mut config = config();
        config
            .rules
            .push(route("example.test", RuleAction::Deny, None));
        config.rules[0].enabled = false;
        config
            .firewall
            .rules
            .push(firewall("example.test", FirewallAction::Deny, None));
        config.ensure_item_uuids();
        config.validate().unwrap();
        assert!(dynamic_capabilities(&config, Backend::Gum)
            .require_supported()
            .is_ok());
        config.firewall.enabled = true;
        config.firewall.rules[0].enabled = false;
        assert!(dynamic_capabilities(&config, Backend::Gum)
            .require_supported()
            .is_ok());
        config.rules[0].enabled = true;
        config.rules[0]
            .endpoints
            .push(serde_json::from_value(json!({"target":"192.0.2.1"})).unwrap());
        assert_external_only(&config);
        config.rules[0].enabled = false;
        config.firewall.rules[0].enabled = true;
        config.firewall.rules[0]
            .endpoints
            .push(serde_json::from_value(json!({"target":"192.0.2.0/24"})).unwrap());
        assert_external_only(&config);
    }

    #[test]
    fn numeric_defaults_and_unrelated_names_keep_their_existing_capabilities() {
        let mut config = config();
        for target in ["192.0.2.1", "192.0.2.0/24", "2001:db8::1", "2001:db8::/32"] {
            let mut rule = route(target, RuleAction::Pass, Some(443));
            rule.id = target.into();
            config.rules.push(rule);
        }
        config.upstreams.push(serde_json::from_value(json!({"id":"transport","type":"socks5","address":"127.0.0.1:1080","headers":{"X-Target-Hint":{"value":"upstream.example.test"}}})).unwrap());
        config.rules[0].rewrite_host = Some("rewritten.example.test".into());
        config.rules[0].upstream = Some("transport".into());
        config.environment.push(
            serde_json::from_value(
                json!({"name":"TEST_DESTINATION","value":{"value":"unrelated.example.test"}}),
            )
            .unwrap(),
        );
        config.sandbox.file.enabled = true;
        config.sandbox.process.enabled = true;
        config.sandbox.file.rules.push(serde_json::from_value(json!({
            "id":"file-name","action":"deny","patterns":[{"pattern":"^unrelated\\.example\\.test$"}],"operations":["read"]
        })).unwrap());
        config.sandbox.process.rules.push(serde_json::from_value(json!({
            "id":"process-name","action":"deny","patterns":[{"executable":"unrelated.example.test"}]
        })).unwrap());
        config.firewall.enabled = true;
        config.firewall.default.as_mut().unwrap().action = FirewallAction::Deny;
        config.default_route.action = RuleAction::Deny;
        config
            .firewall
            .rules
            .push(firewall("192.0.2.0/24", FirewallAction::Pass, None));
        config.ensure_item_uuids();
        config.validate().unwrap();
        for origin in [Origin::Attach, Origin::Run] {
            let report = dynamic_capabilities_for_origin(&config, Backend::Gum, origin);
            assert!(report.require_supported().is_ok(), "{report:?}");
        }
    }

    #[test]
    fn owned_origin_does_not_remove_existing_tls_or_ssh_trust_checks() {
        use crate::config::{PluginConfig, PluginKind, PluginProtocol};
        let mut config = config();
        config.plugins.push(PluginConfig {
            id: "audit".into(),
            kind: PluginKind::Audit,
            protocols: vec![PluginProtocol::Http],
            ..PluginConfig::default()
        });
        config.default_route.plugins = vec!["audit".into()];
        config.ensure_item_uuids();
        config.validate().unwrap();
        for origin in [Origin::Attach, Origin::Run] {
            assert!(
                dynamic_capabilities_for_origin(&config, Backend::Gum, origin)
                    .require_supported()
                    .unwrap_err()
                    .contains("TLS")
            );
        }
        config.plugins[0].protocols = vec![PluginProtocol::Ssh];
        config.plugins[0].ssh_transcript = true;
        config.validate().unwrap();
        for origin in [Origin::Attach, Origin::Run] {
            assert!(
                dynamic_capabilities_for_origin(&config, Backend::Gum, origin)
                    .require_supported()
                    .unwrap_err()
                    .contains("SSH")
            );
        }
    }
}
