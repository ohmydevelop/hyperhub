use hyperhub_engine::{contract::*, *};
use serde_json::json;
fn policy_input(snapshot: serde_json::Value) -> PolicyInput {
    PolicyInput {
        snapshot,
        target: "/vault/key".into(),
        operation: "read".into(),
        command_line: "tool --danger".into(),
    }
}
#[test]
fn rule_order_operations_and_independent_protection_precedence_survive_byte_contract() {
    let lease = resident().acquire();
    let snapshot = json!({"default_action":"deny","rules":[
 {"id":"first","action":"pass","patterns":["^/vault/"],"operations":["read"]},
 {"id":"protected","action":"pass","patterns":["key$"],"operations":["read"],"protection":"review"}]});
    let mut input = policy_input(snapshot);
    let decision = policy(&lease, FILE_POLICY, &input).unwrap();
    assert_eq!(decision.action, "pass");
    assert_eq!(decision.rule_id.as_deref(), Some("first"));
    assert_eq!(decision.protection.as_deref(), Some("review"));
    assert_eq!(decision.protection_rule_id.as_deref(), Some("protected"));
    input.operation = "write".into();
    let decision = policy(&lease, FILE_POLICY, &input).unwrap();
    assert_eq!(decision.action, "deny");
    assert!(decision.rule_id.is_none() && decision.protection.is_none());
}
#[test]
fn executable_and_command_patterns_remain_bound_and_invalid_snapshots_are_rejected() {
    let lease = resident().acquire();
    let mut input = policy_input(
        json!({"default_action":"pass","rules":[{"id":"danger","action":"deny","patterns":[{"executable":"tool$","command_line":"--danger"}]}]}),
    );
    assert_eq!(
        policy(&lease, PROCESS_POLICY, &input).unwrap().action,
        "pass"
    );
    input.target = "/bin/tool".into();
    assert_eq!(
        policy(&lease, PROCESS_POLICY, &input).unwrap().action,
        "deny"
    );
    input.command_line = "tool --safe".into();
    assert_eq!(
        policy(&lease, PROCESS_POLICY, &input).unwrap().action,
        "pass"
    );
    input.snapshot["rules"][0]["patterns"][0]["executable"] = json!("[");
    assert_eq!(policy(&lease, PROCESS_POLICY, &input), Err(INVALID));
    input.snapshot["rules"][0]["patterns"][0]["executable"] = json!("tool$");
    input.snapshot["default_action"] = json!("unknown");
    assert_eq!(policy(&lease, PROCESS_POLICY, &input), Err(INVALID));
}
fn firewall_input(snapshot: serde_json::Value) -> FirewallInput {
    FirewallInput {
        snapshot,
        hostname: Some("example.test".into()),
        ip: "198.18.0.1".parse().unwrap(),
        port: 443,
        bypass: false,
        dns: true,
    }
}
#[test]
fn dns_defers_port_and_ip_rules_without_reordering_firewall_decisions() {
    let lease = resident().acquire();
    let mut input = firewall_input(
        json!({"default_action":"deny","rules":[{"id":"port-bound","action":"pass","endpoints":[{"target":{"kind":"domain","value":{"host":"example.test","wildcard":false}},"port":80}]},{"id":"later-deny","action":"deny","endpoints":[{"target":{"kind":"domain","value":{"host":"example.test","wildcard":false}},"port":null}]}]}),
    );
    assert_eq!(firewall(&lease, &input).unwrap().action, "pass");
    input.dns = false;
    assert_eq!(
        firewall(&lease, &input).unwrap().rule_id.as_deref(),
        Some("later-deny")
    );
    input.port = 80;
    assert_eq!(
        firewall(&lease, &input).unwrap().rule_id.as_deref(),
        Some("port-bound")
    );
    input.bypass = true;
    assert_eq!(firewall(&lease, &input).unwrap().action, "pass");
}
#[test]
fn explicit_wildcard_legacy_apex_and_hostname_precedence_are_preserved() {
    let lease = resident().acquire();
    let mut input = firewall_input(
        json!({"default_action":"pass","rules":[{"id":"wildcard","action":"deny","endpoints":[{"target":{"kind":"domain","value":{"host":"example.test","wildcard":true}},"port":null}]}]}),
    );
    assert_eq!(firewall(&lease, &input).unwrap().action, "pass");
    input.hostname = Some("WWW.Example.Test.".into());
    assert_eq!(firewall(&lease, &input).unwrap().action, "deny");
    input.snapshot["rules"][0]["endpoints"][0]["target"]["value"] = json!("example.test");
    input.hostname = Some("example.test".into());
    assert_eq!(firewall(&lease, &input).unwrap().action, "deny");
    input.snapshot["rules"][0]["endpoints"][0]["target"] =
        json!({"kind":"network","value":"198.18.0.0/15"});
    input.dns = false;
    assert_eq!(firewall(&lease, &input).unwrap().action, "pass");
    input.hostname = None;
    assert_eq!(firewall(&lease, &input).unwrap().action, "deny");
}
#[test]
fn trust_bytes_reject_private_keys_and_preserve_roots_without_duplicate_or_abi_objects() {
    let lease = resident().acquire();
    let source = b"-----BEGIN CERTIFICATE-----\nsource\n-----END CERTIFICATE-----";
    let root = b"-----BEGIN CERTIFICATE-----\nroot\n-----END CERTIFICATE-----\n";
    let bundle = trust_bundle(&lease, "PEM", source, root).unwrap();
    assert!(bundle.ends_with(root));
    assert_eq!(trust_bundle(&lease, "pem", &bundle, root).unwrap(), bundle);
    assert!(trust_bundle(&lease, "txt", source, root)
        .unwrap()
        .is_empty());
    assert!(trust_bundle(
        &lease,
        "pem",
        b"-----BEGIN CERTIFICATE-----\nPRIVATE KEY-----",
        root
    )
    .unwrap()
    .is_empty());
    assert_eq!(
        trust_bundle(&lease, "!der", b"certificate", b"certificate").unwrap(),
        [1]
    );
    assert!(trust_bundle(&lease, "!der", b"other", b"certificate")
        .unwrap()
        .is_empty());
    let mut output = [99; 16];
    assert_eq!(
        lease.invoke(TRUST_BUNDLE, &[0; 7], &mut output),
        Err(INVALID)
    );
    assert_eq!(output, [99; 16]);
}
#[test]
fn child_plan_preserves_callers_suspension_and_unmanaged_creation_flags() {
    let lease = resident().acquire();
    for hook in [false, true] {
        for caller_suspended in [false, true] {
            let plan = child_plan(
                &lease,
                &ChildInput {
                    hook,
                    caller_suspended,
                    creation_flags: 0x100,
                    suspended_flag: 1,
                    unicode_environment_flag: 4,
                },
            )
            .unwrap();
            assert_eq!(plan.inject, hook);
            assert_eq!(plan.creation_flags, if hook { 0x105 } else { 0x100 });
            assert_eq!(plan.resume_after_ready, hook && !caller_suspended);
        }
    }
}

#[test]
fn policy_responses_preserve_large_ascii_unicode_identifiers_and_protection() {
    let runtime = resident();
    let lease = runtime.acquire();
    for id in ["rule-".repeat(2048), "规则标识".repeat(1024)] {
        let protection = format!("profile-{}", id);
        for operation in [FILE_POLICY, PROCESS_POLICY] {
            let patterns = if operation == FILE_POLICY {
                json!(["^/vault/"])
            } else {
                json!([{"executable":"^/vault/", "command_line":""}])
            };
            let decision = policy(
                &lease,
                operation,
                &policy_input(json!({
                    "default_action":"deny", "rules":[{"id":id,"action":"pass", "patterns":patterns,
                        "operations":["read"],"protection":protection}]
                })),
            )
            .expect("valid native decisions must preserve configured identifiers");
            assert_eq!(decision.action, "pass");
            assert_eq!(decision.rule_id.as_deref(), Some(id.as_str()));
            assert_eq!(decision.protection_rule_id.as_deref(), Some(id.as_str()));
            assert_eq!(decision.protection.as_deref(), Some(protection.as_str()));
        }
        let mut input = firewall_input(json!({"default_action":"deny","rules":[
            {"id":id,"action":"pass","protection":protection,"endpoints":[
                {"target":{"kind":"domain","value":{"host":"example.test","wildcard":false}},"port":443}]}]}));
        input.dns = false;
        let decision = firewall(&lease, &input).unwrap();
        assert_eq!(decision.action, "pass");
        assert_eq!(decision.rule_id.as_deref(), Some(id.as_str()));
        assert_eq!(decision.protection_rule_id.as_deref(), Some(id.as_str()));
        assert_eq!(decision.protection.as_deref(), Some(protection.as_str()));
    }
}
