//! Origin is checked against the immutable mode proved by live Core memory.
use super::*;
use hyperhub_runtime::attachment as wire;

#[tokio::test]
async fn origin_capability_rejection_precedes_runtime_publish_and_record_edits_cannot_bypass_it() {
    for origin in [attachments::Origin::Attach, attachments::Origin::Run] {
        let root = std::env::temp_dir().join(format!("hh-origin-update-{}", attachments::new_id()));
        let directory = root.join("runtime").join("attachments");
        let identity = attachments::inspect_process(std::process::id()).unwrap();
        let spec = attachments::Spec {
            id: attachments::new_id(),
            target: identity.clone(),
            current_target: None,
            exec_epoch: 0,
            scope: Scope::Tree,
            backend: Backend::Ptrace,
            policy_digest: attachments::policy_digest(&Config::default()).unwrap(),
            capabilities: attachments::dynamic_capabilities_for_origin(
                &Config::default(),
                Backend::Ptrace,
                origin,
            ),
            recovery: None,
        };
        let mut record = attachments::create_record(&directory, spec.clone()).unwrap();
        let bootstrap:wire::Bootstrap=serde_json::from_value(serde_json::json!({
            "attachment_id":spec.id,"session_id":record.session_id,"token":"t".repeat(64),"control_endpoint":"unused","socks_address":"127.0.0.1:1",
            "tls_ca_pem":"-----BEGIN CERTIFICATE-----\ndummy\n-----END CERTIFICATE-----\n","observe":false,"firewall":null,"sandbox":null,
            "host_endpoint":"unused","host_token":"h".repeat(64),"scope_tree":true,"root_pid":identity.pid,"approval_authority_file":"unused",
            "approval_instance_id":"unit-instance","initially_owned":origin==attachments::Origin::Run,"approval_core_public_key":null,"approval_core_pid":0,"approval_core_birth":0,
            "approval_cli_sha256":"c".repeat(64),"approval_root_identity":identity.root_image_identity(),"external_attachment":origin==attachments::Origin::Attach,"native_dns_mode":origin.native_dns_mode()
        })).unwrap();
        record.origin = origin;
        record.host_binding = Some(bootstrap.approval_binding().unwrap());
        let state = attachments::attachment_directory(&directory, &record.spec.id).unwrap();
        crate::config_store::save_durable_private_bytes(
            &state.join("record.json"),
            &serde_json::to_vec(&record).unwrap(),
        )
        .unwrap();
        attachments::initialize_root_image(
            &directory,
            &spec,
            &record.session_id,
            &bootstrap.approval_instance_id,
            record.host_binding.as_deref().unwrap(),
        )
        .unwrap();
        attachments::verify_root_image_bootstrap(&directory, &bootstrap).unwrap();
        attachments::update_record(
            &state,
            &attachments::Outcome {
                phase: attachments::Phase::Active,
                members: vec![identity.clone()],
                manager: Some(identity),
                manager_endpoint: None,
                compatibility_reasons: vec![],
            },
        )
        .unwrap();
        let runtime = RuntimeState::new(Arc::new(Config::default())).unwrap();
        let service = ControlService::new(
            SessionRegistry::default(),
            ConnectionRegistry::default(),
            String::new(),
            AuditWriter::open(None).unwrap(),
            runtime.clone(),
            Zeroizing::new(vec![0; 32]),
        )
        .with_attachment_directory(directory.clone());
        assert!(
            matches!(service.attachment_profile_view(bootstrap.clone(),Some(std::process::id())),
            ControlResponse::AttachmentProfile{profile} if profile.origin==origin && profile.native_dns_mode==origin.native_dns_mode())
        );
        let other_origin = if origin == attachments::Origin::Attach {
            attachments::Origin::Run
        } else {
            attachments::Origin::Attach
        };
        assert!(
            attachments::ManagerExecutionProfile::from_bootstrap(&bootstrap, other_origin).is_err()
        );
        let mut next = Config::default();
        next.debug = true;
        next.rules.push(serde_json::from_value(serde_json::json!({"id":"name-denial","action":"deny","endpoints":[{"target":"example.test","port":443}]})).unwrap());
        next.ensure_item_uuids();
        next.validate().unwrap();
        let before = runtime.snapshot().updated_at_ms;
        let response = service.update_config(next).await;
        if origin == attachments::Origin::Attach {
            assert!(
                matches!(response,ControlResponse::Error{ref message} if message.contains("connection hostname")),
                "{response:?}"
            );
            assert_eq!(runtime.snapshot().updated_at_ms, before);
            assert!(runtime.snapshot().config.rules.is_empty());
            assert!(!runtime.snapshot().config.debug);
            let mut forged = attachments::load_record(&state).unwrap();
            forged.origin = attachments::Origin::Run;
            crate::config_store::save_durable_private_bytes(
                &state.join("record.json"),
                &serde_json::to_vec(&forged).unwrap(),
            )
            .unwrap();
            assert!(
                matches!(service.update_config(Config::default()).await,ControlResponse::Error{ref message} if message.contains("proven immutable execution profile"))
            );
            assert_eq!(runtime.snapshot().updated_at_ms, before);
        } else {
            assert!(matches!(response, ControlResponse::Ok), "{response:?}");
            assert!(runtime.snapshot().updated_at_ms > before);
            assert_eq!(runtime.snapshot().config.rules.len(), 1);
        }
        let mut forged_bootstrap = bootstrap.clone();
        forged_bootstrap.native_dns_mode = if origin == attachments::Origin::Attach {
            wire::NativeDnsMode::SyntheticPool
        } else {
            wire::NativeDnsMode::PreserveAnswers
        };
        assert!(
            attachments::verify_root_image_bootstrap(&directory, &forged_bootstrap).is_err(),
            "a mutable candidate cannot replace a trusted mode"
        );
        assert!(matches!(
            service.attachment_profile_view(forged_bootstrap, Some(std::process::id())),
            ControlResponse::Error { .. }
        ));
        assert_eq!(
            attachments::root_image_profile(&directory, &record.spec.id)
                .unwrap()
                .origin,
            origin
        );
        let cold = root.join("cold");
        attachments::create_record(&cold, spec).unwrap();
        assert!(
            attachments::root_image_profile(&cold, &record.spec.id).is_err(),
            "a public record must not initialize a profile"
        );
        std::fs::remove_dir_all(root).unwrap();
    }
}
