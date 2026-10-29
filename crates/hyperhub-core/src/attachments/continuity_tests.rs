use super::*;
use crate::{config::Config, config_store as store};
#[test]
#[cfg(any(windows, target_os = "linux"))]
fn cold_core_enrolls_only_the_committed_password_root_and_integer_generation() {
    let private = std::env::temp_dir().join(format!(
        "hh-cold-continuity-{}",
        crate::attachments::new_id()
    ));
    std::fs::create_dir(&private).unwrap();
    let path = private.join("config.bin");
    let descriptor = || {
        let mut d = store::new_descriptor();
        d.memory_kib = 8192;
        d.iterations = 1;
        d
    };
    let passwords: [&[u8]; 3] = [b"cold-fixture-a", b"cold-fixture-b", b"cold-fixture-c"];
    let first = store::ConfigKeyring::derive(passwords[0], descriptor()).unwrap();
    store::save_encrypted_with_keyring(&path, &Config::default(), &first).unwrap();
    for generation in 1..=2 {
        let ring = store::ConfigKeyring::derive(passwords[generation], descriptor())
            .unwrap()
            .with_password_rotation(&path, passwords[generation - 1], passwords[generation])
            .unwrap();
        store::save_encrypted_with_keyring(&path, &Config::default(), &ring).unwrap();
        let config = store::load_encrypted(&path, passwords[generation]).unwrap();
        // Independent, initially unenrolled process-local trust state simulates
        // a fully cold Core; no authority file or retired API master enrolls it.
        let directory = private.join(format!("cold-core-{generation}"));
        std::fs::create_dir(&directory).unwrap();
        pin_expected_approval_anchor(
            &directory,
            ApprovalAuthority {
                instance_id: crate::attachments::instance_id(&path, &config.descriptor),
                config_id: config.descriptor.config_id,
                public_key: config.approval_public_key.unwrap(),
                generation: config.approval_continuity.len() as u64,
            },
        )
        .unwrap();
        assert!(approval_trust(&directory).unwrap().authority.is_none());
        let peer = crate::attachments::inspect_process(std::process::id()).unwrap();
        let previous = challenge(&directory, &path, peer.clone()).unwrap();
        assert!(enroll_password(
            &directory,
            &path,
            &previous.nonce,
            passwords[generation - 1],
            &peer
        )
        .is_err());
        assert!(approval_trust(&directory).unwrap().authority.is_none());
        let fresh = challenge(&directory, &path, peer.clone()).unwrap();
        enroll_password(
            &directory,
            &path,
            &fresh.nonce,
            passwords[generation],
            &peer,
        )
        .unwrap();
        let authority = trusted_authority(&directory).unwrap();
        assert_eq!(authority.generation, generation as u64);
        assert_eq!(authority.public_key, config.approval_public_key.unwrap());
        assert!(enroll_password(
            &directory,
            &path,
            &fresh.nonce,
            passwords[generation],
            &peer
        )
        .is_err());
    }
    std::fs::remove_dir_all(private).unwrap();
}
