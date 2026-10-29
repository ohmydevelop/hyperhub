use super::*;
#[test]
fn older_startup_evidence_cannot_claim_fresh_or_runtime_availability() {
    let legacy = serde_json::json!({"stage":"failed","initializing":false,"cancelled":false,"error":null,"native_pin":null});
    let evidence: InitializationStatus = serde_json::from_value(legacy).unwrap();
    assert_eq!(evidence.origin, InitializationOrigin::Unknown);
    assert!(!evidence.runtime_available);
    assert!(!evidence.ever_active);
    let evidence = InitializationStatus {
        origin: InitializationOrigin::ForkChild,
        ever_active: false,
        runtime_available: false,
        stage: InitializationStage::Cancelled,
        initializing: false,
        cancelled: true,
        error: None,
        native_pin: Some(InitializationNativePin {
            fd: 7,
            device: 8,
            inode: 9,
        }),
    };
    let roundtrip: InitializationStatus =
        serde_json::from_slice(&serde_json::to_vec(&evidence).unwrap()).unwrap();
    assert_eq!(roundtrip, evidence);
}
