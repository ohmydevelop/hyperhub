use super::*;

#[test]
fn control_loss_discards_ungranted_claims_and_keeps_granted_cancellation_watchers() {
    let (ready, ready_result) = mpsc::channel();
    let (pending_done, mut pending_result) = oneshot::channel();
    let (active_done, mut active_result) = oneshot::channel();
    let mut offers = HashMap::from([
        (
            7,
            Offer {
                ready: Some(ready),
                done: Some(pending_done),
                granted: false,
                sent: true,
                cancelled: false,
                cancellation_socket: None,
            },
        ),
        (
            8,
            Offer {
                ready: None,
                done: Some(active_done),
                granted: true,
                sent: true,
                cancelled: false,
                cancellation_socket: None,
            },
        ),
    ]);
    let abandoned = disconnect_offers(&mut offers, "fixture control loss");
    assert_eq!(abandoned, vec![7]);
    assert_eq!(offers.len(), 1);
    assert!(offers.contains_key(&8));
    assert_eq!(
        ready_result.try_recv().unwrap().unwrap_err().kind(),
        io::ErrorKind::BrokenPipe
    );
    assert_eq!(
        pending_result.try_recv().unwrap().unwrap_err().kind(),
        io::ErrorKind::BrokenPipe
    );
    assert!(matches!(
        active_result.try_recv(),
        Err(oneshot::error::TryRecvError::Empty)
    ));
    assert!(disconnect_offers(&mut offers, "repeat disconnect").is_empty());
    assert!(matches!(
        active_result.try_recv(),
        Err(oneshot::error::TryRecvError::Empty)
    ));
}
