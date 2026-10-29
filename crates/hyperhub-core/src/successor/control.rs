use super::*;

impl ControlService {
    pub(super) async fn restart_serve<S: AsyncRead + AsyncWrite + Unpin>(
        &self,
        mut stream: S,
        peer: Option<u32>,
        debug: bool,
    ) -> io::Result<()> {
        let prepared = async {
            if !crate::attachments::process_attachment_identity_available() {
                return Err(
                    "controlled Core succession is unavailable on this platform".to_string()
                );
            }
            let own = crate::attachments::inspect_process(std::process::id())?;
            let caller = crate::attachments::inspect_process(
                peer.ok_or("Core succession requires an OS-authenticated CLI")?,
            )?;
            if caller.owner != own.owner || caller.executable_sha256 != own.executable_sha256 {
                return Err("Core succession requires the trusted HyperHub CLI image".into());
            }
            self.shutdown
                .as_ref()
                .ok_or("Core succession shutdown coordinator unavailable")?;
            let store = self
                .configuration_store
                .as_ref()
                .ok_or("Core succession configuration ownership unavailable")?;
            let freeze = self.successor_admission.freeze().await?;
            let _configuration = self.config_update.lock().await;
            let path = store.path.clone();
            // Bound the largest history before copying any other transfer state.
            let aliases = self.alias_histories.export_successor()?;
            let state = crate::successor::CoreState {
                configuration_digest: crate::attachments::digest(
                    &std::fs::read(&path).map_err(|e| e.to_string())?,
                ),
                config_path: path,
                attachments: self
                    .attachment_directory
                    .as_ref()
                    .map(|directory| crate::attachments::export_successor_state(directory))
                    .transpose()?,
                sessions: self.sessions.export_successor()?,
                aliases,
                accepted_operations: self.operation_challenges.export_successor()?,
            };
            let child = crate::successor::prepare(state, debug).await?;
            Ok::<_, String>((freeze, child))
        }
        .await;
        let (freeze, child) = match prepared {
            Ok(value) => value,
            Err(message) => {
                return write_frame(&mut stream, &ControlResponse::Error { message }).await
            }
        };
        let process = child.identity.clone();
        // If this response cannot be delivered, the prepared child is aborted
        // and admission reopens; the running parent has not released anything.
        write_frame(&mut stream, &ControlResponse::ServeSuccessor { process }).await?;
        if let Err(message) = child.commit().await {
            return Err(io::Error::other(format!(
                "successor commit failed; original Core remains active: {message}"
            )));
        }
        *self
            .successor_freeze
            .lock()
            .map_err(|_| io::Error::other("Core succession state unavailable"))? = Some(freeze);
        if let Err(error) = self.shutdown.as_ref().unwrap().send(true) {
            // The committed child cannot publish while this parent is alive;
            // it times out explicitly. Restore admission if shutdown cannot run.
            self.successor_freeze
                .lock()
                .map_err(|_| io::Error::other("Core succession state unavailable"))?
                .take();
            return Err(io::Error::other(format!("successor committed but parent shutdown unavailable; parent admission restored: {error}")));
        }
        Ok(())
    }

    /// Only an opaque, validated anonymous-pipe object can call this path. The
    /// child has not started either listener, so failed imports abort startup.
    pub fn restore_successor(
        &self,
        received: crate::successor::ReceivedSuccessor,
    ) -> Result<crate::session::DurableSessionState, String> {
        let state = received.state;
        let store = self
            .configuration_store
            .as_ref()
            .ok_or("successor configuration ownership unavailable")?;
        if store.path != state.config_path
            || crate::attachments::digest(&std::fs::read(&store.path).map_err(|e| e.to_string())?)
                != state.configuration_digest
        {
            return Err("successor configuration changed before publication".into());
        }
        match (&self.attachment_directory, state.attachments) {
            (Some(directory), Some(state)) => {
                crate::attachments::import_successor_state(directory, state)?
            }
            (None, None) => (),
            _ => return Err("successor attachment capability differs from its parent".into()),
        }
        self.alias_histories.import_successor(&state.aliases)?;
        self.operation_challenges
            .import_successor(state.accepted_operations)?;
        self.sessions.import_successor(state.sessions)
    }
}
