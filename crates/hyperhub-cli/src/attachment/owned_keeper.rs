//! Private handoff for a target created by the current `run` launcher.
use super::*;
use std::io::Read;

fn execution_digest(execution: &Execution) -> Result<String, String> {
    Ok(attachments::digest(
        &serde_json::to_vec(execution).map_err(|e| e.to_string())?,
    ))
}
fn accepted(response: ControlResponse) -> Result<(), String> {
    match response {
        ControlResponse::Ok => Ok(()),
        ControlResponse::Error { message } => Err(message),
        _ => Err("unexpected owned-run handoff response".into()),
    }
}

pub(crate) const ENTRY_RELEASE: u8 = 0xa5;

pub(crate) struct OwnedRunKeeperBarrier {
    execution: Execution,
    child: Option<std::process::Child>,
    input: Option<std::process::ChildStdin>,
    keeper: attachments::ProcessIdentity,
    secret: Option<String>,
    released: bool,
}

impl OwnedRunKeeperBarrier {
    pub(crate) fn release_after_entry(mut self) -> Result<attachments::ProcessIdentity, String> {
        // The target entry has already been released when this byte is sent.
        // Switch Drop to post-entry semantics before any fallible operation:
        // an activation-pipe error must never kill/cancel the only manager of
        // a live protected process.
        self.released = true;
        drop(self.secret.take());
        (|| -> Result<attachments::ProcessIdentity, String> {
            self.input
                .as_mut()
                .ok_or("owned-run keeper activation pipe is unavailable")?
                .write_all(&[ENTRY_RELEASE])
                .map_err(|e| e.to_string())?;
            drop(self.input.take());
            let deadline = Instant::now() + Duration::from_secs(30);
            loop {
                let record = attachments::load_record(&self.execution.state_directory)?;
                if record.manager.as_ref() == Some(&self.keeper) && record.phase == Phase::Active {
                    return Ok(self.keeper.clone());
                }
                if let Some(status) = self
                    .child
                    .as_mut()
                    .ok_or("owned-run keeper process handle is unavailable")?
                    .try_wait()
                    .map_err(|e| e.to_string())?
                {
                    return Err(format!(
                        "owned-run keeper exited before activation acknowledgement: {status}; inspect its private log"
                    ));
                }
                if Instant::now() >= deadline {
                    return Err(
                        "owned-run keeper did not publish Active after entry release before its bounded deadline"
                            .into(),
                    );
                }
                std::thread::sleep(Duration::from_millis(20));
            }
        })()
    }
}

impl Drop for OwnedRunKeeperBarrier {
    fn drop(&mut self) {
        if self.released {
            return;
        }
        drop(self.input.take());
        if let Some(child) = self.child.as_mut() {
            let _ = stop_created_keeper(child, &self.keeper);
        }
        if let Some(secret) = self.secret.take() {
            let _ = handoff_request(
                &self.execution,
                &ControlRequest::CancelOwnedAttachmentKeeper {
                    session_id: self.execution.bootstrap.session_id.clone(),
                    token: self.execution.bootstrap.token.clone().into(),
                    attachment_id: self.execution.spec.id.clone(),
                    secret: secret.into(),
                },
            )
            .and_then(accepted);
        }
    }
}

pub(crate) fn spawn_owned_run_keeper(
    execution: &Execution,
) -> Result<OwnedRunKeeperBarrier, String> {
    let record = attachments::load_record(&execution.state_directory)?;
    let launcher = attachments::inspect_process(std::process::id())?;
    if execution.origin != attachments::Origin::Run
        || record.origin != attachments::Origin::Run
        || record.manager.as_ref() != Some(&launcher)
        || record.spec != execution.spec
    {
        return Err("keeper handoff requires this launcher's actual owned run".into());
    }
    let secret = attachments::new_id() + &attachments::new_id();
    let path = execution.state_directory.join("keeper.log");
    if !path.exists() {
        attachments::create_private_file(&path, &[])?;
    }
    let mut options = std::fs::OpenOptions::new();
    options.append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let log = options.open(&path).map_err(|e| e.to_string())?;
    let mut command = ProcessCommand::new(std::env::current_exe().map_err(|e| e.to_string())?);
    command
        .arg("owned-run-keeper")
        .arg(&execution.state_directory)
        .env(
            "HYPERHUB_HOME",
            config_store::hyperhub_home().map_err(|e| e.to_string())?,
        )
        .env_remove("HYPERHUB_CONFIG_PASSWORD")
        .stdin(Stdio::piped())
        .stdout(log.try_clone().map_err(|e| e.to_string())?)
        .stderr(log);
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        unsafe {
            command.pre_exec(|| {
                if libc::setsid() < 0 {
                    Err(std::io::Error::last_os_error())
                } else {
                    Ok(())
                }
            });
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x08000000 | 0x00000200);
    }
    let mut child = command.spawn().map_err(|e| e.to_string())?;
    // Do not deliver the nonce until this exact child incarnation is observed.
    // The helper blocks on its private stdin and cannot claim the target yet.
    let observed_birth = attachments::process_birth(child.id());
    let keeper = match attachments::inspect_process(child.id()) {
        Ok(keeper) => keeper,
        Err(error) => {
            drop(child.stdin.take());
            if let Some(birth) = observed_birth {
                // A helper that exited before full image inspection still has
                // its observed creation marker and the exact image we launched.
                // This is a proven-dead attempted owner, never a live controller.
                let mut attempted = launcher.clone();
                attempted.pid = child.id();
                attempted.birth = birth;
                let _ = stop_created_keeper(&mut child, &attempted);
            }
            return Err(format!(
                "cannot identify created keeper before handoff: {error}"
            ));
        }
    };
    let input = child
        .stdin
        .take()
        .ok_or("keeper handoff pipe is unavailable")?;
    let mut child = Some(child);
    let mut input = Some(input);
    let mut secret = Some(secret);
    let result = (|| -> Result<OwnedRunKeeperBarrier, String> {
        accepted(handoff_request(
            execution,
            &ControlRequest::RegisterOwnedAttachmentKeeper {
                session_id: execution.bootstrap.session_id.clone(),
                token: execution.bootstrap.token.clone().into(),
                attachment_id: execution.spec.id.clone(),
                target: execution.spec.target.clone(),
                keeper: keeper.clone(),
                execution_digest: execution_digest(execution)?,
                secret_digest: attachments::digest(
                    secret
                        .as_deref()
                        .ok_or("keeper handoff secret is unavailable")?
                        .as_bytes(),
                ),
            },
        )?)?;
        input
            .as_mut()
            .ok_or("keeper handoff pipe is unavailable")?
            .write_all(
                secret
                    .as_deref()
                    .ok_or("keeper handoff secret is unavailable")?
                    .as_bytes(),
            )
            .map_err(|e| e.to_string())?;
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            let record = attachments::load_record(&execution.state_directory)?;
            if record.manager.as_ref() == Some(&keeper)
                && record.phase == Phase::Preparing
                && record.manager_endpoint.is_some()
            {
                return Ok(OwnedRunKeeperBarrier {
                    execution: execution.clone(),
                    child: child.take(),
                    input: input.take(),
                    keeper: keeper.clone(),
                    secret: secret.take(),
                    released: false,
                });
            }
            if let Some(status) = child
                .as_mut()
                .ok_or("keeper process handle is unavailable")?
                .try_wait()
                .map_err(|e| e.to_string())?
            {
                return Err(format!(
                    "owned-run keeper exited before readiness: {status}; inspect its private log"
                ));
            }
            if Instant::now() >= deadline {
                return Err(
                    "owned-run keeper did not acknowledge readiness before its bounded deadline"
                        .into(),
                );
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    })();
    if let Err(error) = &result {
        drop(input.take());
        let stopped = child
            .as_mut()
            .ok_or_else(|| "keeper process handle is unavailable".to_owned())
            .and_then(|child| stop_created_keeper(child, &keeper));
        // Kill/reap precedes cancellation: a delayed Claim cannot become a
        // controller later, even if Serve is unresponsive to cancellation.
        let cancellation = handoff_request(
            execution,
            &ControlRequest::CancelOwnedAttachmentKeeper {
                session_id: execution.bootstrap.session_id.clone(),
                token: execution.bootstrap.token.clone().into(),
                attachment_id: execution.spec.id.clone(),
                secret: secret.take().unwrap_or_default().into(),
            },
        )
        .and_then(accepted);
        let _ = (error, stopped, cancellation);
    }
    result
}

async fn bounded_request(
    endpoint: &str,
    request: &ControlRequest,
    timeout: Duration,
) -> Result<ControlResponse, String> {
    tokio::time::timeout(timeout, control_request(endpoint, request))
        .await
        .map_err(|_| "owned-run keeper control request exceeded its bounded deadline".to_owned())?
        .map_err(|e| e.to_string())
}
fn handoff_request(
    execution: &Execution,
    request: &ControlRequest,
) -> Result<ControlResponse, String> {
    runtime()?.block_on(bounded_request(
        &execution.bootstrap.control_endpoint,
        request,
        Duration::from_secs(5),
    ))
}
fn stop_created_keeper(
    child: &mut std::process::Child,
    keeper: &attachments::ProcessIdentity,
) -> Result<(), String> {
    if child.try_wait().map_err(|e| e.to_string())?.is_some() {
        return Ok(());
    }
    if child.id() != keeper.pid || attachments::process_birth(keeper.pid) != Some(keeper.birth) {
        return Err("created keeper incarnation changed; no process was signalled".into());
    }
    child.kill().map_err(|e| e.to_string())?;
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if child.try_wait().map_err(|e| e.to_string())?.is_some() {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err("created keeper termination was not confirmed".into());
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

pub(super) fn run_keeper(directory: &Path) -> Result<i32, String> {
    let execution =
        attachments::load_execution(directory, &crate::password::load_runtime_keyring()?)?;
    if execution.origin != attachments::Origin::Run
        || !execution.bootstrap.initially_owned
        || attachments::attachment_directory(&attachments::directory()?, &execution.spec.id)?
            != directory
    {
        return Err("keeper requires a sealed run execution of this instance".into());
    }
    let mut bytes = [0u8; 64];
    std::io::stdin()
        .read_exact(&mut bytes)
        .map_err(|e| e.to_string())?;
    let secret = String::from_utf8(bytes.to_vec()).map_err(|_| "invalid private keeper handoff")?;
    let _manager_lifetime = attachments::ManagerGuard::acquire(directory)?;
    accepted(handoff_request(
        &execution,
        &ControlRequest::ClaimOwnedAttachmentKeeper {
            session_id: execution.bootstrap.session_id.clone(),
            token: execution.bootstrap.token.clone().into(),
            attachment_id: execution.spec.id.clone(),
            execution_digest: execution_digest(&execution)?,
            secret: secret.into(),
        },
    )?)?;
    runtime()?.block_on(attachments::sync_manager_root_image(&execution))?;
    let result = crate::platform::run_owned_attachment_manager(&execution);
    if let Err(error) = &result {
        let _ = attachments::record_execution_error(directory, error.clone());
    }
    result.map(|()| 0)
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    #[tokio::test]
    async fn keeper_control_timeout_drops_unresponsive_transport() {
        let root =
            std::env::temp_dir().join(format!("hh-keeper-timeout-{}", attachments::new_id()));
        attachments::private_directory(&root).unwrap();
        let endpoint = root.join("control.sock");
        let listener = tokio::net::UnixListener::bind(&endpoint).unwrap();
        let server = tokio::spawn(async move {
            let (_stream, _) = listener.accept().await.unwrap();
            std::future::pending::<()>().await;
        });
        let response = tokio::time::timeout(
            Duration::from_secs(1),
            bounded_request(
                endpoint.to_str().unwrap(),
                &ControlRequest::GetStatus,
                Duration::from_millis(50),
            ),
        )
        .await
        .expect("keeper request ignored its deadline");
        assert!(response.unwrap_err().contains("bounded deadline"));
        server.abort();
        let _ = server.await;
        std::fs::remove_dir_all(root).unwrap();
    }
}
