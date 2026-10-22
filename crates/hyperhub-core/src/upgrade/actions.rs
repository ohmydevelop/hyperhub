use super::*;

pub(super) fn apply(inner: &Inner, book: &mut Book, request: &Request, now: u64) -> io::Result<()> {
    if let Action::Prepare {
        manifest,
        source,
        cache,
        hosts,
    }
    | Action::PrepareAll {
        manifest,
        source,
        cache,
        hosts,
        ..
    } = &request.action
    {
        let all_sessions = matches!(request.action, Action::PrepareAll { .. });
        if all_sessions && super::super::stable_version(&manifest.version).is_none() {
            return Err(io::Error::other(
                "global deployment requires a stable numeric version",
            ));
        }
        let digest = fingerprint(&request.action)?;
        if let Some(record) = book.records.get(&request.id) {
            return if record.prepare_digest == digest {
                Ok(())
            } else {
                Err(io::Error::other("upgrade transaction ID conflict"))
            };
        }
        if let Action::PrepareAll {
            native_base_sha256, ..
        } = &request.action
        {
            let latest = book
                .records
                .values()
                .filter(|record| {
                    record.all_sessions
                        && record.finalize_decided
                        && record.native_base_sha256 == *native_base_sha256
                        && record.manifest.target == manifest.target
                })
                .filter_map(|record| super::super::stable_version(&record.manifest.version))
                .max();
            if latest.is_some_and(|stable| {
                super::super::stable_version(&manifest.version).unwrap() < stable
            }) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "global Engine deployment cannot downgrade a finalized version",
                ));
            }
        }
        if book.records.len() >= 128 {
            return Err(io::Error::other(
                "upgrade journal transaction limit reached",
            ));
        }
        if book
            .records
            .values()
            .any(|record| !record.phase.terminal() && record.phase != Phase::Draining)
        {
            return Err(io::Error::other("another upgrade transaction is active"));
        }
        manifest.validate().map_err(io::Error::other)?;
        let command = hyperhub_engine::management::Command::Prepare {
            id: request.id.clone(),
            manifest: manifest.clone(),
            source: source.clone(),
            cache: cache.clone(),
        };
        if serde_json::to_vec(&command)
            .map_err(io::Error::other)?
            .len()
            > hyperhub_engine::management::MAX_COMMAND
        {
            return Err(io::Error::other("upgrade artifact command exceeds limit"));
        }
        if !source.is_absolute()
            || !cache.is_absolute()
            || (!all_sessions && hosts.is_empty())
            || hosts.len() > 256
        {
            return Err(io::Error::other(
                "upgrade requires absolute artifact/cache paths and 1..256 Hosts",
            ));
        }
        let mut unique = std::collections::BTreeSet::new();
        let known = inner.hosts.host(None);
        let mut selected_sessions = std::collections::BTreeSet::new();
        for id in hosts.iter().filter(|_| !all_sessions) {
            if !unique.insert(id) {
                return Err(io::Error::other("duplicate upgrade Host"));
            }
            let host = known
                .iter()
                .find(|host| &host.host_id == id && host.online)
                .ok_or_else(|| io::Error::other("upgrade Host unavailable"))?;
            selected_sessions.insert(host.session_id.as_str());
        }
        // Host IDs select sessions. Snapshotting all current members under the
        // transaction lock closes the CLI-list / child-registration race.
        // Later registrations join through the same durable admission path.
        let mut participants = Vec::new();
        let mut incompatible = false;
        let mut native_base_sha256 = match &request.action {
            Action::PrepareAll {
                native_base_sha256, ..
            } => Some(native_base_sha256.clone()),
            _ => None,
        };
        for host in known.iter().filter(|host| {
            host.online
                && (all_sessions || selected_sessions.contains(host.session_id.as_str()))
                && !Identity::from_host(host).is_ok_and(|identity| participant::gone(&identity))
        }) {
            let identity = Identity::from_host(host)?;
            let base = native_base_sha256.get_or_insert_with(|| host.native_base_sha256.clone());
            incompatible |= base != &host.native_base_sha256;
            incompatible |= !manifest.compatible_with(&host.snapshot.host)
                || (all_sessions && !super::super::not_older(manifest, &host.snapshot.host));
            participants.push(Participant {
                identity,
                host_id: host.host_id.clone(),
                previous_generation: host.snapshot.active.generation,
                generation: None,
                stage: None,
                reason: None,
                confirmed: false,
                finalized: false,
                cleanup_done: false,
                exited: false,
                sequence: 0,
                pending: None,
                recovering: false,
                exit_wait_started_ms: None,
                exit_clean: false,
            });
        }
        if !all_sessions && participants.is_empty() {
            return Err(io::Error::other("selected Engine Hosts have exited"));
        }
        book.records.insert(request.id.clone(), Record { id: request.id.clone(), manifest: manifest.clone(),
            native_base_sha256: native_base_sha256.unwrap_or_default(),
            phase: if incompatible { Phase::RequiresRestart } else { Phase::Preparing },
            reason: incompatible.then(|| "target, base ABI, state schema or Hook capability set differs; requires_restart".into()),
            participants, created_at_ms: now, updated_at_ms: now, health_started_at_ms: None,
            finalize_decided: false, defer_finalize: false, finalize_order: 0, all_sessions,
            source: source.clone(), cache: cache.clone(), rollback_requested: false, restart_requested: incompatible,
            preparing_deadline_ms: now.saturating_add(inner.prepare_timeout_ms), health_window_ms: inner.health_window_ms,
            prepare_digest: digest,
        });
        return Ok(());
    }
    let record = book
        .records
        .get_mut(&request.id)
        .ok_or_else(|| io::Error::other("unknown upgrade transaction"))?;
    match &request.action {
        Action::Prepare { .. } | Action::PrepareAll { .. } => unreachable!(),
        Action::Recover => unreachable!("recovery is handled before action dispatch"),
        Action::Commit => match record.phase {
            Phase::Preparing => {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "upgrade preparation is not complete",
                ))
            }
            Phase::Prepared => record.phase = Phase::Switching,
            Phase::Switching
            | Phase::Committed
            | Phase::Observing
            | Phase::Finalizing
            | Phase::Draining
            | Phase::Complete => {}
            _ => return Err(io::Error::other("upgrade transaction is not prepared")),
        },
        Action::Abort => match record.phase {
            Phase::Preparing | Phase::Prepared => record.phase = Phase::Aborting,
            Phase::Aborting | Phase::Aborted => {}
            _ => {
                return Err(io::Error::other(
                    "upgrade already committed or terminal; use rollback before finalization",
                ))
            }
        },
        Action::Rollback { reason } => {
            if reason.len() > 1024 {
                return Err(io::Error::other("upgrade rollback reason exceeds limit"));
            }
            match record.phase {
                Phase::Switching | Phase::Committed | Phase::Observing => {
                    record.rollback_requested = true;
                    record.reason = Some(reason.clone());
                    record.phase = Phase::RollingBack;
                }
                Phase::RollingBack | Phase::RolledBack => {}
                _ => {
                    return Err(io::Error::other(
                        "upgrade cannot roll back in its current phase",
                    ))
                }
            }
        }
        Action::Observe | Action::ObserveHeld => match record.phase {
            Phase::Committed => {
                record.phase = Phase::Observing;
                record.health_started_at_ms = Some(now);
                record.defer_finalize = matches!(request.action, Action::ObserveHeld);
            }
            Phase::Observing
                if record.defer_finalize != matches!(request.action, Action::ObserveHeld) =>
            {
                return Err(io::Error::other(
                    "upgrade observation mode is already fixed",
                ));
            }
            Phase::Observing | Phase::Finalizing | Phase::Draining | Phase::Complete => {}
            _ => return Err(io::Error::other("upgrade commit is not confirmed")),
        },
        Action::Finalize => {
            if record.finalize_decided {
                return Ok(());
            }
            if record.phase != Phase::Observing {
                return Err(io::Error::other(
                    "upgrade health observation has not started",
                ));
            }
            let elapsed = now.saturating_sub(record.health_started_at_ms.unwrap_or(now));
            let hosts = inner.hosts.host(None);
            if elapsed < record.health_window_ms || !participant::healthy(record, &hosts, now) {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "upgrade health window is incomplete or a Host report is stale",
                ));
            }
            record.finalize_decided = true;
            record.phase = Phase::Finalizing;
        }
    }
    record.updated_at_ms = now;
    Ok(())
}
