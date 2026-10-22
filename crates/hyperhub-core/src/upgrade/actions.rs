use super::*;

pub(super) fn apply(inner: &Inner, book: &mut Book, request: &Request, now: u64) -> io::Result<()> {
    if let Action::Prepare {
        manifest,
        source,
        cache,
        hosts,
    } = &request.action
    {
        let digest = fingerprint(&request.action)?;
        if let Some(record) = book.records.get(&request.id) {
            return if record.prepare_digest == digest {
                Ok(())
            } else {
                Err(io::Error::other("upgrade transaction ID conflict"))
            };
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
        if !source.is_absolute() || !cache.is_absolute() || hosts.is_empty() || hosts.len() > 256 {
            return Err(io::Error::other(
                "upgrade requires absolute artifact/cache paths and 1..256 Hosts",
            ));
        }
        let mut unique = std::collections::BTreeSet::new();
        let known = inner.hosts.host(None);
        let mut participants = Vec::new();
        let mut incompatible = false;
        for id in hosts {
            if !unique.insert(id) {
                return Err(io::Error::other("duplicate upgrade Host"));
            }
            let host = known
                .iter()
                .find(|host| &host.host_id == id && host.online)
                .ok_or_else(|| io::Error::other("upgrade Host unavailable"))?;
            let identity = Identity::from_host(host)?;
            incompatible |= !manifest.compatible_with(&host.snapshot.host);
            participants.push(Participant {
                identity,
                host_id: id.clone(),
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
            });
        }
        book.records.insert(request.id.clone(), Record { id: request.id.clone(), manifest: manifest.clone(),
            phase: if incompatible { Phase::RequiresRestart } else { Phase::Preparing },
            reason: incompatible.then(|| "target, base ABI, state schema or Hook capability set differs; requires_restart".into()),
            participants, created_at_ms: now, updated_at_ms: now, health_started_at_ms: None,
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
        Action::Prepare { .. } => unreachable!(),
        Action::Recover => unreachable!("recovery is handled before action dispatch"),
        Action::Commit => match record.phase {
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
        Action::Observe => match record.phase {
            Phase::Committed => {
                record.phase = Phase::Observing;
                record.health_started_at_ms = Some(now);
            }
            Phase::Observing | Phase::Finalizing | Phase::Draining | Phase::Complete => {}
            _ => return Err(io::Error::other("upgrade commit is not confirmed")),
        },
    }
    record.updated_at_ms = now;
    Ok(())
}
