//! Trusted resident-Host management. This is not a public network endpoint.
//! A caller outside the process must authenticate before using these commands.
use hyperhub_runtime::artifact::Artifact;
use hyperhub_runtime::generation::Transaction;
use hyperhub_runtime::native::NativeEngine;
use hyperhub_runtime::{Manifest, Runtime, Snapshot};
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::path::PathBuf;
use std::sync::Arc;

pub const MAX_COMMAND: usize = 16 * 1024;
pub const MIN_REPLY: usize = 16 * 1024;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum Command {
    Prepare {
        id: String,
        manifest: Manifest,
        source: PathBuf,
        cache: PathBuf,
    },
    Commit {
        id: String,
    },
    Abort {
        id: String,
    },
    Rollback {
        id: String,
        reason: String,
    },
    Observe,
    Query,
    QueryTransaction {
        id: String,
    },
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Reply {
    Transaction { transaction: Transaction },
    Snapshot { snapshot: Snapshot },
    Ok,
    Error { message: String },
}
/// # Safety
/// Prepare manifests and native code must come from the trusted upgrade owner.
/// Cache paths must have Host-only access. Hash/ABI checks do not sandbox code.
/// Call with no Agent-state, tracing-state or hook-installation lock held.
pub unsafe fn execute(runtime: &Runtime, command: Command) -> Reply {
    let result = match command {
        Command::Prepare {
            id,
            manifest,
            source,
            cache,
        } => runtime
            .prepare(&id, &manifest, || {
                let file = File::open(source)
                    .map_err(|e| hyperhub_runtime::Error::Artifact(e.to_string()))?;
                let artifact = Artifact::install(&cache, &manifest, file)?;
                Ok(Arc::new(unsafe { NativeEngine::load(artifact, None)? }))
            })
            .map(|transaction| Reply::Transaction { transaction }),
        Command::Commit { id } => runtime
            .commit(&id)
            .map(|transaction| Reply::Transaction { transaction }),
        Command::Abort { id } => runtime
            .abort(&id)
            .map(|transaction| Reply::Transaction { transaction }),
        Command::Rollback { id, reason } => runtime
            .rollback(&id, &reason)
            .map(|transaction| Reply::Transaction { transaction }),
        Command::Observe => runtime.observe().map(|_| Reply::Ok),
        Command::Query => runtime
            .snapshot()
            .map(|snapshot| Reply::Snapshot { snapshot }),
        Command::QueryTransaction { id } => runtime
            .query(&id)
            .map(|transaction| Reply::Transaction { transaction }),
    };
    result.unwrap_or_else(|error| Reply::Error {
        message: error.to_string().chars().take(1024).collect(),
    })
}
