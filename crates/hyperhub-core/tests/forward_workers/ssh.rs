use super::support::*;
use base64::Engine;
use hyperhub_core::config::{
    Config, PluginConfig, PluginKind, PluginProtocol, SecretValue, SshAccount, SshHostKey,
};
use russh::{client, server, Channel, ChannelId, ChannelMsg};
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::TcpListener;

struct Echo;
impl server::Handler for Echo {
    type Error = russh::Error;
    async fn auth_password(
        &mut self,
        user: &str,
        password: &str,
    ) -> Result<server::Auth, Self::Error> {
        Ok(
            if user == "fixture-user" && password == "local-upstream-password" {
                server::Auth::Accept
            } else {
                server::Auth::reject()
            },
        )
    }
    async fn channel_open_session(
        &mut self,
        _channel: Channel<server::Msg>,
        reply: server::ChannelOpenHandle,
        _session: &mut server::Session,
    ) -> Result<(), Self::Error> {
        reply.accept().await;
        Ok(())
    }
    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut server::Session,
    ) -> Result<(), Self::Error> {
        session.data(channel, data.to_vec())?;
        Ok(())
    }

    async fn pty_request(
        &mut self,
        channel: ChannelId,
        _term: &str,
        _cols: u32,
        _rows: u32,
        _width: u32,
        _height: u32,
        _modes: &[(russh::Pty, u32)],
        session: &mut server::Session,
    ) -> Result<(), Self::Error> {
        session.channel_success(channel)?;
        Ok(())
    }
    async fn shell_request(
        &mut self,
        channel: ChannelId,
        session: &mut server::Session,
    ) -> Result<(), Self::Error> {
        session.channel_success(channel)?;
        Ok(())
    }
    async fn exec_request(
        &mut self,
        channel: ChannelId,
        _command: &[u8],
        session: &mut server::Session,
    ) -> Result<(), Self::Error> {
        session.channel_success(channel)?;
        Ok(())
    }
    async fn subsystem_request(
        &mut self,
        channel: ChannelId,
        _name: &str,
        session: &mut server::Session,
    ) -> Result<(), Self::Error> {
        session.channel_success(channel)?;
        Ok(())
    }
}
struct CheckKey(Arc<Mutex<Option<russh::keys::PublicKey>>>);
impl client::Handler for CheckKey {
    type Error = russh::Error;
    async fn check_server_key(
        &mut self,
        key: &russh::keys::PublicKey,
    ) -> Result<bool, Self::Error> {
        let mut original = self.0.lock().unwrap();
        if let Some(original) = &*original {
            Ok(original == key)
        } else {
            *original = Some(key.clone());
            Ok(true)
        }
    }
}
async fn exchange(channel: &mut Channel<client::Msg>, bytes: &[u8]) {
    channel.data(bytes).await.unwrap();
    let mut observed = Vec::new();
    tokio::time::timeout(Duration::from_secs(10), async {
        while observed.len() < bytes.len() {
            match channel.wait().await {
                Some(ChannelMsg::Data { data }) => observed.extend_from_slice(&data),
                other => panic!("SSH echo ended: {other:?}"),
            }
        }
    })
    .await
    .unwrap();
    assert_eq!(observed, bytes);
}

fn ssh_config(address: std::net::SocketAddr, public: &russh::keys::PublicKey) -> Config {
    let mut config = Config::default();
    config.plugins.push(PluginConfig {
        id: "ssh-credential".into(),
        kind: PluginKind::Credential,
        protocols: vec![PluginProtocol::Ssh],
        ssh_accounts: vec![SshAccount {
            username: "fixture-user".into(),
            private_keys: vec![],
            passwords: vec![SecretValue::Inline {
                value: "local-upstream-password".into(),
            }],
        }],
        ..Default::default()
    });
    config.plugins.push(PluginConfig {
        id: "ssh-audit".into(),
        kind: PluginKind::Audit,
        protocols: vec![PluginProtocol::Ssh],
        ssh_transcript: true,
        ..Default::default()
    });
    config.default_route.plugins = vec!["ssh-credential".into(), "ssh-audit".into()];
    config.ssh_host_keys.push(SshHostKey {
        uuid: hyperhub_core::config::new_config_uuid(),
        host: address.to_string(),
        key_type: public.algorithm().to_string(),
        key_blob: base64::engine::general_purpose::STANDARD.encode(public.to_bytes().unwrap()),
        enabled: true,
    });
    config
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires forwarding worker and the built ssh_idle_probe; run through the platform Suite"]
async fn external_ssh_clients_keep_idle_pty_exec_and_subsystem_channels_alive() {
    use tokio::io::AsyncWriteExt;
    let key =
        russh::keys::PrivateKey::random(&mut rand::rng(), russh::keys::Algorithm::Ed25519).unwrap();
    let public = key.public_key().clone();
    // A client heartbeat acknowledged by the MITM cannot reset this separate
    // upstream deadline. The proxy itself must probe the origin before 45 s.
    let origin_config = Arc::new(server::Config {
        keys: vec![key],
        auth_rejection_time: Duration::ZERO,
        inactivity_timeout: Some(Duration::from_secs(45)),
        keepalive_interval: None,
        ..Default::default()
    });
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let address = listener.local_addr().unwrap();
    let origin = tokio::spawn(async move {
        let mut peers = tokio::task::JoinSet::new();
        loop {
            tokio::select! {
                stream = listener.accept() => {
                    let (stream, _) = stream.unwrap();
                    let config = origin_config.clone();
                    peers.spawn(async move {
                        if let Ok(session) = server::run_stream(config, stream, Echo).await {
                            let _ = session.await;
                        }
                    });
                }
                _ = peers.join_next(), if !peers.is_empty() => {}
            }
        }
    });
    let fixture = Fixture::start_with(ssh_config(address, &public), vec![]).await;
    let pinned = Arc::new(Mutex::new(None));
    let mut initial = client::connect_stream(
        Arc::new(client::Config::default()),
        fixture.connect(100, address).await,
        CheckKey(pinned.clone()),
    )
    .await
    .unwrap();
    assert!(initial
        .authenticate_none("fixture-user")
        .await
        .unwrap()
        .success());
    let expected_key = base64::engine::general_purpose::STANDARD
        .encode(pinned.lock().unwrap().as_ref().unwrap().to_bytes().unwrap());
    initial
        .disconnect(russh::Disconnect::ByApplication, "key captured", "")
        .await
        .unwrap();
    drop(initial);
    let program = std::env::current_exe()
        .unwrap()
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("examples")
        .join(format!("ssh_idle_probe{}", std::env::consts::EXE_SUFFIX));
    assert!(
        program.is_file(),
        "build the source fixture: cargo build -p hyperhub-core --example ssh_idle_probe"
    );
    let mut clients = Vec::new();
    for client_probes in [false, true] {
        let mut child = tokio::process::Command::new(&program)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let input = serde_json::json!({
            "socks": fixture.address, "destination": address, "session": "worker-session",
            "registered_pid": std::process::id(), "token": fixture.token,
            "connection_id": if client_probes { 102 } else { 101 },
            "expected_key": expected_key, "client_probes": client_probes, "idle_seconds": 65
        });
        let mut stdin = child.stdin.take().unwrap();
        stdin
            .write_all(&serde_json::to_vec(&input).unwrap())
            .await
            .unwrap();
        drop(stdin);
        clients.push((client_probes, child));
    }
    let mut outputs = Vec::new();
    for (client_probes, child) in clients {
        let output = tokio::time::timeout(Duration::from_secs(100), child.wait_with_output())
            .await
            .expect("SSH source fixture did not exit")
            .unwrap();
        outputs.push((client_probes, output));
    }
    fixture.stop().await;
    origin.abort();
    let _ = origin.await;
    for (client_probes, output) in &outputs {
        if !output.status.success() {
            eprintln!(
                "SSH_IDLE_FAIL client_probes={client_probes}: {}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }
    for (client_probes, output) in outputs {
        assert!(
            output.status.success(),
            "client_probes={client_probes}: {}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let stdout = String::from_utf8(output.stdout).unwrap();
        assert!(stdout.contains(&format!("SSH_IDLE_PASS client_probes={client_probes} idle_seconds=65 channels=pty-shell,exec,subsystem")));
        eprintln!("{}", stdout.trim());
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires built forwarding worker fixture or final CLI"]
async fn ssh_mitm_reuses_host_identity_and_keeps_authenticated_channels_across_workers() {
    let key =
        russh::keys::PrivateKey::random(&mut rand::rng(), russh::keys::Algorithm::Ed25519).unwrap();
    let public = key.public_key().clone();
    let config = Arc::new(server::Config {
        keys: vec![key],
        auth_rejection_time: Duration::ZERO,
        ..Default::default()
    });
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let address = listener.local_addr().unwrap();
    let origin = tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            let config = config.clone();
            tokio::spawn(async move {
                if let Ok(running) = server::run_stream(config, stream, Echo).await {
                    let _ = running.await;
                }
            });
        }
    });
    let fixture = Fixture::start_with(ssh_config(address, &public), vec![]).await;
    let expected = Arc::new(Mutex::new(None));
    let stream = fixture.connect(1, address).await;
    let mut old = tokio::time::timeout(
        Duration::from_secs(10),
        client::connect_stream(
            Arc::new(client::Config::default()),
            stream,
            CheckKey(expected.clone()),
        ),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(old
        .authenticate_none("fixture-user")
        .await
        .unwrap()
        .success());
    // Only the worker has the configured upstream password. An unauthenticated
    // passthrough cannot satisfy this none-authentication assertion.
    let mut old_channel = old.channel_open_session().await.unwrap();
    exchange(&mut old_channel, b"old-SSH-before-switch").await;
    let manager = fixture.manager.clone();
    let binary = executable();
    let hash = digest(&binary);
    tokio::task::spawn_blocking(move || manager.prepare("ssh-switch", &binary, &hash))
        .await
        .unwrap()
        .unwrap();
    fixture.manager.commit("ssh-switch").unwrap();
    fixture.manager.finalize("ssh-switch").unwrap();
    let stream = fixture.connect(2, address).await;
    let mut new = tokio::time::timeout(
        Duration::from_secs(10),
        client::connect_stream(
            Arc::new(client::Config::default()),
            stream,
            CheckKey(expected),
        ),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(new
        .authenticate_none("fixture-user")
        .await
        .unwrap()
        .success());
    let mut new_channel = new.channel_open_session().await.unwrap();
    for index in 0..16 {
        let bytes = format!("SSH-generation-echo-{index:04}");
        exchange(&mut old_channel, bytes.as_bytes()).await;
        exchange(&mut new_channel, bytes.as_bytes()).await;
    }
    assert_eq!(
        fixture.manager.query("ssh-switch").unwrap().phase,
        "draining"
    );
    old.disconnect(russh::Disconnect::ByApplication, "fixture finished", "")
        .await
        .unwrap();
    new.disconnect(russh::Disconnect::ByApplication, "fixture finished", "")
        .await
        .unwrap();
    drop((old_channel, new_channel, old, new));
    fixture.stop().await;
    origin.abort();
}
