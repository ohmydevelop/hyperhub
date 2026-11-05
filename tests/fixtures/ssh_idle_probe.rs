//! An independent SSH client: keep PTY, exec and subsystem channels idle, then
//! verify each channel still carries the exact application bytes.
use base64::Engine;
use russh::{client, Channel, ChannelMsg};
use serde::Deserialize;
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

#[derive(Deserialize)]
struct Input {
    socks: SocketAddr,
    destination: SocketAddr,
    session: String,
    registered_pid: u32,
    token: String,
    connection_id: u64,
    expected_key: String,
    client_probes: bool,
    idle_seconds: u64,
}

struct CheckKey(String);
impl client::Handler for CheckKey {
    type Error = russh::Error;
    async fn check_server_key(
        &mut self,
        key: &russh::keys::PublicKey,
    ) -> Result<bool, Self::Error> {
        Ok(base64::engine::general_purpose::STANDARD.encode(key.to_bytes().unwrap()) == self.0)
    }
}

async fn exchange(channel: &mut Channel<client::Msg>, value: &[u8]) {
    channel.data(value).await.unwrap();
    let mut actual = Vec::new();
    tokio::time::timeout(Duration::from_secs(10), async {
        while actual.len() < value.len() {
            match channel.wait().await {
                Some(ChannelMsg::Data { data }) => actual.extend_from_slice(&data),
                Some(ChannelMsg::Success) => {}
                other => panic!("idle channel ended: {other:?}"),
            }
        }
    })
    .await
    .expect("SSH channel exchange timed out");
    assert_eq!(actual, value);
}

async fn run(input: Input) {
    let mut stream = TcpStream::connect(input.socks).await.unwrap();
    stream.write_all(&[5, 1, 2]).await.unwrap();
    let mut method = [0; 2];
    stream.read_exact(&mut method).await.unwrap();
    assert_eq!(method, [5, 2]);
    let user = format!(
        "hh2:{}:{}:{}",
        input.session, input.registered_pid, input.connection_id
    );
    let mut auth = vec![1, u8::try_from(user.len()).unwrap()];
    auth.extend(user.bytes());
    auth.push(u8::try_from(input.token.len()).unwrap());
    auth.extend(input.token.bytes());
    stream.write_all(&auth).await.unwrap();
    stream.read_exact(&mut method).await.unwrap();
    assert_eq!(method, [1, 0]);
    let mut request = vec![5, 1, 0, 1];
    let std::net::IpAddr::V4(address) = input.destination.ip() else {
        panic!("this local fixture uses an IPv4 loopback origin");
    };
    request.extend(address.octets());
    request.extend(input.destination.port().to_be_bytes());
    stream.write_all(&request).await.unwrap();
    let mut reply = [0; 10];
    stream.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[1], 0);
    let mut client = client::connect_stream(
        Arc::new(client::Config {
            inactivity_timeout: None,
            keepalive_interval: input.client_probes.then_some(Duration::from_secs(5)),
            ..Default::default()
        }),
        stream,
        CheckKey(input.expected_key),
    )
    .await
    .unwrap();
    assert!(client
        .authenticate_none("fixture-user")
        .await
        .unwrap()
        .success());
    let mut channels = Vec::new();
    for kind in ["pty-shell", "exec", "subsystem"] {
        let mut channel = client.channel_open_session().await.unwrap();
        match kind {
            "pty-shell" => {
                channel
                    .request_pty(true, "xterm", 80, 24, 0, 0, &[])
                    .await
                    .unwrap();
                channel.request_shell(true).await.unwrap();
            }
            "exec" => channel.exec(true, b"idle-fixture".to_vec()).await.unwrap(),
            _ => channel
                .request_subsystem(true, "idle-fixture")
                .await
                .unwrap(),
        }
        exchange(&mut channel, format!("{kind}:before-idle").as_bytes()).await;
        channels.push((kind, channel));
    }
    println!("SSH_IDLE_READY client_probes={}", input.client_probes);
    std::io::stdout().flush().unwrap();
    // No application data is sent during this interval. Only protocol probes
    // may keep the independently timed origin connection alive.
    tokio::time::sleep(Duration::from_secs(input.idle_seconds)).await;
    for (kind, channel) in &mut channels {
        exchange(channel, format!("{kind}:after-idle").as_bytes()).await;
    }
    client
        .disconnect(russh::Disconnect::ByApplication, "fixture complete", "")
        .await
        .unwrap();
    println!(
        "SSH_IDLE_PASS client_probes={} idle_seconds={} channels=pty-shell,exec,subsystem",
        input.client_probes, input.idle_seconds
    );
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let mut bytes = String::new();
    std::io::stdin().read_to_string(&mut bytes).unwrap();
    let input: Input = serde_json::from_str(&bytes).unwrap();
    tokio::time::timeout(Duration::from_secs(95), run(input))
        .await
        .expect("external SSH idle fixture exceeded its watchdog");
}
