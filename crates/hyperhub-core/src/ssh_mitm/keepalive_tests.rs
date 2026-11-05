use super::*;
use crate::policy::{Destination, ProcessInfo};
use std::net::{IpAddr, Ipv4Addr};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize};
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, DuplexStream, ReadBuf};

// Count actual peer replies. After authentication a test can discard one
// direction to model a silent path failure without sending an EOF.
struct ObservedStream {
    inner: DuplexStream,
    received: Arc<AtomicUsize>,
    blackhole: Arc<AtomicBool>,
}

impl AsyncRead for ObservedStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.blackhole.load(Ordering::Acquire) {
            let mut bytes = [0; 4096];
            let mut discarded = ReadBuf::new(&mut bytes);
            return match Pin::new(&mut self.inner).poll_read(cx, &mut discarded) {
                Poll::Ready(Ok(())) if !discarded.filled().is_empty() => {
                    cx.waker().wake_by_ref();
                    Poll::Pending
                }
                result => result,
            };
        }
        let before = out.filled().len();
        let result = Pin::new(&mut self.inner).poll_read(cx, out);
        self.received
            .fetch_add(out.filled().len() - before, Ordering::Release);
        result
    }
}

impl AsyncWrite for ObservedStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, bytes)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

struct Echo;
impl server::Handler for Echo {
    type Error = russh::Error;
    async fn auth_password(
        &mut self,
        user: &str,
        password: &str,
    ) -> Result<server::Auth, Self::Error> {
        Ok(
            if user == "idle-user" && password == "local-idle-password" {
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
}

struct Client(russh::keys::PublicKey);
impl client::Handler for Client {
    type Error = russh::Error;
    async fn check_server_key(
        &mut self,
        key: &russh::keys::PublicKey,
    ) -> Result<bool, Self::Error> {
        Ok(key == &self.0)
    }
}

struct Fixture {
    client: client::Handle<Client>,
    channel: Channel<client::Msg>,
    proxy: JoinHandle<io::Result<()>>,
    origin: JoinHandle<()>,
    replies: [Arc<AtomicUsize>; 2],
    blackhole: [Arc<AtomicBool>; 2],
}

impl Fixture {
    async fn start() -> Self {
        Self::start_mode(true).await
    }

    async fn start_mode(mitm: bool) -> Self {
        let origin_key = server_key_from_master(b"local-idle-origin");
        let origin_public = origin_key.public_key().clone();
        let proxy_key = Arc::new(server_key_from_master(b"local-idle-proxy"));
        let proxy_public = proxy_key.public_key().clone();
        let (client_stream, proxy_client) = tokio::io::duplex(64 * 1024);
        let (proxy_origin, origin_stream) = tokio::io::duplex(64 * 1024);
        let origin = tokio::spawn(async move {
            let session = server::run_stream(
                Arc::new(server::Config {
                    keys: vec![origin_key],
                    auth_rejection_time: Duration::ZERO,
                    inactivity_timeout: None,
                    keepalive_interval: None,
                    ..Default::default()
                }),
                origin_stream,
                Echo,
            )
            .await
            .unwrap();
            let _ = session.await;
        });
        let replies = std::array::from_fn(|_| Arc::new(AtomicUsize::new(0)));
        let blackhole = std::array::from_fn(|_| Arc::new(AtomicBool::new(false)));
        let observed = |inner, index: usize| {
            Box::new(ObservedStream {
                inner,
                received: replies[index].clone(),
                blackhole: blackhole[index].clone(),
            }) as BoxedStream
        };
        let accepted_key = if mitm {
            proxy_public
        } else {
            origin_public.clone()
        };
        let proxy = if mitm {
            tokio::spawn(run_ssh_mitm(
                observed(proxy_client, 0),
                observed(proxy_origin, 1),
                SshAuthCandidates {
                    accounts: vec![SshAuthAccount {
                        username: "idle-user".into(),
                        keys: vec![],
                        passwords: vec!["local-idle-password".into()],
                    }],
                },
                SshHostKeyExpectation {
                    key_type: origin_public.algorithm().to_string(),
                    key_blob: base64::engine::general_purpose::STANDARD
                        .encode(origin_public.to_bytes().unwrap()),
                },
                SshAuditContext {
                    audit: AuditWriter::open(None).unwrap(),
                    context: ConnectionContext {
                        session_id: "idle-test".into(),
                        connection_id: 1,
                        process: ProcessInfo::default(),
                        destination: Destination {
                            ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
                            port: 22,
                            hostnames: vec![],
                        },
                        protocol: crate::policy::Protocol::Ssh,
                    },
                    rule_id: None,
                    server_key: proxy_key,
                    record_events: false,
                    transcript: None,
                },
            ))
        } else {
            let client = observed(proxy_client, 0);
            let upstream = observed(proxy_origin, 1);
            tokio::spawn(async move {
                crate::duplex::bridge(client, upstream, None)
                    .await
                    .map(|_| ())
            })
        };
        let mut client = client::connect_stream(
            Arc::new(client::Config {
                keepalive_interval: None,
                inactivity_timeout: None,
                ..Default::default()
            }),
            client_stream,
            Client(accepted_key),
        )
        .await
        .unwrap();
        let authentication = if mitm {
            client.authenticate_none("idle-user").await
        } else {
            client
                .authenticate_password("idle-user", "local-idle-password")
                .await
        };
        assert!(authentication.unwrap().success());
        let channel = client.channel_open_session().await.unwrap();
        let mut fixture = Self {
            client,
            channel,
            proxy,
            origin,
            replies,
            blackhole,
        };
        fixture.exchange(b"before idle").await;
        for _ in 0..128 {
            tokio::task::yield_now().await;
        }
        fixture
    }

    async fn exchange(&mut self, expected: &[u8]) {
        self.channel.data(expected).await.unwrap();
        let mut actual = vec![];
        tokio::time::timeout(Duration::from_secs(5), async {
            while actual.len() < expected.len() {
                match self.channel.wait().await {
                    Some(ChannelMsg::Data { data }) => actual.extend_from_slice(&data),
                    Some(ChannelMsg::Success) => {}
                    other => panic!("idle SSH channel ended: {other:?}"),
                }
            }
        })
        .await
        .expect("idle SSH echo did not complete");
        assert_eq!(actual, expected);
    }

    async fn stop(mut self) {
        let _ = self
            .client
            .disconnect(russh::Disconnect::ByApplication, "fixture complete", "")
            .await;
        tokio::time::timeout(Duration::from_secs(5), &mut self.proxy)
            .await
            .expect("proxy did not finish")
            .unwrap()
            .ok();
        self.origin.abort();
        let _ = self.origin.await;
    }
}

#[tokio::test]
async fn encrypted_passthrough_has_no_idle_session_deadline() {
    let mut fixture = Fixture::start_mode(false).await;
    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(601)).await;
    for _ in 0..128 {
        tokio::task::yield_now().await;
    }
    fixture
        .exchange(b"passthrough after ten idle minutes")
        .await;
    fixture.stop().await;
}

#[tokio::test]
async fn passive_ssh_client_survives_the_old_ten_minute_idle_boundary() {
    let mut fixture = Fixture::start().await;
    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(601)).await;
    for _ in 0..128 {
        tokio::task::yield_now().await;
    }
    fixture.exchange(b"after ten idle minutes").await;
    fixture.stop().await;
}

#[tokio::test]
async fn both_ssh_transports_probe_passive_peers_without_channel_traffic() {
    let fixture = Fixture::start().await;
    tokio::time::pause();
    for cycle in 0..5 {
        let before = fixture
            .replies
            .each_ref()
            .map(|count| count.load(Ordering::Acquire));
        tokio::time::advance(Duration::from_secs(31)).await;
        for _ in 0..4096 {
            if fixture
                .replies
                .iter()
                .zip(before)
                .all(|(count, before)| count.load(Ordering::Acquire) > before)
            {
                break;
            }
            tokio::task::yield_now().await;
        }
        for (index, before) in before.into_iter().enumerate() {
            assert!(
                fixture.replies[index].load(Ordering::Acquire) > before,
                "transport {index} did not complete keepalive cycle {cycle}: before={before}, after={}", fixture.replies[index].load(Ordering::Acquire)
            );
        }
    }
    fixture.stop().await;
}

#[tokio::test]
async fn missing_keepalive_replies_end_the_affected_channel() {
    for broken_leg in 0..2 {
        let mut fixture = Fixture::start().await;
        tokio::time::pause();
        fixture.blackhole[broken_leg].store(true, Ordering::Release);
        for cycle in 0..5 {
            tokio::time::advance(Duration::from_secs(31)).await;
            for _ in 0..128 {
                tokio::task::yield_now().await;
            }
            eprintln!("blackhole leg={broken_leg} cycle={cycle} proxy_finished={} client_closed={} replies={:?}", fixture.proxy.is_finished(), fixture.client.is_closed(), fixture.replies.each_ref().map(|count| count.load(Ordering::Acquire)));
        }
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                match fixture.channel.wait().await {
                    Some(ChannelMsg::Close) | None => break,
                    Some(ChannelMsg::Eof) => {}
                    other => panic!("unexpected message after silent path failure: {other:?}"),
                }
            }
        })
        .await
        .unwrap_or_else(|_| {
            panic!("silent SSH path failure on leg {broken_leg} left the channel open")
        });
        fixture.stop().await;
        tokio::time::resume();
    }
}
