use crate::audit::TranscriptMetadata;
use crate::retention::date_partition_directory;
use sha2::{Digest, Sha256};
use std::io;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub struct PrefixedIo<I> {
    inner: I,
    prefix: Vec<u8>,
    offset: usize,
}

impl<I> PrefixedIo<I> {
    pub fn new(inner: I, prefix: Vec<u8>) -> Self {
        Self {
            inner,
            prefix,
            offset: 0,
        }
    }

    pub fn into_inner(self) -> I {
        self.inner
    }

    pub fn into_parts(self) -> (I, Vec<u8>) {
        (self.inner, self.prefix[self.offset..].to_vec())
    }
}

impl<I: AsyncRead + Unpin> AsyncRead for PrefixedIo<I> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.offset < self.prefix.len() && buffer.remaining() > 0 {
            let count = buffer
                .remaining()
                .min(self.prefix.len().saturating_sub(self.offset));
            let end = self.offset + count;
            buffer.put_slice(&self.prefix[self.offset..end]);
            self.offset = end;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(context, buffer)
    }
}

impl<I: AsyncWrite + Unpin> AsyncWrite for PrefixedIo<I> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(context, buffer)
    }

    fn poll_flush(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(context)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(context)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffers: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write_vectored(context, buffers)
    }
}

#[derive(Clone, Debug)]
pub struct CaptureConfig {
    pub root: PathBuf,
    pub date_key: u32,
    pub limit: usize,
    pub session_id: String,
    pub connection_id: u64,
    pub stream_id: Option<u64>,
    pub client_upload: bool,
    pub server_response: bool,
}

impl CaptureConfig {
    pub(crate) fn transcript_paths(&self, extension: &str) -> (PathBuf, PathBuf) {
        let safe_session = self
            .session_id
            .chars()
            .map(|value| {
                if value.is_ascii_alphanumeric() || value == '-' || value == '_' {
                    value
                } else {
                    '_'
                }
            })
            .collect::<String>();
        let directory = date_partition_directory(&self.root, self.date_key).join(safe_session);
        let name = self.stream_id.map_or_else(
            || self.connection_id.to_string(),
            |stream_id| format!("{}-{stream_id}", self.connection_id),
        );
        (
            directory.join(format!("{name}-up.{extension}")),
            directory.join(format!("{name}-down.{extension}")),
        )
    }
}

#[derive(Debug)]
pub struct BridgeResult {
    pub bytes_up: u64,
    pub bytes_down: u64,
    pub transcripts: Vec<TranscriptMetadata>,
}

pub async fn bridge<C, U>(
    mut client: C,
    mut upstream: U,
    capture: Option<CaptureConfig>,
) -> io::Result<BridgeResult>
where
    C: AsyncRead + AsyncWrite + Unpin,
    U: AsyncRead + AsyncWrite + Unpin,
{
    let Some(capture) = capture else {
        let (bytes_up, bytes_down) =
            tokio::io::copy_bidirectional(&mut client, &mut upstream).await?;
        return Ok(BridgeResult {
            bytes_up,
            bytes_down,
            transcripts: Vec::new(),
        });
    };

    let (client_read, client_write) = tokio::io::split(client);
    let (upstream_read, upstream_write) = tokio::io::split(upstream);
    let (up_path, down_path) = capture.transcript_paths("bin");
    let up_path = capture.client_upload.then_some(up_path);
    let down_path = capture.server_response.then_some(down_path);
    if let Some(path) = up_path.as_deref() {
        prepare_transcript(path)?;
    }
    if let Some(path) = down_path.as_deref() {
        prepare_transcript(path)?;
    }
    let (up, down) = tokio::try_join!(
        copy_direction(
            client_read,
            upstream_write,
            up_path,
            capture.limit,
            "client_to_target"
        ),
        copy_direction(
            upstream_read,
            client_write,
            down_path,
            capture.limit,
            "target_to_client"
        )
    )?;
    Ok(BridgeResult {
        bytes_up: up.0,
        bytes_down: down.0,
        transcripts: [up.1, down.1].into_iter().flatten().collect(),
    })
}

pub(crate) fn prepare_transcript(path: &Path) -> io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "transcript has no parent"))?;
    std::fs::create_dir_all(parent)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))?;
        std::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .mode(0o600)
            .open(path)?;
    }
    #[cfg(not(unix))]
    {
        std::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(path)?;
    }
    Ok(())
}

async fn copy_direction<R, W>(
    mut reader: R,
    mut writer: W,
    path: Option<PathBuf>,
    limit: usize,
    direction: &'static str,
) -> io::Result<(u64, Option<TranscriptMetadata>)>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let Some(path) = path else {
        let size = tokio::io::copy(&mut reader, &mut writer).await?;
        writer.shutdown().await?;
        return Ok((size, None));
    };
    let mut transcript = tokio::fs::OpenOptions::new()
        .write(true)
        .open(&path)
        .await?;
    let mut hash = Sha256::new();
    let mut size = 0u64;
    let mut captured = 0usize;
    let mut buffer = vec![0u8; 16 * 1024];
    loop {
        let count = reader.read(&mut buffer).await?;
        if count == 0 {
            break;
        }
        hash.update(&buffer[..count]);
        size = size.saturating_add(count as u64);
        let remaining = limit.saturating_sub(captured);
        let to_write = remaining.min(count);
        if to_write > 0 {
            transcript.write_all(&buffer[..to_write]).await?;
            captured += to_write;
        }
        writer.write_all(&buffer[..count]).await?;
    }
    writer.shutdown().await?;
    transcript.flush().await?;
    Ok((
        size,
        Some(TranscriptMetadata {
            direction,
            path,
            sha256: format!("{:x}", hash.finalize()),
            size,
            captured_size: captured as u64,
            truncated: size > captured as u64,
        }),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[tokio::test]
    async fn bridges_unknown_bytes_in_both_directions() {
        let (mut application, client) = tokio::io::duplex(128);
        let (upstream, mut target) = tokio::io::duplex(128);
        let bridge_task = tokio::spawn(bridge(client, upstream, None));

        application.write_all(b"unknown-request").await.unwrap();
        let mut request = [0u8; 15];
        target.read_exact(&mut request).await.unwrap();
        assert_eq!(&request, b"unknown-request");

        target.write_all(b"unknown-response").await.unwrap();
        let mut response = [0u8; 16];
        application.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"unknown-response");

        application.shutdown().await.unwrap();
        target.shutdown().await.unwrap();
        let result = bridge_task.await.unwrap().unwrap();
        assert_eq!(result.bytes_up, 15);
        assert_eq!(result.bytes_down, 16);
    }

    #[tokio::test]
    async fn captures_and_truncates_both_directions() {
        let root = std::env::temp_dir().join(format!(
            "hyperhub-duplex-test-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        let (mut application, client) = tokio::io::duplex(128);
        let (upstream, mut target) = tokio::io::duplex(128);
        let bridge_task = tokio::spawn(bridge(
            client,
            upstream,
            Some(CaptureConfig {
                root: root.clone(),
                date_key: crate::retention::date_key(0),
                limit: 4,
                session_id: "session/unsafe".into(),
                connection_id: 7,
                stream_id: None,
                client_upload: true,
                server_response: true,
            }),
        ));

        application.write_all(b"abcdefgh").await.unwrap();
        let mut request = [0u8; 8];
        target.read_exact(&mut request).await.unwrap();
        target.write_all(b"123456").await.unwrap();
        let mut response = [0u8; 6];
        application.read_exact(&mut response).await.unwrap();
        application.shutdown().await.unwrap();
        target.shutdown().await.unwrap();

        let result = bridge_task.await.unwrap().unwrap();
        assert_eq!((result.bytes_up, result.bytes_down), (8, 6));
        assert!(result.transcripts.iter().all(|item| item.truncated));
        assert!(result
            .transcripts
            .iter()
            .all(|item| item.captured_size == 4));
        let directory =
            date_partition_directory(&root, crate::retention::date_key(0)).join("session_unsafe");
        assert_eq!(std::fs::read(directory.join("7-up.bin")).unwrap(), b"abcd");
        assert_eq!(
            std::fs::read(directory.join("7-down.bin")).unwrap(),
            b"1234"
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn captures_only_the_selected_direction() {
        let root = std::env::temp_dir().join(format!(
            "hyperhub-duplex-direction-test-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        let (mut application, client) = tokio::io::duplex(128);
        let (upstream, mut target) = tokio::io::duplex(128);
        let bridge_task = tokio::spawn(bridge(
            client,
            upstream,
            Some(CaptureConfig {
                root: root.clone(),
                date_key: crate::retention::date_key(0),
                limit: 32,
                session_id: "direction".into(),
                connection_id: 8,
                stream_id: None,
                client_upload: false,
                server_response: true,
            }),
        ));

        application.write_all(b"request").await.unwrap();
        let mut request = [0u8; 7];
        target.read_exact(&mut request).await.unwrap();
        target.write_all(b"response").await.unwrap();
        let mut response = [0u8; 8];
        application.read_exact(&mut response).await.unwrap();
        application.shutdown().await.unwrap();
        target.shutdown().await.unwrap();

        let result = bridge_task.await.unwrap().unwrap();
        assert_eq!(result.transcripts.len(), 1);
        assert_eq!(result.transcripts[0].direction, "target_to_client");
        let directory =
            date_partition_directory(&root, crate::retention::date_key(0)).join("direction");
        assert!(!directory.join("8-up.bin").exists());
        assert_eq!(
            std::fs::read(directory.join("8-down.bin")).unwrap(),
            b"response"
        );
        std::fs::remove_dir_all(root).unwrap();
    }
}
