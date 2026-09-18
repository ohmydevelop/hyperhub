//! Length-prefixed JSON framing used exclusively by the local control plane.

use serde::{de::DeserializeOwned, Serialize};
use std::io;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// 控制平面帧上限：配置热更新会携带完整 Config JSON（含根证书与规则），
/// 64 KiB 对真实配置过小，放宽到 1 MiB；本地管道内存开销可忽略。
pub const MAX_FRAME: usize = 1024 * 1024;

pub async fn write_frame<W: AsyncWrite + Unpin, T: Serialize>(
    writer: &mut W,
    value: &T,
) -> io::Result<()> {
    let data = serde_json::to_vec(value).map_err(io::Error::other)?;
    if data.len() > MAX_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "frame exceeds 64 KiB",
        ));
    }
    writer.write_u32(data.len() as u32).await?;
    writer.write_all(&data).await?;
    writer.flush().await
}

pub async fn read_frame<R: AsyncRead + Unpin, T: DeserializeOwned>(
    reader: &mut R,
) -> io::Result<T> {
    let len = reader.read_u32().await? as usize;
    if len > MAX_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "frame exceeds 64 KiB",
        ));
    }
    let mut data = vec![0; len];
    reader.read_exact(&mut data).await?;
    serde_json::from_slice(&data).map_err(io::Error::other)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[tokio::test]
    async fn round_trip_frame() {
        let (mut left, mut right) = tokio::io::duplex(1024);
        let task = tokio::spawn(async move {
            write_frame(&mut left, &json!({"version": 2, "ok": true}))
                .await
                .unwrap();
        });
        let received: serde_json::Value = read_frame(&mut right).await.unwrap();
        task.await.unwrap();
        assert_eq!(received, json!({"version": 2, "ok": true}));
    }
}
