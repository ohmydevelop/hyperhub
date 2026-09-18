use crate::audit::TranscriptMetadata;
use crate::duplex::{prepare_transcript, BridgeResult, CaptureConfig};
use base64::Engine;
use flate2::{Decompress, FlushDecompress};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::io;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

const MAX_FRAME_SIZE: usize = 64 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Compression {
    pub enabled: bool,
    pub client_no_context_takeover: bool,
    pub server_no_context_takeover: bool,
}

pub(crate) async fn bridge_messages<C, U>(
    client: C,
    upstream: U,
    capture: CaptureConfig,
    compression: Compression,
) -> io::Result<BridgeResult>
where
    C: AsyncRead + AsyncWrite + Unpin,
    U: AsyncRead + AsyncWrite + Unpin,
{
    let (client_read, client_write) = tokio::io::split(client);
    let (upstream_read, upstream_write) = tokio::io::split(upstream);
    let (up_path, down_path) = capture.transcript_paths("jsonl");
    let up_path = capture.client_upload.then_some(up_path);
    let down_path = capture.server_response.then_some(down_path);
    if let Some(path) = up_path.as_deref() {
        prepare_transcript(path)?;
    }
    if let Some(path) = down_path.as_deref() {
        prepare_transcript(path)?;
    }
    let (up, down) = tokio::try_join!(
        copy_messages(
            client_read,
            upstream_write,
            up_path,
            capture.limit,
            "client_to_target",
            compression.enabled,
            compression.client_no_context_takeover,
        ),
        copy_messages(
            upstream_read,
            client_write,
            down_path,
            capture.limit,
            "target_to_client",
            compression.enabled,
            compression.server_no_context_takeover,
        )
    )?;
    Ok(BridgeResult {
        bytes_up: up.0,
        bytes_down: down.0,
        transcripts: [up.1, down.1].into_iter().flatten().collect(),
    })
}

async fn copy_messages<R, W>(
    mut reader: R,
    mut writer: W,
    path: Option<PathBuf>,
    limit: usize,
    direction: &'static str,
    compression_enabled: bool,
    no_context_takeover: bool,
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
    let mut parser = FrameParser::new(compression_enabled, no_context_takeover, limit);
    let mut hash = Sha256::new();
    let mut raw_size = 0u64;
    let mut file_size = 0u64;
    let mut payload_captured = 0usize;
    let mut sequence = 0u64;
    let mut truncated = false;
    let mut exhausted_recorded = false;
    let mut buffer = vec![0u8; 16 * 1024];

    loop {
        let count = reader.read(&mut buffer).await?;
        if count == 0 {
            break;
        }
        let bytes = &buffer[..count];
        hash.update(bytes);
        raw_size = raw_size.saturating_add(count as u64);
        writer.write_all(bytes).await?;
        for event in parser.feed(bytes) {
            sequence = sequence.saturating_add(1);
            if event.is_payload() && payload_captured >= limit {
                truncated = true;
                if exhausted_recorded {
                    continue;
                }
                exhausted_recorded = true;
            }
            let (record, captured, event_truncated) =
                event.to_json(direction, sequence, limit.saturating_sub(payload_captured));
            payload_captured = payload_captured.saturating_add(captured);
            truncated |= event_truncated;
            let mut line = serde_json::to_vec(&record).map_err(io::Error::other)?;
            line.push(b'\n');
            transcript.write_all(&line).await?;
            file_size = file_size.saturating_add(line.len() as u64);
        }
    }
    if let Some(event) = parser.finish() {
        sequence = sequence.saturating_add(1);
        truncated = true;
        let (record, _, _) = event.to_json(direction, sequence, 0);
        let mut line = serde_json::to_vec(&record).map_err(io::Error::other)?;
        line.push(b'\n');
        transcript.write_all(&line).await?;
        file_size = file_size.saturating_add(line.len() as u64);
    }
    writer.shutdown().await?;
    transcript.flush().await?;
    Ok((
        raw_size,
        Some(TranscriptMetadata {
            direction,
            path,
            sha256: format!("{:x}", hash.finalize()),
            size: raw_size,
            captured_size: file_size,
            truncated,
        }),
    ))
}

#[derive(Debug)]
enum Event {
    Message {
        opcode: &'static str,
        payload: Vec<u8>,
        size: u64,
        compressed: bool,
        masked: bool,
        truncated: bool,
    },
    Error(String),
}

impl Event {
    fn is_payload(&self) -> bool {
        matches!(self, Self::Message { .. })
    }

    fn to_json(
        &self,
        direction: &'static str,
        sequence: u64,
        remaining: usize,
    ) -> (Value, usize, bool) {
        match self {
            Self::Error(message) => (
                json!({
                    "timestamp_ms": timestamp_ms(),
                    "sequence": sequence,
                    "direction": direction,
                    "type": "parse_error",
                    "message": message,
                }),
                0,
                true,
            ),
            Self::Message {
                opcode,
                payload,
                size,
                compressed,
                masked,
                truncated,
            } => {
                let captured = remaining.min(payload.len());
                let payload = &payload[..captured];
                let truncated = *truncated || captured as u64 != *size;
                let mut record = json!({
                    "timestamp_ms": timestamp_ms(),
                    "sequence": sequence,
                    "direction": direction,
                    "type": opcode,
                    "compressed": compressed,
                    "masked": masked,
                    "size": size,
                    "captured_size": captured,
                    "truncated": truncated,
                });
                match *opcode {
                    "text" => {
                        record["utf8_valid"] = json!(std::str::from_utf8(payload).is_ok());
                        record["text"] = json!(String::from_utf8_lossy(payload));
                    }
                    "close" => {
                        if payload.len() >= 2 {
                            record["code"] = json!(u16::from_be_bytes([payload[0], payload[1]]));
                            record["reason"] = json!(String::from_utf8_lossy(&payload[2..]));
                        }
                    }
                    _ => {
                        record["base64"] =
                            json!(base64::engine::general_purpose::STANDARD.encode(payload));
                    }
                }
                (record, captured, truncated)
            }
        }
    }
}

struct MessageAccumulator {
    opcode: &'static str,
    compressed: bool,
    masked: bool,
    data: Vec<u8>,
    size: u64,
    truncated: bool,
}

impl MessageAccumulator {
    fn push(&mut self, payload: &[u8], store_limit: usize) {
        self.size = self.size.saturating_add(payload.len() as u64);
        let remaining = store_limit.saturating_sub(self.data.len());
        let captured = remaining.min(payload.len());
        self.data.extend_from_slice(&payload[..captured]);
        self.truncated |= captured != payload.len();
    }
}

struct FrameParser {
    buffer: Vec<u8>,
    fragmented: Option<MessageAccumulator>,
    inflater: Decompress,
    compression_enabled: bool,
    no_context_takeover: bool,
    store_limit: usize,
    disabled: bool,
}

impl FrameParser {
    fn new(compression_enabled: bool, no_context_takeover: bool, store_limit: usize) -> Self {
        Self {
            buffer: Vec::new(),
            fragmented: None,
            inflater: Decompress::new(false),
            compression_enabled,
            no_context_takeover,
            store_limit,
            disabled: false,
        }
    }

    fn feed(&mut self, bytes: &[u8]) -> Vec<Event> {
        if self.disabled {
            return Vec::new();
        }
        self.buffer.extend_from_slice(bytes);
        let mut events = Vec::new();
        let mut consumed = 0usize;
        loop {
            let frame = match parse_frame(&self.buffer[consumed..]) {
                Ok(Some(frame)) => frame,
                Ok(None) => break,
                Err(error) => {
                    events.push(Event::Error(error));
                    self.disabled = true;
                    break;
                }
            };
            consumed = consumed.saturating_add(frame.consumed);
            if let Err(error) = self.process_frame(frame, &mut events) {
                events.push(Event::Error(error));
                self.disabled = true;
                break;
            }
        }
        if consumed > 0 {
            self.buffer.drain(..consumed);
        }
        if self.buffer.len() > MAX_FRAME_SIZE {
            events.push(Event::Error(
                "WebSocket frame buffer exceeded 64 MiB".into(),
            ));
            self.buffer.clear();
            self.disabled = true;
        }
        events
    }

    fn process_frame(&mut self, frame: Frame, events: &mut Vec<Event>) -> Result<(), String> {
        match frame.opcode {
            0 => {
                if frame.rsv1 {
                    return Err("continuation frame unexpectedly sets RSV1".into());
                }
                let compressed = self
                    .fragmented
                    .as_ref()
                    .ok_or_else(|| "continuation frame has no initial frame".to_string())?
                    .compressed;
                let store_limit = self.message_store_limit(compressed);
                let message = self
                    .fragmented
                    .as_mut()
                    .ok_or_else(|| "continuation frame has no initial frame".to_string())?;
                message.masked &= frame.masked;
                message.push(&frame.payload, store_limit);
                if frame.fin {
                    let message = self.fragmented.take().expect("fragment exists");
                    events.push(self.finish_message(message)?);
                }
            }
            1 | 2 => {
                if self.fragmented.is_some() {
                    return Err("new data frame arrived before fragmented message completed".into());
                }
                if frame.rsv1 && !self.compression_enabled {
                    return Err("compressed WebSocket frame was not negotiated".into());
                }
                let mut message = MessageAccumulator {
                    opcode: if frame.opcode == 1 { "text" } else { "binary" },
                    compressed: frame.rsv1,
                    masked: frame.masked,
                    data: Vec::new(),
                    size: 0,
                    truncated: false,
                };
                message.push(&frame.payload, self.message_store_limit(message.compressed));
                if frame.fin {
                    events.push(self.finish_message(message)?);
                } else {
                    self.fragmented = Some(message);
                }
            }
            8..=10 => {
                if !frame.fin || frame.payload.len() > 125 || frame.rsv1 {
                    return Err("invalid WebSocket control frame".into());
                }
                events.push(Event::Message {
                    opcode: match frame.opcode {
                        8 => "close",
                        9 => "ping",
                        _ => "pong",
                    },
                    size: frame.payload.len() as u64,
                    payload: frame.payload,
                    compressed: false,
                    masked: frame.masked,
                    truncated: false,
                });
            }
            _ => return Err(format!("unsupported WebSocket opcode 0x{:x}", frame.opcode)),
        }
        Ok(())
    }

    fn message_store_limit(&self, compressed: bool) -> usize {
        if compressed {
            MAX_FRAME_SIZE
        } else {
            self.store_limit.min(MAX_FRAME_SIZE)
        }
    }

    fn finish_message(&mut self, message: MessageAccumulator) -> Result<Event, String> {
        if !message.compressed {
            return Ok(Event::Message {
                opcode: message.opcode,
                payload: message.data,
                size: message.size,
                compressed: false,
                masked: message.masked,
                truncated: message.truncated,
            });
        }
        if message.truncated {
            return Err("compressed WebSocket message exceeded 64 MiB".into());
        }
        let (payload, size, truncated) = decompress_message(
            &mut self.inflater,
            &message.data,
            self.store_limit.min(MAX_FRAME_SIZE),
        )?;
        if self.no_context_takeover {
            self.inflater = Decompress::new(false);
        }
        Ok(Event::Message {
            opcode: message.opcode,
            payload,
            size,
            compressed: true,
            masked: message.masked,
            truncated,
        })
    }

    fn finish(mut self) -> Option<Event> {
        if self.disabled || (self.buffer.is_empty() && self.fragmented.is_none()) {
            return None;
        }
        self.buffer.clear();
        self.fragmented = None;
        Some(Event::Error(
            "WebSocket stream ended with an incomplete frame or fragmented message".into(),
        ))
    }
}

struct Frame {
    fin: bool,
    rsv1: bool,
    opcode: u8,
    masked: bool,
    payload: Vec<u8>,
    consumed: usize,
}

fn parse_frame(input: &[u8]) -> Result<Option<Frame>, String> {
    if input.len() < 2 {
        return Ok(None);
    }
    let fin = input[0] & 0x80 != 0;
    let rsv1 = input[0] & 0x40 != 0;
    if input[0] & 0x30 != 0 {
        return Err("WebSocket frame sets unsupported RSV2/RSV3 bits".into());
    }
    let opcode = input[0] & 0x0f;
    let masked = input[1] & 0x80 != 0;
    let mut offset = 2usize;
    let length = match input[1] & 0x7f {
        value @ 0..=125 => value as u64,
        126 => {
            if input.len() < offset + 2 {
                return Ok(None);
            }
            let value = u16::from_be_bytes([input[offset], input[offset + 1]]) as u64;
            offset += 2;
            value
        }
        _ => {
            if input.len() < offset + 8 {
                return Ok(None);
            }
            let value = u64::from_be_bytes(input[offset..offset + 8].try_into().unwrap());
            if value >> 63 != 0 {
                return Err("WebSocket frame uses an invalid 64-bit length".into());
            }
            offset += 8;
            value
        }
    };
    let length = usize::try_from(length).map_err(|_| "WebSocket frame length overflow")?;
    if length > MAX_FRAME_SIZE {
        return Err("WebSocket frame exceeds 64 MiB".into());
    }
    let mask = if masked {
        if input.len() < offset + 4 {
            return Ok(None);
        }
        let mask: [u8; 4] = input[offset..offset + 4].try_into().unwrap();
        offset += 4;
        Some(mask)
    } else {
        None
    };
    let end = offset
        .checked_add(length)
        .ok_or_else(|| "WebSocket frame length overflow".to_string())?;
    if input.len() < end {
        return Ok(None);
    }
    let mut payload = input[offset..end].to_vec();
    if let Some(mask) = mask {
        for (index, byte) in payload.iter_mut().enumerate() {
            *byte ^= mask[index % 4];
        }
    }
    Ok(Some(Frame {
        fin,
        rsv1,
        opcode,
        masked,
        payload,
        consumed: end,
    }))
}

fn decompress_message(
    inflater: &mut Decompress,
    compressed: &[u8],
    store_limit: usize,
) -> Result<(Vec<u8>, u64, bool), String> {
    let mut input = Vec::with_capacity(compressed.len() + 4);
    input.extend_from_slice(compressed);
    input.extend_from_slice(&[0x00, 0x00, 0xff, 0xff]);
    let mut input_offset = 0usize;
    let mut output = Vec::new();
    let mut total_output = 0u64;
    loop {
        let before_in = inflater.total_in();
        let before_out = inflater.total_out();
        let mut chunk = [0u8; 16 * 1024];
        inflater
            .decompress(&input[input_offset..], &mut chunk, FlushDecompress::Sync)
            .map_err(|error| format!("permessage-deflate decode failed: {error}"))?;
        let consumed = (inflater.total_in() - before_in) as usize;
        let produced = (inflater.total_out() - before_out) as usize;
        input_offset = input_offset.saturating_add(consumed);
        total_output = total_output.saturating_add(produced as u64);
        let remaining = store_limit.saturating_sub(output.len());
        output.extend_from_slice(&chunk[..remaining.min(produced)]);
        if consumed == 0 && produced == 0 {
            break;
        }
        if input_offset >= input.len() && produced < chunk.len() {
            break;
        }
    }
    if input_offset < input.len() {
        return Err("permessage-deflate decoder did not consume the message".into());
    }
    Ok((output, total_output, total_output > store_limit as u64))
}

fn timestamp_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u64::MAX as u128) as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::{Compress, Compression as FlateCompression, FlushCompress};

    fn masked_frame(fin: bool, opcode: u8, payload: &[u8]) -> Vec<u8> {
        let mask = [1u8, 2, 3, 4];
        let mut frame = vec![(u8::from(fin) << 7) | opcode, 0x80 | payload.len() as u8];
        frame.extend_from_slice(&mask);
        frame.extend(
            payload
                .iter()
                .enumerate()
                .map(|(index, byte)| byte ^ mask[index % 4]),
        );
        frame
    }

    fn server_text_frame(payload: &[u8]) -> Vec<u8> {
        let mut frame = vec![0x81, payload.len() as u8];
        frame.extend_from_slice(payload);
        frame
    }

    #[test]
    fn unmasks_and_reassembles_fragmented_text_messages() {
        let mut parser = FrameParser::new(false, false, 1024);
        assert!(parser.feed(&masked_frame(false, 1, b"hel")).is_empty());
        let events = parser.feed(&masked_frame(true, 0, b"lo"));
        let Event::Message {
            opcode,
            payload,
            masked,
            ..
        } = &events[0]
        else {
            panic!("expected a message")
        };
        assert_eq!(*opcode, "text");
        assert_eq!(payload, b"hello");
        assert!(*masked);
    }

    #[test]
    fn decodes_permessage_deflate_payloads() {
        let payload = br#"{"type":"delta","text":"hello"}"#;
        let mut compressor = Compress::new(FlateCompression::fast(), false);
        let mut compressed = Vec::with_capacity(128);
        compressor
            .compress_vec(payload, &mut compressed, FlushCompress::Sync)
            .unwrap();
        assert!(compressed.ends_with(&[0x00, 0x00, 0xff, 0xff]));
        compressed.truncate(compressed.len() - 4);
        let (decoded, size, truncated) =
            decompress_message(&mut Decompress::new(false), &compressed, 1024).unwrap();
        assert_eq!(decoded, payload);
        assert_eq!(size, payload.len() as u64);
        assert!(!truncated);
    }

    #[tokio::test]
    async fn message_capture_respects_the_selected_direction() {
        let root = std::env::temp_dir().join(format!(
            "hyperhub-websocket-direction-{}-{}",
            std::process::id(),
            timestamp_ms()
        ));
        let date_key = crate::retention::date_key(0);
        let (mut application, client) = tokio::io::duplex(1024);
        let (upstream, mut target) = tokio::io::duplex(1024);
        let task = tokio::spawn(bridge_messages(
            client,
            upstream,
            CaptureConfig {
                root: root.clone(),
                date_key,
                limit: 1024,
                session_id: "ws-direction".into(),
                connection_id: 9,
                stream_id: None,
                client_upload: false,
                server_response: true,
            },
            Compression::default(),
        ));

        let request = masked_frame(true, 1, b"request");
        application.write_all(&request).await.unwrap();
        let mut forwarded_request = vec![0; request.len()];
        target.read_exact(&mut forwarded_request).await.unwrap();
        assert_eq!(forwarded_request, request);

        let response = server_text_frame(b"response");
        target.write_all(&response).await.unwrap();
        let mut forwarded_response = vec![0; response.len()];
        application
            .read_exact(&mut forwarded_response)
            .await
            .unwrap();
        assert_eq!(forwarded_response, response);
        application.shutdown().await.unwrap();
        target.shutdown().await.unwrap();

        let result = task.await.unwrap().unwrap();
        assert_eq!(result.transcripts.len(), 1);
        assert_eq!(result.transcripts[0].direction, "target_to_client");
        let directory =
            crate::retention::date_partition_directory(&root, date_key).join("ws-direction");
        assert!(!directory.join("9-up.jsonl").exists());
        let content = std::fs::read_to_string(directory.join("9-down.jsonl")).unwrap();
        assert!(content.contains("response"));
        std::fs::remove_dir_all(root).unwrap();
    }
}
