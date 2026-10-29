//! Stop JSON serialization at the pipe budget, before reserving excess memory.
use serde::Serialize;
use std::io::{self, Write};
use zeroize::Zeroizing;

fn exceeded() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "Core succession state exceeds its bounded pipe limit",
    )
}
struct Budget {
    limit: usize,
    written: usize,
    failed: bool,
}
impl Budget {
    fn admit(&mut self, count: usize) -> io::Result<usize> {
        let Some(next) = self
            .written
            .checked_add(count)
            .filter(|next| *next <= self.limit)
        else {
            self.failed = true;
            return Err(exceeded());
        };
        if self.failed {
            return Err(exceeded());
        }
        self.written = next;
        Ok(next)
    }
}
struct BoundedWriter {
    bytes: Zeroizing<Vec<u8>>,
    budget: Budget,
}
impl BoundedWriter {
    fn new(limit: usize) -> Self {
        Self {
            bytes: Zeroizing::new(Vec::new()),
            budget: Budget {
                limit,
                written: 0,
                failed: false,
            },
        }
    }
    fn finish(mut self) -> io::Result<Vec<u8>> {
        if self.budget.failed {
            return Err(exceeded());
        }
        Ok(std::mem::take(&mut *self.bytes))
    }
}
impl Write for BoundedWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let next = self.budget.admit(bytes.len())?;
        if next > self.bytes.capacity() {
            let capacity = self
                .bytes
                .capacity()
                .max(128)
                .saturating_mul(2)
                .min(self.budget.limit)
                .max(next);
            let additional = capacity - self.bytes.len();
            if let Err(error) = self.bytes.try_reserve_exact(additional) {
                self.budget.failed = true;
                return Err(io::Error::other(error));
            }
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        if self.budget.failed {
            Err(exceeded())
        } else {
            Ok(())
        }
    }
}
impl Write for Budget {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.admit(bytes.len())?;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        if self.failed {
            Err(exceeded())
        } else {
            Ok(())
        }
    }
}
pub(crate) fn to_vec<T: Serialize + ?Sized>(value: &T, limit: usize) -> Result<Vec<u8>, String> {
    let mut writer = BoundedWriter::new(limit);
    serde_json::to_writer(&mut writer, value).map_err(|e| e.to_string())?;
    writer.finish().map_err(|e| e.to_string())
}
/// Check borrowed source data before cloning it into the transfer object.
pub(crate) fn check<T: Serialize + ?Sized>(value: &T, limit: usize) -> Result<(), String> {
    let mut writer = Budget {
        limit,
        written: 0,
        failed: false,
    };
    serde_json::to_writer(&mut writer, value).map_err(|e| e.to_string())?;
    if writer.failed {
        Err(exceeded().to_string())
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    struct Stream<'a>(&'a AtomicUsize);
    impl Serialize for Stream<'_> {
        fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            use serde::ser::SerializeSeq;
            let mut sequence = serializer.serialize_seq(None)?;
            for _ in 0..usize::MAX {
                self.0.fetch_add(1, Ordering::Relaxed);
                sequence.serialize_element("bounded-line")?;
            }
            sequence.end()
        }
    }
    #[test]
    fn successor_writer_accepts_exact_limit_and_round_trips_without_over_reserving() {
        let value = serde_json::json!({"id":7,"value":"private-test"});
        let ordinary = serde_json::to_vec(&value).unwrap();
        assert_eq!(to_vec(&value, ordinary.len()).unwrap(), ordinary);
        assert!(to_vec(&value, ordinary.len() - 1).is_err());
        check(&value, ordinary.len()).unwrap();
        assert!(check(&value, ordinary.len() - 1).is_err());
        let mut writer = BoundedWriter::new(31);
        writer.write_all(&[1; 24]).unwrap();
        writer.write_all(&[2; 7]).unwrap();
        assert!(writer.bytes.capacity() <= 31);
        assert_eq!(writer.bytes.len(), 31);
        assert!(writer.write_all(&[3]).is_err());
        assert_eq!(writer.bytes.len(), 31);
    }
    #[test]
    fn successor_writer_stops_streaming_input_and_counting_before_large_allocation() {
        let visited = AtomicUsize::new(0);
        assert!(to_vec(&Stream(&visited), 64).is_err());
        assert!(visited.load(Ordering::Relaxed) < 10);
        visited.store(0, Ordering::Relaxed);
        assert!(check(&Stream(&visited), 64).is_err());
        assert!(visited.load(Ordering::Relaxed) < 10);
        let mut writer = BoundedWriter::new(8);
        writer.write_all(b"before").unwrap();
        assert!(writer.write_all(b"oversized").is_err());
        assert!(writer.write_all(b"x").is_err());
        assert!(writer.finish().is_err());
    }
    #[tokio::test]
    async fn successor_encoding_error_reopens_original_core_admission() {
        let admission = super::super::Admission::default();
        let failed = async {
            let _freeze = admission.freeze().await?;
            assert!(admission.enter().is_err());
            to_vec(&"oversized", 2)?;
            Ok::<(), String>(())
        }
        .await;
        assert!(failed.is_err());
        assert!(admission.enter().is_ok());
    }
}
