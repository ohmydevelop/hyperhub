//! Pointer-only snapshots for native Hooks. Acquiring a snapshot must not
//! register a thread-local destructor or take the dynamic loader lock.
use std::sync::{Arc, RwLock};

pub(crate) struct Snapshot<T>(RwLock<Option<Arc<T>>>);
impl<T> Snapshot<T> {
    pub(crate) fn empty() -> Self {
        Self::from(None)
    }
    pub(crate) fn from(value: Option<Arc<T>>) -> Self {
        Self(RwLock::new(value))
    }
    pub(crate) fn load_full(&self) -> Option<Arc<T>> {
        self.0.read().expect("Hook snapshot poisoned").clone()
    }
    pub(crate) fn store(&self, value: Option<Arc<T>>) {
        let old = std::mem::replace(&mut *self.0.write().expect("Hook snapshot poisoned"), value);
        // A final destructor can free allocator resources or enter another Hook.
        drop(old);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Weak,
    };

    #[test]
    fn a_retired_snapshot_can_reenter_without_holding_the_publication_lock() {
        struct Value {
            slot: Weak<Snapshot<Value>>,
            destroyed: Arc<AtomicBool>,
        }
        impl Drop for Value {
            fn drop(&mut self) {
                if let Some(slot) = self.slot.upgrade() {
                    assert!(slot.load_full().is_none());
                }
                self.destroyed.store(true, Ordering::Release);
            }
        }
        let slot = Arc::new(Snapshot::empty());
        let destroyed = Arc::new(AtomicBool::new(false));
        slot.store(Some(Arc::new(Value {
            slot: Arc::downgrade(&slot),
            destroyed: destroyed.clone(),
        })));
        let reader = slot.load_full().unwrap();
        slot.store(None);
        assert!(!destroyed.load(Ordering::Acquire));
        drop(reader);
        assert!(destroyed.load(Ordering::Acquire));
        destroyed.store(false, Ordering::Release);
        slot.store(Some(Arc::new(Value {
            slot: Arc::downgrade(&slot),
            destroyed: destroyed.clone(),
        })));
        slot.store(None);
        assert!(destroyed.load(Ordering::Acquire));
    }
}
