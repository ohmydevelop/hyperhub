//! Type-safe, immutable callback chains used by the injected Agent hook runtime.

use std::fmt;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum HookFailureMode {
    FailOpen,
    FailClosed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CallbackCategory {
    Control,
    Transform,
    Observe,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HookError {
    message: String,
}

impl HookError {
    pub(crate) fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for HookError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

pub(crate) enum HookDecision<R> {
    Continue,
    Return(R),
    Deny(R),
}

pub(crate) type HookCallbackResult<R> = Result<HookDecision<R>, HookError>;

type BeforeCallback<C, R> = dyn Fn(&mut C) -> HookCallbackResult<R> + Send + Sync + 'static;
type AfterCallback<C, R> = dyn Fn(&mut C, &mut R) -> HookCallbackResult<R> + Send + Sync + 'static;
type FailureModeProvider = dyn Fn() -> HookFailureMode + Send + Sync + 'static;

struct RegisteredBeforeCallback<C, R> {
    plugin_id: &'static str,
    category: CallbackCategory,
    failure_mode: HookFailureMode,
    failure_mode_provider: Option<Arc<FailureModeProvider>>,
    failures: AtomicU64,
    callback: Arc<BeforeCallback<C, R>>,
}

struct RegisteredAfterCallback<C, R> {
    plugin_id: &'static str,
    category: CallbackCategory,
    failure_mode: HookFailureMode,
    failure_mode_provider: Option<Arc<FailureModeProvider>>,
    failures: AtomicU64,
    callback: Arc<AfterCallback<C, R>>,
}

pub(crate) struct HookPointBuilder<C, R> {
    name: &'static str,
    failure_mode: HookFailureMode,
    before: Vec<RegisteredBeforeCallback<C, R>>,
    after: Vec<RegisteredAfterCallback<C, R>>,
}

impl<C, R> HookPointBuilder<C, R> {
    pub(crate) fn new(name: &'static str, failure_mode: HookFailureMode) -> Self {
        Self {
            name,
            failure_mode,
            before: Vec::new(),
            after: Vec::new(),
        }
    }

    pub(crate) fn before<F>(
        &mut self,
        plugin_id: &'static str,
        category: CallbackCategory,
        callback: F,
    ) where
        F: Fn(&mut C) -> HookCallbackResult<R> + Send + Sync + 'static,
    {
        self.before_with_failure_mode(plugin_id, category, self.failure_mode, callback);
    }

    pub(crate) fn before_with_failure_mode<F>(
        &mut self,
        plugin_id: &'static str,
        category: CallbackCategory,
        failure_mode: HookFailureMode,
        callback: F,
    ) where
        F: Fn(&mut C) -> HookCallbackResult<R> + Send + Sync + 'static,
    {
        self.before.push(RegisteredBeforeCallback {
            plugin_id,
            category,
            failure_mode,
            failure_mode_provider: None,
            failures: AtomicU64::new(0),
            callback: Arc::new(callback),
        });
    }

    /// 仅 Gum Agent 构建使用；普通（非 gum-agent）构建中该帮助方法无调用方。
    #[cfg(feature = "gum-agent")]
    pub(crate) fn before_with_failure_mode_provider<F, P>(
        &mut self,
        plugin_id: &'static str,
        category: CallbackCategory,
        failure_mode: HookFailureMode,
        provider: P,
        callback: F,
    ) where
        F: Fn(&mut C) -> HookCallbackResult<R> + Send + Sync + 'static,
        P: Fn() -> HookFailureMode + Send + Sync + 'static,
    {
        self.before.push(RegisteredBeforeCallback {
            plugin_id,
            category,
            failure_mode,
            failure_mode_provider: Some(Arc::new(provider)),
            failures: AtomicU64::new(0),
            callback: Arc::new(callback),
        });
    }

    pub(crate) fn after<F>(
        &mut self,
        plugin_id: &'static str,
        category: CallbackCategory,
        callback: F,
    ) where
        F: Fn(&mut C, &mut R) -> HookCallbackResult<R> + Send + Sync + 'static,
    {
        self.after_with_failure_mode(plugin_id, category, self.failure_mode, callback);
    }

    pub(crate) fn after_with_failure_mode<F>(
        &mut self,
        plugin_id: &'static str,
        category: CallbackCategory,
        failure_mode: HookFailureMode,
        callback: F,
    ) where
        F: Fn(&mut C, &mut R) -> HookCallbackResult<R> + Send + Sync + 'static,
    {
        self.after.push(RegisteredAfterCallback {
            plugin_id,
            category,
            failure_mode,
            failure_mode_provider: None,
            failures: AtomicU64::new(0),
            callback: Arc::new(callback),
        });
    }

    pub(crate) fn freeze(self) -> HookPoint<C, R> {
        HookPoint {
            name: self.name,
            failure_mode: self.failure_mode,
            before: self.before.into_boxed_slice(),
            after: self.after.into_boxed_slice(),
        }
    }
}

impl<C, R> RegisteredBeforeCallback<C, R> {
    fn failure_mode(&self) -> HookFailureMode {
        self.failure_mode_provider
            .as_ref()
            .map(|provider| provider())
            .unwrap_or(self.failure_mode)
    }
}

impl<C, R> RegisteredAfterCallback<C, R> {
    fn failure_mode(&self) -> HookFailureMode {
        self.failure_mode_provider
            .as_ref()
            .map(|provider| provider())
            .unwrap_or(self.failure_mode)
    }
}

pub(crate) struct HookPoint<C, R> {
    name: &'static str,
    failure_mode: HookFailureMode,
    before: Box<[RegisteredBeforeCallback<C, R>]>,
    after: Box<[RegisteredAfterCallback<C, R>]>,
}

impl<C, R> HookPoint<C, R> {
    pub(crate) fn dispatch<F, D>(&self, context: &mut C, original: F, denied: D) -> R
    where
        F: FnOnce(&mut C) -> R,
        D: Fn(&mut C, Option<&R>, &HookError) -> R,
    {
        if let Some(result) = self.run_before(context, &denied) {
            return result;
        }
        let mut result = original(context);
        self.run_after(context, &mut result, &denied);
        result
    }

    pub(crate) fn manifest(&self) -> HookPointManifest {
        HookPointManifest {
            name: self.name,
            failure_mode: self.failure_mode,
            before: self.before.iter().map(CallbackManifest::from).collect(),
            after: self.after.iter().map(CallbackManifest::from).collect(),
        }
    }

    fn run_before<D>(&self, context: &mut C, denied: &D) -> Option<R>
    where
        D: Fn(&mut C, Option<&R>, &HookError) -> R,
    {
        for callback in &self.before {
            let outcome = catch_unwind(AssertUnwindSafe(|| (callback.callback)(context)));
            match outcome {
                Ok(Ok(HookDecision::Continue)) => {}
                Ok(Ok(HookDecision::Return(result) | HookDecision::Deny(result))) => {
                    return Some(result);
                }
                Ok(Err(error)) => {
                    callback.failures.fetch_add(1, Ordering::Relaxed);
                    report_failure(self.name, callback.plugin_id, &error);
                    if callback.failure_mode() == HookFailureMode::FailClosed {
                        return Some(denied(context, None, &error));
                    }
                }
                Err(_) => {
                    callback.failures.fetch_add(1, Ordering::Relaxed);
                    let error = HookError::new("callback panicked");
                    report_failure(self.name, callback.plugin_id, &error);
                    if callback.failure_mode() == HookFailureMode::FailClosed {
                        return Some(denied(context, None, &error));
                    }
                }
            }
        }
        None
    }

    fn run_after<D>(&self, context: &mut C, result: &mut R, denied: &D)
    where
        D: Fn(&mut C, Option<&R>, &HookError) -> R,
    {
        for callback in &self.after {
            let outcome = catch_unwind(AssertUnwindSafe(|| (callback.callback)(context, result)));
            match outcome {
                Ok(Ok(HookDecision::Continue)) => {}
                Ok(Ok(HookDecision::Return(replacement) | HookDecision::Deny(replacement))) => {
                    *result = replacement;
                }
                Ok(Err(error)) => {
                    callback.failures.fetch_add(1, Ordering::Relaxed);
                    report_failure(self.name, callback.plugin_id, &error);
                    if callback.failure_mode() == HookFailureMode::FailClosed {
                        *result = denied(context, Some(result), &error);
                        return;
                    }
                }
                Err(_) => {
                    callback.failures.fetch_add(1, Ordering::Relaxed);
                    let error = HookError::new("callback panicked");
                    report_failure(self.name, callback.plugin_id, &error);
                    if callback.failure_mode() == HookFailureMode::FailClosed {
                        *result = denied(context, Some(result), &error);
                        return;
                    }
                }
            }
        }
    }
}

fn report_failure(hook: &str, plugin: &str, error: &HookError) {
    if std::env::var_os("HYPERHUB_AGENT_DEBUG").is_some() {
        eprintln!("hyperhub-agent: hook={hook} plugin={plugin} error={error}");
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CallbackManifest {
    pub(crate) plugin_id: &'static str,
    pub(crate) category: CallbackCategory,
    pub(crate) failure_mode: HookFailureMode,
    pub(crate) failures: u64,
}

impl<C, R> From<&RegisteredBeforeCallback<C, R>> for CallbackManifest {
    fn from(callback: &RegisteredBeforeCallback<C, R>) -> Self {
        Self {
            plugin_id: callback.plugin_id,
            category: callback.category,
            failure_mode: callback.failure_mode(),
            failures: callback.failures.load(Ordering::Relaxed),
        }
    }
}

impl<C, R> From<&RegisteredAfterCallback<C, R>> for CallbackManifest {
    fn from(callback: &RegisteredAfterCallback<C, R>) -> Self {
        Self {
            plugin_id: callback.plugin_id,
            category: callback.category,
            failure_mode: callback.failure_mode(),
            failures: callback.failures.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HookPointManifest {
    pub(crate) name: &'static str,
    pub(crate) failure_mode: HookFailureMode,
    pub(crate) before: Vec<CallbackManifest>,
    pub(crate) after: Vec<CallbackManifest>,
}

#[cfg_attr(test, allow(dead_code))]
pub(crate) trait AgentHookPlugin: Send + Sync {
    fn id(&self) -> &'static str;

    fn initialize(&self) -> Result<(), HookError> {
        Ok(())
    }

    fn shutdown(&self) {}
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    #[derive(Default)]
    struct Context {
        value: i32,
        order: Vec<&'static str>,
    }

    #[test]
    fn callbacks_run_in_registration_order_and_share_mutations() {
        let mut builder = HookPointBuilder::new("test", HookFailureMode::FailClosed);
        builder.before(
            "first",
            CallbackCategory::Transform,
            |context: &mut Context| {
                context.order.push("before-first");
                context.value += 1;
                Ok(HookDecision::Continue)
            },
        );
        builder.before(
            "second",
            CallbackCategory::Transform,
            |context: &mut Context| {
                context.order.push("before-second");
                context.value *= 2;
                Ok(HookDecision::Continue)
            },
        );
        builder.after(
            "first",
            CallbackCategory::Observe,
            |context: &mut Context, _result| {
                context.order.push("after-first");
                context.value += 3;
                Ok(HookDecision::Continue)
            },
        );
        builder.after(
            "second",
            CallbackCategory::Transform,
            |context: &mut Context, result| {
                context.order.push("after-second");
                assert_eq!(*result, 2);
                Ok(HookDecision::Return(context.value * 10))
            },
        );
        let point = builder.freeze();
        let mut context = Context::default();
        let result = point.dispatch(
            &mut context,
            |context| {
                context.order.push("original");
                context.value
            },
            |_, _, _| -1,
        );
        assert_eq!(result, 50);
        assert_eq!(
            context.order,
            [
                "before-first",
                "before-second",
                "original",
                "after-first",
                "after-second"
            ]
        );
    }

    #[test]
    fn after_callbacks_all_run_and_later_results_override_earlier_results() {
        let mut builder = HookPointBuilder::new("test", HookFailureMode::FailClosed);
        builder.after(
            "first",
            CallbackCategory::Transform,
            |context: &mut Context, result| {
                context.order.push("first");
                assert_eq!(*result, 1);
                Ok(HookDecision::Return(2))
            },
        );
        builder.after(
            "second",
            CallbackCategory::Transform,
            |context: &mut Context, result| {
                context.order.push("second");
                assert_eq!(*result, 2);
                *result = 3;
                Ok(HookDecision::Continue)
            },
        );
        builder.after(
            "third",
            CallbackCategory::Transform,
            |context: &mut Context, result| {
                context.order.push("third");
                assert_eq!(*result, 3);
                Ok(HookDecision::Deny(4))
            },
        );
        let point = builder.freeze();
        let mut context = Context::default();

        let result = point.dispatch(&mut context, |_| 1, |_, _, _| -1);

        assert_eq!(result, 4);
        assert_eq!(context.order, ["first", "second", "third"]);
    }

    #[test]
    fn before_short_circuit_skips_remaining_callbacks_and_original() {
        let called = Arc::new(Mutex::new(Vec::new()));
        let mut builder = HookPointBuilder::new("test", HookFailureMode::FailClosed);
        let first = called.clone();
        builder.before("first", CallbackCategory::Control, move |_| {
            first.lock().unwrap().push("first");
            Ok(HookDecision::Return(7))
        });
        let second = called.clone();
        builder.before("second", CallbackCategory::Control, move |_| {
            second.lock().unwrap().push("second");
            Ok(HookDecision::Continue)
        });
        let point = builder.freeze();
        let mut context = Context::default();
        let result = point.dispatch(
            &mut context,
            |_| panic!("original must not run"),
            |_, _, _| -1,
        );
        assert_eq!(result, 7);
        assert_eq!(*called.lock().unwrap(), ["first"]);
    }

    #[test]
    fn failure_modes_handle_errors_and_panics() {
        let mut open = HookPointBuilder::new("open", HookFailureMode::FailOpen);
        open.before("error", CallbackCategory::Observe, |_| {
            Err(HookError::new("failure"))
        });
        open.before("panic", CallbackCategory::Observe, |_| panic!("boom"));
        let open = open.freeze();
        let mut context = Context::default();
        assert_eq!(open.dispatch(&mut context, |_| 9, |_, _, _| -1), 9);
        assert_eq!(open.manifest().before[0].failures, 1);
        assert_eq!(open.manifest().before[1].failures, 1);

        let mut closed = HookPointBuilder::new("closed", HookFailureMode::FailClosed);
        closed.before("error", CallbackCategory::Control, |_| {
            Err(HookError::new("failure"))
        });
        let closed = closed.freeze();
        assert_eq!(closed.dispatch(&mut context, |_| 9, |_, _, _| -1), -1);
    }

    #[test]
    fn after_fail_open_continues_but_fail_closed_stops_the_chain() {
        let mut open = HookPointBuilder::new("open", HookFailureMode::FailOpen);
        open.after("error", CallbackCategory::Observe, |_, _| {
            Err(HookError::new("failure"))
        });
        open.after(
            "next",
            CallbackCategory::Transform,
            |context: &mut Context, result| {
                context.order.push("next");
                Ok(HookDecision::Return(*result + 1))
            },
        );
        let open = open.freeze();
        let mut context = Context::default();
        assert_eq!(open.dispatch(&mut context, |_| 9, |_, _, _| -1), 10);
        assert_eq!(context.order, ["next"]);

        let mut closed = HookPointBuilder::new("closed", HookFailureMode::FailClosed);
        closed.after("panic", CallbackCategory::Control, |_, _| panic!("boom"));
        closed.after(
            "skipped",
            CallbackCategory::Observe,
            |context: &mut Context, _| {
                context.order.push("skipped");
                Ok(HookDecision::Continue)
            },
        );
        let closed = closed.freeze();
        let mut context = Context::default();
        assert_eq!(
            closed.dispatch(
                &mut context,
                |_| 9,
                |_, current, _| {
                    assert_eq!(current.copied(), Some(9));
                    -1
                }
            ),
            -1
        );
        assert!(context.order.is_empty());
    }

    #[test]
    fn callback_failure_mode_can_override_the_hook_default() {
        let mut builder = HookPointBuilder::new("override", HookFailureMode::FailClosed);
        builder.before_with_failure_mode(
            "firewall",
            CallbackCategory::Control,
            HookFailureMode::FailOpen,
            |_| Err(HookError::new("failure")),
        );
        let point = builder.freeze();
        let mut context = Context::default();
        assert_eq!(point.dispatch(&mut context, |_| 7, |_, _, _| -1), 7);
        assert_eq!(
            point.manifest().before[0].failure_mode,
            HookFailureMode::FailOpen
        );

        let mut builder = HookPointBuilder::new("after-override", HookFailureMode::FailOpen);
        builder.after_with_failure_mode(
            "firewall",
            CallbackCategory::Control,
            HookFailureMode::FailClosed,
            |_, _| Err(HookError::new("failure")),
        );
        let point = builder.freeze();
        assert_eq!(point.dispatch(&mut context, |_| 7, |_, _, _| -1), -1);
        assert_eq!(
            point.manifest().after[0].failure_mode,
            HookFailureMode::FailClosed
        );
    }

    #[test]
    fn frozen_manifest_preserves_registration_metadata() {
        let mut builder: HookPointBuilder<Context, i32> =
            HookPointBuilder::new("manifest", HookFailureMode::FailOpen);
        builder.before("observer", CallbackCategory::Observe, |_| {
            Ok(HookDecision::Continue)
        });
        builder.after("transform", CallbackCategory::Transform, |_, _| {
            Ok(HookDecision::Continue)
        });
        let manifest = builder.freeze().manifest();
        assert_eq!(manifest.name, "manifest");
        assert_eq!(manifest.failure_mode, HookFailureMode::FailOpen);
        assert_eq!(manifest.before[0].plugin_id, "observer");
        assert_eq!(manifest.before[0].failure_mode, HookFailureMode::FailOpen);
        assert_eq!(manifest.after[0].plugin_id, "transform");
    }
}
