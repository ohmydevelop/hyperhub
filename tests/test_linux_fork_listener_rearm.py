"""Run the shipped fork-listener script with deterministic transaction doubles.

The native double implements the Agent's five-argument rearm transaction.  It
checks generation and deadline before apply, after apply, and after commit;
publishes readiness only after the final check; and invokes rollback on every
post-apply refusal.  This keeps the JavaScript ownership tests coupled to the
real target-side commit protocol instead of treating apply as the transaction.
"""
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import unittest


SOURCE = (Path(__file__).resolve().parents[1] /
          'crates/hyperhub-cli/src/platform/linux/frida_core/fork_listener.rs')
NODE = shutil.which('node')

HARNESS = r'''
const assert = require('node:assert/strict');
const MAGIC = 0x48484f4b;
const ERR_BUSY = -7;
const ERR_PROTOCOL = -4;
const events = [];
const late = [];
let marker, abortMarker;
let epoch = 0, armed = false, nativeReady = false;
let nativeGeneration = 17, now = 100;
let guarded = false, transition = false, rearming = false, faultInjected = false;
let flushFailures = 0, abortFlushFailures = 0, abortCallback = false;
let lastRearmStatus = null;
const runtime = {getExportByName: name => name};
const Module = {getGlobalExportByName: name => name};
function send(_) {}
function NativeCallback(callback) { return callback; }
function injectEligibilityFault(phase, expected, deadline) {
  if (!rearming || faultInjected) return;
  if (mode === 'stale-' + phase) {
    nativeGeneration = (expected + 1) >>> 0;
    faultInjected = true;
  } else if (mode === 'deadline-' + phase) {
    now = Number(deadline);
    faultInjected = true;
  }
}
function eligible(phase, expected, deadline) {
  events.push('check-' + phase);
  injectEligibilityFault(phase, expected, deadline);
  return nativeGeneration === expected && now < Number(deadline);
}
function NativeFunction(name, result, args, options) {
  assert.equal(name.endsWith('_rearm_run') || name.endsWith('_abort_run'), false,
    'production script must not call back into its own JavaScript context');
  return (...values) => {
    if (name.endsWith('_is_prepared')) return 0;
    if (name.endsWith('_recovery_pending'))
      return rearming && mode === 'child' ? 1 : 0;
    if (name.endsWith('_generation')) return nativeGeneration;
    if (name.endsWith('_epoch')) return epoch;
    if (name.endsWith('_is_armed')) return armed ? 1 : 0;
    if (name.endsWith('_rearm_begin')) {
      events.push('begin');
      if (transition || (rearming && mode === 'busy')) return ERR_BUSY;
      if (!eligible('pre', values[0] >>> 0, values[1])) return ERR_BUSY;
      transition = true;
      guarded = true;
      return 0;
    }
    if (name.endsWith('_rearm_commit')) {
      if (!transition) return ERR_PROTOCOL;
      if (!eligible('final', values[0] >>> 0, values[1])) return ERR_BUSY;
      armed = true;
      nativeReady = true;
      epoch++;
      events.push('publish');
      transition = false;
      guarded = false;
      events.push('end');
      return 0;
    }
    if (name.endsWith('_rearm_cancel')) {
      if (!transition) return ERR_PROTOCOL;
      transition = false;
      guarded = false;
      events.push('end');
      return 0;
    }
    if (name.endsWith('_abort_begin')) {
      events.push('abort-begin');
      if (guarded && !transition) return ERR_BUSY;
      transition = true;
      guarded = true;
      abortCallback = true;
      return 0;
    }
    if (name.endsWith('_abort_commit')) {
      nativeGeneration = (nativeGeneration + 1) >>> 0;
      armed = false;
      nativeReady = false;
      transition = false;
      abortCallback = false;
      guarded = false;
      events.push('abort-end');
      return 0;
    }
    return 0;
  };
}
const Interceptor = {
  attach(target, callbacks) {
    if (target.endsWith('_mark_armed')) {
      marker = callbacks;
      return {};
    }
    if (target.endsWith('_abort_arm')) {
      abortMarker = callbacks;
      return {};
    }
    if (!callbacks.onEnter) return {};
    events.push('attach');
    if (rearming && mode === 'attach-error') throw new Error('attach failed');
    const entry = {
      active: true,
      detachCount: 0,
      detach() {
        events.push(this === late[0] ? 'detach-old' : 'detach-new');
        if (rearming && mode === 'detach-error' && this === late[0])
          throw new Error('detach failed before mutation');
        if (!this.active) throw new Error('listener detached twice');
        this.active = false;
        this.detachCount++;
      }
    };
    late.push(entry);
    return entry;
  },
  flush() {
    events.push('flush');
    if (abortCallback && abortFlushFailures > 0) {
      abortFlushFailures--;
      throw new Error('abort flush failed');
    }
    if (rearming && mode === 'flush-error' && flushFailures > 0) {
      flushFailures--;
      throw new Error('replacement flush failed');
    }
  }
};
function triggerMark(generation = nativeGeneration, deadline = 1000) {
  const invocation = {};
  const result = {value: ERR_PROTOCOL, replace(value) { this.value = value; }};
  marker.onEnter.call(invocation, [
    {toUInt32: () => generation},
    {toUInt64: () => deadline}
  ]);
  marker.onLeave.call(invocation, result);
  return result.value;
}
function triggerAbort() {
  const invocation = {};
  const result = {value: null, replace(value) { this.value = value; }};
  abortMarker.onEnter.call(invocation);
  abortMarker.onLeave.call(invocation, result);
  return result.value;
}
'''

ASSERTIONS = r'''
assert.ok(marker);
assert.ok(abortMarker);
assert.equal(triggerMark(), 0, 'initial transaction must commit');
assert.equal(epoch, 1);
assert.equal(armed, true);
assert.equal(nativeReady, true);
assert.equal(late.length, 1);
const previous = late[0];
events.length = 0;
rearming = true;
flushFailures = mode === 'flush-error' ? 1 : 0;

if (mode === 'abort-flush-retry') {
  abortFlushFailures = 1;
  assert.equal(triggerAbort(), -1, 'failed flush must not acknowledge retirement');
  assert.deepEqual(events, ['abort-begin', 'detach-old', 'flush']);
  assert.equal(previous.detachCount, 1);
  assert.equal(previous.active, false);
  events.length = 0;
  assert.equal(triggerAbort(), 0, 'retry must finish the pending flush');
  assert.deepEqual(events, ['abort-begin', 'flush', 'abort-end']);
  assert.equal(previous.detachCount, 1, 'retry must never detach a handle twice');
  assert.equal(late.filter(entry => entry.active).length, 0);
  assert.equal(epoch, 1);
  assert.equal(armed, false);
  assert.equal(nativeReady, false);
} else {
  const status = triggerMark();
  assert.equal(guarded, false, 'native scope must release every acquired guard');
  const eligibilityFailure = mode.startsWith('stale-') || mode.startsWith('deadline-');
  if (mode === 'success' || mode === 'child') assert.equal(status, 0);
  else assert.notEqual(status, 0, 'failed transaction must not report success');

  if (mode === 'busy') {
    assert.deepEqual(events, ['begin'], 'busy must refuse before acquiring the gate');
  } else if (mode === 'success') {
    assert.deepEqual(events, ['begin', 'check-pre', 'attach', 'flush',
      'detach-old', 'flush', 'check-final', 'publish', 'end']);
  } else if (mode === 'child') {
    assert.deepEqual(events, ['begin', 'check-pre', 'check-final', 'publish', 'end']);
  } else if (mode === 'attach-error') {
    assert.deepEqual(events, ['begin', 'check-pre', 'attach', 'end']);
  } else if (mode === 'flush-error') {
    assert.deepEqual(events, ['begin', 'check-pre', 'attach', 'flush',
      'detach-new', 'flush', 'end']);
  } else if (mode === 'detach-error') {
    assert.deepEqual(events, ['begin', 'check-pre', 'attach', 'flush', 'detach-old',
      'detach-new', 'flush', 'end']);
  } else if (mode.endsWith('-pre') && eligibilityFailure) {
    assert.deepEqual(events, ['begin', 'check-pre']);
  } else if (mode.endsWith('-final') && eligibilityFailure) {
    assert.deepEqual(events, ['begin', 'check-pre', 'attach', 'flush', 'detach-old',
      'flush', 'check-final', 'detach-new', 'attach', 'flush', 'end']);
  } else {
    assert.fail('unasserted mode: ' + mode);
  }

  if (mode === 'success') {
    assert.equal(previous.active, false);
    assert.equal(late.filter(entry => entry.active).length, 1);
    assert.equal(epoch, 2);
  } else if (mode === 'child') {
    assert.equal(previous.active, true);
    assert.equal(late.length, 1, 'child recovery must reuse the inherited listener');
    assert.equal(epoch, 2);
  } else {
    assert.equal(late.filter(entry => entry.active).length, 1,
      'failed transaction must preserve one semantic late listener');
    assert.equal(epoch, 1, 'failed transaction must not publish an epoch');
  }
  assert.equal(armed, true, 'failed rearm must preserve the prior committed generation');
  assert.equal(nativeReady, true);
}
'''


@unittest.skipUnless(NODE, 'Node.js is required to execute the shipped Frida script')
class ForkListenerRearmTests(unittest.TestCase):
    def run_case(self, mode):
        match = re.search(r'const PREPARE: &str = r#"(.*?)"#;', SOURCE.read_text(), re.S)
        self.assertIsNotNone(match)
        script = ('const mode = ' + json.dumps(mode) + ';\n' + HARNESS +
                  match.group(1) + ASSERTIONS)
        result = subprocess.run([NODE, '-'], input=script, text=True,
                                capture_output=True, timeout=10,
                                env={'PATH': os.defpath})
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_busy_refuses_before_mutation(self):
        self.run_case('busy')

    def test_replacement_publishes_only_after_apply_commit_and_final_check(self):
        self.run_case('success')

    def test_attach_failure_preserves_old_and_releases_guard(self):
        self.run_case('attach-error')

    def test_flush_failure_removes_new_and_preserves_old(self):
        self.run_case('flush-error')

    def test_commit_failure_rolls_back_new_and_preserves_old(self):
        self.run_case('detach-error')

    def test_inherited_child_transaction_reuses_listener(self):
        self.run_case('child')

    def test_stale_generation_is_rejected_at_every_commit_check(self):
        for phase in ('pre', 'final'):
            with self.subTest(phase=phase):
                self.run_case('stale-' + phase)

    def test_deadline_is_rejected_at_every_commit_check(self):
        for phase in ('pre', 'final'):
            with self.subTest(phase=phase):
                self.run_case('deadline-' + phase)

    def test_abort_flush_retry_never_detaches_same_handle_twice(self):
        self.run_case('abort-flush-retry')

    def test_unowned_abort_uses_native_transaction_only_after_no_owner_check(self):
        match = re.search(
            r'const ABORT_UNOWNED: &str = r#"(.*?)"#;', SOURCE.read_text(), re.S
        )
        self.assertIsNotNone(match)
        assertions = r'''
assert.equal(nativeGeneration, 18);
assert.equal(armed, false);
assert.equal(nativeReady, false);
assert.deepEqual(events, ['abort-begin', 'abort-end']);
'''
        script = ('const mode = "unowned-abort";\n' + HARNESS +
                  'armed = true; nativeReady = true;\n' + match.group(1) + assertions)
        result = subprocess.run([NODE, '-'], input=script, text=True,
                                capture_output=True, timeout=10,
                                env={'PATH': os.defpath})
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
