#!/usr/bin/env python3
"""Raw keyboard, terminal modes and VT output of a disposable target application.

Build the source fixture separately; this driver never starts Cargo. Approvals
use a different PTY/ConPTY and only a private dummy administrator password.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import socket
import subprocess
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parents[1]


class PosixConsole:
    def __init__(self, arguments, environment):
        import pty
        self.pid, self.master = pty.fork()
        if self.pid == 0:
            try:
                os.execve(str(arguments[0]), [str(arg) for arg in arguments], environment)
            finally:
                os._exit(127)
        self.data = bytearray()
        self.lock = threading.Lock()
        self.code = None
        self.reader = threading.Thread(target=self._read, daemon=True)
        self.reader.start()

    def _read(self):
        while True:
            try:
                data = os.read(self.master, 8192)
            except OSError:
                return
            if not data:
                return
            with self.lock:
                self.data.extend(data)

    def transcript(self):
        with self.lock:
            return bytes(self.data)

    def send(self, text):
        data = text.encode()
        while data:
            written = os.write(self.master, data)
            if not written:
                raise OSError('zero terminal input write')
            data = data[written:]

    def wait_for(self, needle, timeout=60):
        deadline = time.monotonic() + timeout
        while needle not in self.transcript():
            if time.monotonic() >= deadline:
                raise TimeoutError('console prompt was not produced')
            time.sleep(.01)

    def wait(self, timeout=60):
        deadline = time.monotonic() + timeout
        while self.code is None:
            pid, status = os.waitpid(self.pid, os.WNOHANG)
            if pid:
                self.code = os.waitstatus_to_exitcode(status)
                break
            if time.monotonic() >= deadline:
                raise TimeoutError('owned console child did not exit')
            time.sleep(.01)
        return self.code

    def close(self):
        if self.code is None:
            try:
                self.wait(.05)
            except TimeoutError:
                # This PID is our unreaped child, so it cannot be reused.
                import signal
                os.kill(self.pid, signal.SIGTERM)
                self.wait(5)
        os.close(self.master)
        self.reader.join(timeout=3)


def console(arguments, environment):
    if os.name == 'nt':
        from windows_conpty import Console
        return Console(arguments, environment)
    return PosixConsole(arguments, environment)


class FixturePin:
    """Pin only the exact source fixture, including a run launcher's child."""
    def __init__(self, pid, image):
        self.handle = None
        if os.name == 'nt':
            import ctypes
            from ctypes import wintypes as w
            self.ctypes = ctypes
            self.kernel = ctypes.WinDLL('kernel32', use_last_error=True)
            kernel = self.kernel
            kernel.OpenProcess.argtypes = [w.DWORD, w.BOOL, w.DWORD]
            kernel.OpenProcess.restype = w.HANDLE
            kernel.QueryFullProcessImageNameW.argtypes = [w.HANDLE, w.DWORD, w.LPWSTR, ctypes.POINTER(w.DWORD)]
            kernel.QueryFullProcessImageNameW.restype = w.BOOL
            kernel.WaitForSingleObject.argtypes = [w.HANDLE, w.DWORD]
            kernel.WaitForSingleObject.restype = w.DWORD
            kernel.TerminateProcess.argtypes = [w.HANDLE, w.UINT]
            kernel.TerminateProcess.restype = w.BOOL
            kernel.CloseHandle.argtypes = [w.HANDLE]
            kernel.CloseHandle.restype = w.BOOL
            handle = kernel.OpenProcess(0x1000 | 0x100000 | 1, False, pid)
            if not handle:
                raise ctypes.WinError(ctypes.get_last_error())
            try:
                path = ctypes.create_unicode_buffer(32768)
                size = w.DWORD(len(path))
                if not kernel.QueryFullProcessImageNameW(handle, 0, path, ctypes.byref(size)):
                    raise ctypes.WinError(ctypes.get_last_error())
                assert os.path.samefile(path.value, image), 'ready PID is not the fixture'
                self.handle = handle
            finally:
                if self.handle is None:
                    kernel.CloseHandle(handle)
        else:
            handle = os.pidfd_open(pid)
            try:
                assert Path(f'/proc/{pid}/exe').resolve() == image, 'ready PID is not the fixture'
                self.handle = handle
            finally:
                if self.handle is None:
                    os.close(handle)

    def close(self):
        if self.handle is None:
            return
        if os.name == 'nt':
            if self.kernel.WaitForSingleObject(self.handle, 1000) == 0x102:
                if not self.kernel.TerminateProcess(self.handle, 70):
                    raise self.ctypes.WinError(self.ctypes.get_last_error())
                assert self.kernel.WaitForSingleObject(self.handle, 5000) == 0
            self.kernel.CloseHandle(self.handle)
        else:
            import select
            import signal
            if not select.select([self.handle], [], [], 1)[0]:
                signal.pidfd_send_signal(self.handle, signal.SIGTERM)
                if not select.select([self.handle], [], [], 5)[0]:
                    signal.pidfd_send_signal(self.handle, signal.SIGKILL)
            os.close(self.handle)
        self.handle = None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--hyperhub', type=Path)
    parser.add_argument('--fixture', type=Path, required=True)
    parser.add_argument('--backend', choices=['ptrace', 'gum'], default='ptrace')
    parser.add_argument('--origin', choices=['attach', 'run'], default='attach')
    parser.add_argument('--native-only', action='store_true')
    parser.add_argument('--cycles', type=int, default=2)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.cycles < 1 or (not args.native_only and args.hyperhub is None):
        parser.error('positive cycles and --hyperhub are required for managed tests')
    output = args.output.resolve()
    output.mkdir(parents=True, mode=0o700, exist_ok=False)
    binary = args.hyperhub.resolve() if args.hyperhub else None
    fixture = args.fixture.resolve()
    inputs = {
        'driver_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        'fixture_sha256': hashlib.sha256(fixture.read_bytes()).hexdigest(),
        'declared_fixture_source_sha256': hashlib.sha256(
            (ROOT/'tests/fixtures/dynamic-attach-terminal/src/main.rs').read_bytes()).hexdigest(),
        'fixture_lock_sha256': hashlib.sha256(
            (ROOT/'tests/fixtures/dynamic-attach-terminal/Cargo.lock').read_bytes()).hexdigest(),
        'declared_fixture_manifest_sha256': hashlib.sha256(
            (ROOT/'tests/fixtures/dynamic-attach-terminal/Cargo.toml').read_bytes()).hexdigest(),
    }
    if binary:
        inputs['hyperhub_sha256'] = hashlib.sha256(binary.read_bytes()).hexdigest()
    temporary = tempfile.TemporaryDirectory(prefix='hh-terminal-')
    private = Path(temporary.name)
    if os.name == 'nt':
        from windows_test_env import isolated_environment
        env = isolated_environment(os.environ, private)
    else:
        env = {key: value for key, value in os.environ.items()
               if key in ['PATH', 'LANG', 'LC_ALL', 'LC_CTYPE', 'TERM', 'TZ']}
        env.update(HOME=str(private/'home'), HYPERHUB_HOME=str(private/'instance'),
                   TMPDIR=str(private/'tmp'), XDG_RUNTIME_DIR=str(private/'runtime'))
    for key in ['HOME', 'USERPROFILE', 'HYPERHUB_HOME', 'TMP', 'TEMP', 'TMPDIR',
                'XDG_RUNTIME_DIR', 'APPDATA', 'LOCALAPPDATA']:
        if key in env:
            Path(env[key]).mkdir(parents=True, mode=0o700, exist_ok=True)
    password = private/'password'
    password.write_text('disposable-terminal-password\n')
    password.chmod(0o600)
    secret = private/'terminal-protected.txt'
    secret.write_text('S\n')
    secret.chmod(0o600)
    commands, phases = [], []
    target = None
    target_pin = None
    pump = None
    stop = threading.Event()
    expected = bytearray()
    expected_lock = threading.Lock()
    pump_errors = []
    sequence = 'hj\x1b[A\x1b[B\x7f\x03'
    info = None

    def cli(arguments, expected_code=0):
        result = subprocess.run([str(binary), *arguments], env=env,
                                capture_output=True, timeout=90)
        commands.append({'args': arguments, 'exit_code': result.returncode})
        (output/f'cli-{len(commands)}.stdout').write_bytes(result.stdout)
        (output/f'cli-{len(commands)}.stderr').write_bytes(result.stderr)
        assert result.returncode == expected_code, (arguments, result.returncode, result.stderr)
        return result.stdout

    def approve(request_id):
        prompt = console([binary, 'approve', request_id, '--admin-password-file', password], env)
        try:
            prompt.wait_for(b'Approve [y], reject [n], or quit [q]:')
            prompt.send('y\n')
            assert prompt.wait() == 0, prompt.transcript().decode(errors='replace')
            data = prompt.transcript()
            (output/f'approval-{request_id}.log').write_bytes(data)
            for line in data.decode(errors='replace').splitlines():
                try:
                    value = json.loads(re.sub(r'\x1b\[[0-?]*[ -/]*[@-~]', '', line).strip())
                except json.JSONDecodeError:
                    continue
                if isinstance(value, dict) and 'attachment_id' in value:
                    return value
            raise AssertionError('approval omitted actual attachment identity')
        finally:
            prompt.close()

    def exchange(command):
        with socket.create_connection(('127.0.0.1', info['port']), timeout=5) as connection:
            connection.sendall((command+'\n').encode())
            return json.loads(connection.makefile('rb').readline())

    def snapshot(name):
        result = exchange('snapshot')
        assert result['pid'] == info['pid']
        assert all(result[key] for key in ['terminal', 'mode_preserved', 'cwd_preserved', 'home_preserved']), result
        with expected_lock:
            sent = bytes(expected)
        assert sent.startswith(bytes.fromhex(result['received_hex'])), result
        marker = secrets.token_hex(16)
        assert exchange('render '+marker)['rendered'] == marker
        target.wait_for(('TARGET-RENDER:'+marker).encode(), timeout=5)
        result['render_marker_observed'] = True
        phases.append({'phase': name, 'observed_unix_ns': time.time_ns(), **result})

    def file_access(allowed):
        result = exchange('read')
        assert result['read_allowed'] is allowed, result
        if not allowed:
            assert result['error'] == (5 if os.name == 'nt' else 13), result

    def wait_phase(attachment_id, allowed):
        deadline = time.monotonic()+30
        while time.monotonic() < deadline:
            status = json.loads(cli(['status', '--json']))
            record = next(row for row in status['attachments'] if row['spec']['id'] == attachment_id)
            if record['phase'] in allowed:
                return record
            assert record['phase'] not in ['failed', 'degraded', 'cleanup_pending'], record
            time.sleep(.02)
        raise TimeoutError('attachment phase did not converge')

    def pump_input():
        while not stop.is_set():
            try:
                with expected_lock:
                    expected.extend(sequence.encode())
                # Never hold the sample lock over a potentially blocked write.
                # A failed/unfinished write invalidates the run below.
                target.send(sequence)
            except BaseException as error:
                pump_errors.append(repr(error))
                return
            stop.wait(.05)

    try:
        if not args.native_only:
            assert b'attach <pid>' in cli(['--help'])
            with socket.socket() as reserved:
                reserved.bind(('127.0.0.1', 0))
                port = reserved.getsockname()[1]
            config = private/'config.toml'
            pattern = json.dumps('^'+re.escape(str(secret))+'$')
            config.write_text(f'''schema_version = 2
environment_variables = []
[gateway]
mode = "enforce"
debug = false
[gateway.listener]
socks_address = "127.0.0.1:{port}"
pending_session_ttl_seconds = 60
[gateway.audit.settings]
retention_days = 1
connections = true
header_allowlist = []
[gateway.routing.default]
enabled = true
[gateway.routing.default.decision]
action = "allow"
[gateway.trust]
tls_certificates = []
ssh_host_keys = []
[sandbox.network]
enabled = false
default_action = "allow"
error_action = "allow"
rules = []
[sandbox.process]
enabled = false
default_action = "allow"
error_action = "allow"
rules = []
[sandbox.file]
enabled = true
default_action = "allow"
error_action = "deny"
[[sandbox.file.rules]]
id = "deny-terminal-fixture-file"
enabled = true
priority = 100
action = "deny"
operations = ["read"]
[[sandbox.file.rules.patterns]]
enabled = true
pattern = {pattern}
''')
            cli(['import', str(config), '--admin-password-file', str(password)])
            cli(['start', '--admin-password-file', str(password)])
        ready = private/'target-ready.json'
        arguments = [fixture, ready, secret]
        if not args.native_only and args.origin == 'run':
            arguments = [binary, 'run', '--backend', args.backend, '--', *arguments]
        target = console(arguments, env)
        deadline = time.monotonic()+40
        while not ready.exists():
            if time.monotonic() >= deadline:
                raise TimeoutError('terminal fixture did not become ready')
            time.sleep(.01)
        info = json.loads(ready.read_text())
        target_pin = FixturePin(info['pid'], fixture)
        pump = threading.Thread(target=pump_input, daemon=True)
        pump.start()
        snapshot('initial_raw_terminal')
        if args.native_only:
            file_access(True)
            time.sleep(.15)
            snapshot('unmanaged_raw_keyboard')
        else:
            for cycle in range(args.cycles):
                if args.origin == 'run' and cycle == 0:
                    records = json.loads(cli(['status', '--json']))['attachments']
                    attachment_id = next(row['spec']['id'] for row in records
                                         if row['spec']['target']['pid'] == info['supervisor_pid'])
                else:
                    file_access(True)
                    scope = 'process' if os.name != 'nt' and args.backend == 'gum' else 'tree'
                    proposal = json.loads(cli(['attach', str(info['pid']), '--scope', scope,
                                              '--backend', args.backend]))
                    attachment_id = approve(proposal['request_id'])['attachment_id']
                wait_phase(attachment_id, ['active'])
                file_access(False)
                snapshot(f'active-{cycle}')
                if cycle == 0:
                    # The raw target continues to receive keyboard bytes during
                    # service restart. No extra administrator prompt is needed.
                    cli(['restart'])
                    file_access(False)
                    snapshot('active_after_serve_restart')
                removal = json.loads(cli(['detach', attachment_id]))
                attachment_id = approve(removal['request_id'])['attachment_id']
                wait_phase(attachment_id, ['draining', 'detached_resident', 'detached'])
                file_access(True)
                snapshot(f'detached-{cycle}')
        stop.set()
        pump.join(timeout=5)
        assert not pump.is_alive() and not pump_errors, pump_errors
        with expected_lock:
            final = bytes(expected)
        deadline = time.monotonic()+10
        while bytes.fromhex(exchange('snapshot')['received_hex']) != final:
            if time.monotonic() >= deadline:
                raise AssertionError('raw keyboard bytes were lost, changed or duplicated')
            time.sleep(.01)
        snapshot('all_keyboard_bytes_delivered')
        assert final and b'\x03' in final and b'\x1b[A' in final
        exchange('exit')
        assert target.wait() == 37
        completion = json.loads(ready.with_suffix('.completed').read_text())
        assert completion['worker_exit_code'] == 37 and completion['terminal_restored_after_worker_exit'], completion
        target.reader.join(timeout=3)
        transcript = target.transcript()
        assert b'keys=' in transcript
        assert b'hyperhub:' not in transcript.lower(), 'management output polluted target terminal'
        visible = re.sub(rb'\x1b\](?:[^\x07\x1b]|\x1b(?!\\))*(?:\x07|\x1b\\)', b'', transcript)
        visible = re.sub(rb'\x1b\[[0-?]*[ -/]*[@-~]', b'', visible)
        visible = re.sub(rb'\x1b[78=>]', b'', visible)
        unexpected = re.sub(
            rb'terminal-ready|keys=[0-9]+|TARGET-RENDER:[0-9a-fA-F]{32}',
            b'', visible).strip(b' \r\n\t\b')
        assert not unexpected, ('unexpected output in target terminal', unexpected[:1000])
        (output/'target-terminal.log').write_bytes(transcript)
        (output/'result.json').write_text(json.dumps({
            'status': 'pass', 'origin': args.origin, 'backend': args.backend,
            'native_only': args.native_only, 'phases': phases,
            'input_bytes_sent': len(final), 'input_bytes_received': len(final),
            'keyboard_sequences': 'ASCII, arrow keys, DEL, literal Ctrl-C in raw mode',
            'commands': commands,
            'inputs': inputs,
            'terminal_restored_after_worker_exit': True,
            'only_fixture_visible_output': True,
            'scope': 'real target PTY/ConPTY; not only the approval console',
        }, indent=2)+'\n')
    except BaseException as error:
        (output/'failure.json').write_text(json.dumps({
            'status': 'fail', 'error': repr(error), 'phases': phases,
            'commands': commands, 'input_errors': pump_errors,
            'inputs': inputs,
        }, indent=2)+'\n')
        if target:
            (output/'target-terminal.log').write_bytes(target.transcript())
        raise
    finally:
        stop.set()
        if pump:
            pump.join(timeout=5)
        if info:
            try:
                exchange('exit')
            except (OSError, ValueError):
                pass
        if target_pin:
            target_pin.close()
        if target:
            target.close()
        if binary and not args.native_only:
            subprocess.run([str(binary), 'stop'], env=env, capture_output=True, timeout=30)
        temporary.cleanup()


if __name__ == '__main__':
    main()
