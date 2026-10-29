#!/usr/bin/env python3
"""Windows POSIX-runtime fork regression using only a disposable source target.

The compiler must target MSYS/Cygwin. A native MinGW executable cannot prove
fork continuity. Omitted compiler and non-Windows hosts do not count as a pass.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import queue
import shutil
import socket
import socketserver
import subprocess
import tempfile
import threading
import time

from windows_test_env import compiler_environment, isolated_environment

ROOT = Path(__file__).resolve().parents[1]


class Echo(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        while True:
            data = self.request.recv(8192)
            if not data:
                return
            self.request.sendall(data)


def free_port():
    with socket.socket() as stream:
        stream.bind(('127.0.0.1', 0))
        return stream.getsockname()[1]


def validate(report, expected_read, *, child, parent_pid):
    assert report['read_result'] == expected_read, ('file-policy', report)
    assert report['old_stream'], ('existing-socket-lost', report)
    assert report['stable_environment'] and report['stable_cwd'], ('target-context-changed', report)
    assert report['fork_error'] == 0, ('fork-failed', report)
    assert report['child_exit'] == (37 if child else 0), ('native-child-exit-changed', report)
    assert report['pid'] > 0 and (report['pid'] != parent_pid if child else report['pid'] == parent_pid)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--hyperhub', type=Path)
    parser.add_argument('--compiler', required=True, type=Path)
    parser.add_argument('--native-only', action='store_true')
    parser.add_argument('--expect-unsupported', action='store_true',
                        help='verify the current pre-mutation capability refusal; does not validate managed fork')
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    if os.name != 'nt':
        parser.error('Native Windows and a real MSYS/Cygwin compiler are required')
    if not args.native_only and args.hyperhub is None:
        parser.error('--hyperhub is required for the managed regression')
    if args.native_only and args.expect_unsupported:
        parser.error('native-only and expect-unsupported are distinct scenarios')
    from windows_conpty import Console

    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    compiler = args.compiler.resolve(strict=True)
    binary = args.hyperhub.resolve(strict=True) if args.hyperhub else None
    source = ROOT / 'tests/fixtures/dynamic_attach_posix_runtime.c'
    temporary = Path(tempfile.mkdtemp(prefix='hh-posix-runtime-'))
    env = isolated_environment(os.environ, temporary)
    # This explicit compiler directory supplies only the selected POSIX runtime
    # DLL. No target is started through bash or a caller's shell initialization.
    env['PATH'] = str(compiler.parent) + os.pathsep + env.get('PATH', '')
    for key in ['HOME', 'USERPROFILE', 'HYPERHUB_HOME', 'TMP', 'TEMP', 'APPDATA', 'LOCALAPPDATA']:
        Path(env[key]).mkdir(parents=True, exist_ok=True)
    build_env = compiler_environment(os.environ)
    secret = temporary / 'protected.txt'
    secret.write_bytes(b'S\n')
    password = temporary / 'administrator-password'
    password.write_text('private-posix-runtime-fixture-password\n')
    server = Echo(('127.0.0.1', 0), Handler)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    target = None
    errors = bytearray()
    commands, observations, cleanup_errors = [], [], []
    failure = None
    counter = 0
    started = False
    fixture = output / 'dynamic-posix-runtime.exe'

    def run(arguments, expected=0):
        nonlocal counter
        counter += 1
        result = subprocess.run([str(binary), *map(str, arguments)], env=env,
                                capture_output=True, timeout=90)
        (output / f'cli-{counter}.stdout').write_bytes(result.stdout)
        (output / f'cli-{counter}.stderr').write_bytes(result.stderr)
        commands.append({'arguments': list(map(str, arguments)), 'exit_code': result.returncode})
        assert result.returncode == expected, (arguments, result.returncode, result.stderr.decode(errors='replace'))
        return result.stdout

    def approve(request_id):
        with Console([str(binary), 'approve', request_id, '--admin-password-file', str(password)], env) as console:
            console.wait_for(b'Approve [y], reject [n], or quit [q]:')
            console.send('y\r')
            code = console.wait(90)
            transcript = console.transcript()
        (output / f'approval-{request_id}.log').write_bytes(transcript)
        assert code == 0, ('interactive approval failed', code, transcript.decode(errors='replace'))

    def phase(identifier, expected):
        deadline = time.monotonic() + 45
        while time.monotonic() < deadline:
            status = json.loads(run(['status', '--json']))
            record = next((r for r in status.get('attachments', []) if r['spec']['id'] == identifier), None)
            if record and record['phase'] in expected:
                return record
            assert not record or record['phase'] not in ['failed', 'cleanup_pending', 'degraded'], record
            time.sleep(.05)
        raise AssertionError(('attachment did not reach phase', identifier, expected))

    try:
        command = [str(compiler), '-std=c11', '-Wall', '-Wextra', '-Werror', str(source), '-o', str(fixture)]
        built = subprocess.run(command, env=build_env, capture_output=True, timeout=180)
        (output / 'build.stdout').write_bytes(built.stdout)
        (output / 'build.stderr').write_bytes(built.stderr)
        assert built.returncode == 0, ('POSIX runtime fixture build failed', built.returncode)
        if not args.native_only:
            config = temporary / 'config.toml'
            pattern = json.dumps(str(secret).replace('\\', '/'))
            config.write_text(f'''schema_version = 2
mode = "enforce"
debug = false
[gateway.listener]
socks_address = "127.0.0.1:{free_port()}"
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
id = "deny-private-fixture"
enabled = true
priority = 100
action = "deny"
operations = ["read"]
[[sandbox.file.rules.patterns]]
enabled = true
pattern = {pattern}
''')
            run(['import', config, '--admin-password-file', password])
            run(['start', '--admin-password-file', password])
            started = True
        target = subprocess.Popen([str(fixture), str(secret), str(server.server_address[1])], env=env,
                                  stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0)
        lines = queue.Queue()
        def collect():
            for line in iter(target.stdout.readline, b''):
                lines.put(line)
            lines.put(None)
        def collect_errors():
            for data in iter(lambda: target.stderr.read(8192), b''):
                errors.extend(data)
        threading.Thread(target=collect, daemon=True).start()
        threading.Thread(target=collect_errors, daemon=True).start()
        def exchange(command=None):
            if command is not None:
                target.stdin.write(command.encode() + b'\n')
                target.stdin.flush()
            line = lines.get(timeout=30)
            assert line is not None, ('source target exited', target.poll(), errors.decode(errors='replace'))
            report = json.loads(line)
            observations.append({'command': command or 'initial', 'report': report})
            return report
        initial = exchange()
        parent_pid = initial['pid']
        assert parent_pid == target.pid, 'The attachment target must be the exact native Windows child'
        validate(initial, 0, child=False, parent_pid=parent_pid)
        validate(exchange('fork'), 0, child=True, parent_pid=parent_pid)
        if not args.native_only:
            if args.expect_unsupported:
                for scope in ['process', 'tree']:
                    run(['attach', str(parent_pid), '--scope', scope, '--backend', 'gum'], expected=2)
                    assert b'unsupported_external_posix_runtime_fork' in (output / f'cli-{counter}.stderr').read_bytes()
                    assert not json.loads(run(['status', '--json']))['attachments']
                    validate(exchange('snapshot'), 0, child=False, parent_pid=parent_pid)
                    validate(exchange('fork'), 0, child=True, parent_pid=parent_pid)
            else:
                proposal = json.loads(run(['attach', str(parent_pid), '--scope', 'tree', '--backend', 'gum']))
                approve(proposal['request_id'])
                phase(proposal['attachment_id'], ['active'])
                validate(exchange('snapshot'), 13, child=False, parent_pid=parent_pid)
                validate(exchange('fork'), 13, child=True, parent_pid=parent_pid)
                validate(exchange('replace-stream'), 13, child=False, parent_pid=parent_pid)
                validate(exchange('fork'), 13, child=True, parent_pid=parent_pid)
                removal = json.loads(run(['detach', proposal['attachment_id']]))
                approve(removal['request_id'])
                phase(proposal['attachment_id'], ['detached', 'detached_resident'])
        validate(exchange('snapshot'), 0, child=False, parent_pid=parent_pid)
        validate(exchange('fork'), 0, child=True, parent_pid=parent_pid)
        target.stdin.write(b'exit\n')
        target.stdin.flush()
        assert target.wait(timeout=30) == 37
    except BaseException as error:
        failure = f'{type(error).__name__}: {error}'
    finally:
        if target is not None and target.poll() is None:
            try:
                target.stdin.write(b'exit\n')
                target.stdin.flush()
                target.wait(timeout=5)
            except BaseException:
                target.terminate()  # Only our unreaped, private fixture child.
                try:
                    target.wait(timeout=5)
                except BaseException as error:
                    cleanup_errors.append(str(error))
        if started:
            try:
                run(['stop'])
            except BaseException as error:
                cleanup_errors.append(str(error))
        server.shutdown()
        server.server_close()
        worker.join(timeout=3)
        try:
            shutil.rmtree(temporary)
        except BaseException as error:
            cleanup_errors.append(str(error))
        report = {'schema_version': 1, 'status': 'pass' if failure is None and not cleanup_errors else 'failed',
                  'platform': 'native-windows-posix-runtime', 'native_only': args.native_only,
                  'scenario': 'capability_refusal' if args.expect_unsupported else ('native' if args.native_only else 'managed_continuity'),
                  'source_sha256': hashlib.sha256(source.read_bytes()).hexdigest(),
                  'fixture_sha256': hashlib.sha256(fixture.read_bytes()).hexdigest() if fixture.exists() else None,
                  'compiler': str(compiler), 'observations': observations, 'commands': commands,
                  'error': failure, 'cleanup_errors': cleanup_errors, 'formal_run_binding': None}
        (output / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
    if failure or cleanup_errors:
        raise SystemExit(failure or str(cleanup_errors))
    print('POSIX-runtime native fork and socket continuity passed')


if __name__ == '__main__':
    main()
