#!/usr/bin/env python3
"""Real Linux attach approvals, non-owning lifetime and detach continuity.

All targets, credentials and local services are disposable. Only the fixture
opts into PR_SET_PTRACER; this runner never changes host ptrace_scope.
"""
import argparse
import errno
import hashlib
from collections import deque
import json
import os
from pathlib import Path
import pty
import re
import select
import shutil
import socket
import socketserver
import subprocess
import tempfile
import termios
import signal
import struct
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
EXEC_COMMANDS={method:('exec-root' if method=='path' else 'exec-root-'+method) for method in ['path','fexecve','execveat','fexecve-opath','execveat-relative','fexecve-deleted','execv','execvp','execl','execlp','execle','execvpe','path-nullargv','execveat-nullargv']}
EXEC_FAMILY_SEQUENCE=['path','path','fexecve','execveat','fexecve-opath','execveat-relative','fexecve-deleted','execv','execvp','execl','execlp','execle','execvpe','path-nullargv','execveat-nullargv','path']

class Echo(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True
class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        while True:
            data = self.request.recv(65536)
            if not data:
                break
            self.request.sendall(data)

class FakeDNS(socketserver.UDPServer):
    allow_reuse_address=True
class FakeDNSHandler(socketserver.BaseRequestHandler):
    def handle(self):
        packet,transport=self.request
        if len(packet)<17:return
        response=packet[:2]+bytes.fromhex('81800001000100000000')+packet[12:]+bytes.fromhex('c00c00010001000002580004c6124d09')
        transport.sendto(response,self.client_address)

class TargetStdioCapture:
    """Drain target stderr without retaining unbounded application data."""
    def __init__(self, label, stderr):
        self.label=label
        self.stderr=stderr
        self._lock=threading.Lock()
        self._stderr_bytes=0
        self._stderr_hash=hashlib.sha256()
        self._stderr_prefix=bytearray()
        self._unexpected_stdout_bytes=0
        self._unexpected_stdout_hash=hashlib.sha256()
        self._unexpected_stdout_prefix=bytearray()
        self._closed=False
        self._thread=threading.Thread(target=self._drain_stderr,name='target-stderr-drain',daemon=True)
        self._thread.start()

    @staticmethod
    def _safe_prefix(data):
        return ''.join(chr(value) if 32<=value<127 else f'\\x{value:02x}' for value in data)

    @staticmethod
    def _update(total, digest, prefix, data):
        total+=len(data)
        digest.update(data)
        if len(prefix)<256:prefix.extend(data[:256-len(prefix)])
        return total

    def _drain_stderr(self):
        while True:
            try:data=self.stderr.read(65536)
            except (OSError,ValueError):break
            if not data:break
            with self._lock:
                self._stderr_bytes=self._update(self._stderr_bytes,self._stderr_hash,self._stderr_prefix,data)

    def record_unexpected_stdout(self, data):
        if not data:return
        with self._lock:
            self._unexpected_stdout_bytes=self._update(self._unexpected_stdout_bytes,self._unexpected_stdout_hash,self._unexpected_stdout_prefix,data)

    def close(self, timeout=5):
        self._thread.join(timeout=timeout)
        with self._lock:self._closed=not self._thread.is_alive()

    def snapshot(self):
        with self._lock:
            return {
                'label':self.label,
                'stderr_bytes':self._stderr_bytes,
                'stderr_sha256':self._stderr_hash.hexdigest(),
                'stderr_prefix':self._safe_prefix(self._stderr_prefix),
                'unexpected_stdout_bytes':self._unexpected_stdout_bytes,
                'unexpected_stdout_sha256':self._unexpected_stdout_hash.hexdigest(),
                'unexpected_stdout_prefix':self._safe_prefix(self._unexpected_stdout_prefix),
                'drain_closed':self._closed,
            }

def copy_manager_logs(home, output):
    copied=0
    private_attachments=home/'runtime'/'attachments'
    if not private_attachments.is_dir() or private_attachments.is_symlink():return copied
    for directory in private_attachments.iterdir():
        if not directory.is_dir() or directory.is_symlink():continue
        source=directory/'manager.log'
        if not source.is_file() or source.is_symlink():continue
        destination=output/'manager-diagnostics'/directory.name/'manager.log'
        destination.parent.mkdir(parents=True,exist_ok=True)
        shutil.copyfile(source,destination)
        copied+=1
    return copied

def free_port():
    with socket.socket() as stream:
        stream.bind(('127.0.0.1', 0))
        return stream.getsockname()[1]

class PtyTarget:
    """A persistent session owner models a shell's foreground job faithfully.

    The CLI itself must not be the terminal's session leader: its normal exit
    must not manufacture SIGHUP for a still-running worker or descendant.
    """
    def __init__(self, argv, env):
        status_read,status_write=os.pipe()
        release_read,release_write=os.pipe()
        supervisor,master=pty.fork()
        if supervisor==0:
            os.close(status_read);os.close(release_write)
            gate_read,gate_write=os.pipe()
            child=os.fork()
            if child==0:
                os.close(gate_write)
                os.setpgid(0,0)
                os.read(gate_read,1);os.close(gate_read)
                attributes=termios.tcgetattr(0)
                attributes[3] &= ~(termios.ECHO | termios.ECHONL)
                termios.tcsetattr(0,termios.TCSANOW,attributes)
                os.execve(argv[0],argv,env)
            os.close(gate_read)
            os.setpgid(child,child)
            os.tcsetpgrp(0,child)
            os.write(status_write,child.to_bytes(8,'big'))
            os.write(gate_write,b'G');os.close(gate_write)
            _,status=os.waitpid(child,0)
            os.write(status_write,status.to_bytes(8,'big'))
            os.read(release_read,1)
            os._exit(0)
        os.close(status_write);os.close(release_read)
        assert select.select([status_read],[],[],30)[0], 'PTY supervisor did not launch foreground job'
        self.pid=int.from_bytes(os.read(status_read,8),'big')
        self.supervisor=supervisor
        self.status_read=status_read;self.release_write=release_write
        self.stdin=os.fdopen(os.dup(master),'wb',buffering=0)
        self.stdout=os.fdopen(master,'rb',buffering=0)
        self.returncode=None
    def poll(self):
        if self.returncode is None and select.select([self.status_read],[],[],0)[0]:
            status=os.read(self.status_read,8)
            assert len(status)==8, 'PTY supervisor lost original foreground status'
            self.returncode=os.waitstatus_to_exitcode(int.from_bytes(status,'big'))
        return self.returncode
    def wait(self, timeout):
        deadline=time.monotonic()+timeout
        while self.poll() is None:
            if time.monotonic()>deadline:raise subprocess.TimeoutExpired('disposable target',timeout)
            time.sleep(.01)
        return self.returncode
    def terminate(self):os.kill(self.pid,signal.SIGTERM)
    def kill(self):os.kill(self.pid,signal.SIGKILL)
    def close(self):
        os.close(self.release_write);os.close(self.status_read)
        deadline=time.monotonic()+5
        while time.monotonic()<deadline:
            pid,_=os.waitpid(self.supervisor,os.WNOHANG)
            if pid:return
            time.sleep(.01)
        os.kill(self.supervisor,signal.SIGKILL);os.waitpid(self.supervisor,0)

def phase_is_terminal_failure(current, transient=()):
    return current in {'failed','cleanup_pending','degraded'} and current not in transient


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--hyperhub', required=True, type=Path)
    parser.add_argument('--backend', required=True, choices=['ptrace', 'gum'])
    parser.add_argument('--scope', choices=['process','tree'], default='tree')
    parser.add_argument('--target-pty', action='store_true')
    parser.add_argument('--origin', choices=['attach','run'], default='attach')
    parser.add_argument('--legacy-negative', action='store_true')
    parser.add_argument('--unsupported-negative',action='store_true',help='verify restricted-Yama Gum refusal before target mutation')
    parser.add_argument('--child-startup-failure',action='store_true',help='isolated Gum tree future-child bind failure; approved Detach alone releases its original application thread')
    parser.add_argument('--busy-preparation',action='store_true',help='continuously fork during approved initial attachment and reactivation')
    parser.add_argument('--busy-fork-workers',type=int,choices=[1,2],default=2,help='independent native fork workers in the busy-preparation fixture')
    parser.add_argument('--root-exit', action='store_true')
    parser.add_argument('--allocator-fork-regression',action='store_true',help='neutral allocator-to-fork-to-child-exit continuation regression')
    parser.add_argument('--thread-creation-regression',action='store_true',help='ordinary pthread allocation/creation while anonymous VMAs change; isolated memory regression')
    parser.add_argument('--mapping-regression',choices=['plain','space','newline','deleted-literal'],help='preexisting closed-FD PROT_NONE file mapping plus allocator and FD-pressure regressions')
    parser.add_argument('--root-self-exec',action='store_true',help='exec the approved original root in place before detach and reactivation')
    parser.add_argument('--root-exec-methods',nargs='+',choices=list(EXEC_COMMANDS),help='ordered root exec events; requires root-self-exec (default: one path exec)')
    parser.add_argument('--exec-family-regression',action='store_true',help='native/managed/detached exec errno and standard API family, including FD and deleted/relative images')
    parser.add_argument('--fake-ip', action='store_true',help='observed external alias with pre-existing native route')
    parser.add_argument('--issued-fake-ip', action='store_true',help='cache an alias actually issued by the loaded HyperHub SDK')
    parser.add_argument('--inherited-issued',action='store_true',help='verify native-only cached aliases in unmanaged fork children and grandchildren')
    parser.add_argument('--cross-producer-issued',action='store_true',help='existing child issues the alias; parent consumes only sockaddr IPC after producer exit')
    parser.add_argument('--serve-restart', action='store_true')
    parser.add_argument('--alias-serve-offline',action='store_true',help='verify detached cached aliases with the private Serve stopped')
    parser.add_argument('--diagnostic-fork', action='store_true')
    parser.add_argument('--manager-frida-diagnostics', action='store_true',help='record manager-only Frida command stages without target arguments or data')
    parser.add_argument('--diagnostic-crash',action='store_true',help='stop only a crashing disposable fixture child for an address-only debugger backtrace')
    parser.add_argument('--fixture-child-debugger',action='store_true',help='diagnostic control: disposable application opts its future children into debugger access')
    parser.add_argument('--trace-manager-ptrace',action='store_true',help='diagnostic: trace only private approval manager/helper ptrace syscalls, never the target')
    parser.add_argument('--manager-loss',choices=['none','clean','dirty'],default='none')
    parser.add_argument('--approval-manager-exit',action='store_true',help='kill the exact live manager only after the Detach review prompt; the first approval must be superseded and reviewed again')
    parser.add_argument('--cycles', type=int, default=1)
    parser.add_argument('--duration', type=float, default=0)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    if args.exec_family_regression:
        args.root_self_exec=True
        if args.root_exec_methods is None:args.root_exec_methods=list(EXEC_FAMILY_SEQUENCE)
    if args.allocator_fork_regression:args.thread_creation_regression=True
    if args.cycles < 1 or args.duration < 0:
        parser.error('cycles must be positive and duration nonnegative')
    if args.manager_loss!='none' and (args.origin!='attach' or args.root_exit or args.legacy_negative or args.fake_ip or args.issued_fake_ip):
        parser.error('manager-loss requires external attach and its own isolated non-FAKE-IP scenario')
    if args.manager_loss=='dirty' and args.backend!='ptrace':parser.error('dirty virtual-FD refusal is a ptrace scenario')
    if args.serve_restart and args.origin!='attach':parser.error('serve-restart continuity fixture requires an originally direct pre-attach connection')
    if args.root_exit and (args.scope!='tree' or args.cycles!=1 or args.duration!=0 or args.legacy_negative):
        parser.error('root-exit requires tree scope, one cycle, no duration and no legacy-negative')
    if args.legacy_negative and args.origin != 'attach':
        parser.error('legacy-negative requires external attach')
    if args.origin == 'run' and args.scope != 'tree':
        parser.error('owned run has tree scope')
    if args.issued_fake_ip and (args.backend!='gum' or args.fake_ip):parser.error('issued-fake-ip requires Gum and is separate from observed fake-ip')
    alias_scenario=args.fake_ip or args.issued_fake_ip
    if args.approval_manager_exit and (args.backend!='gum' or args.origin!='attach' or args.cycles!=1 or args.duration or args.root_self_exec or args.root_exit or args.legacy_negative or args.unsupported_negative or args.busy_preparation or args.child_startup_failure or alias_scenario or args.manager_loss!='none' or args.serve_restart or args.thread_creation_regression or args.mapping_regression):
        parser.error('approval-manager-exit requires its own one-cycle Gum external attach scenario')
    if args.inherited_issued and not args.issued_fake_ip:parser.error('inherited-issued requires an actual SDK-issued alias')
    if args.cross_producer_issued and (not args.issued_fake_ip or args.backend!='gum' or args.scope!='tree' or args.origin!='attach' or not args.alias_serve_offline or args.cycles<2):parser.error('cross-producer-issued requires Gum tree external attach, issued-fake-ip, alias-serve-offline and at least two cycles')
    if args.alias_serve_offline and (not alias_scenario or args.origin!='attach'):parser.error('alias-serve-offline requires an external alias scenario')
    if args.unsupported_negative and (args.backend!='gum' or args.legacy_negative or args.root_exit or alias_scenario or args.manager_loss!='none'):parser.error('unsupported-negative requires its own Gum attach/run scenario')
    if args.unsupported_negative:
        yama=Path('/proc/sys/kernel/yama/ptrace_scope')
        if not yama.exists() or yama.read_text().strip() not in ['1','2','3']:parser.error('unsupported-negative requires an actually restricted Yama environment')
    if args.busy_preparation:
        if args.backend!='gum' or args.scope!='tree' or args.origin!='attach' or args.unsupported_negative or args.legacy_negative or args.root_exit or alias_scenario or args.manager_loss!='none' or args.serve_restart or args.duration:parser.error('busy-preparation requires its own Gum tree external attach scenario')
        yama=Path('/proc/sys/kernel/yama/ptrace_scope')
        if yama.exists() and yama.read_text().strip()!='0':parser.error('busy-preparation positive/refusal semantics require an actually unrestricted Yama environment')
    if args.child_startup_failure:
        if args.backend!='gum' or args.scope!='tree' or args.origin!='attach' or args.target_pty or args.cycles!=1 or args.duration or args.busy_preparation or args.root_self_exec or args.root_exit or args.legacy_negative or args.unsupported_negative or alias_scenario or args.manager_loss!='none' or args.serve_restart or args.thread_creation_regression or args.mapping_regression:
            parser.error('child-startup-failure requires its own Gum tree external attach, one cycle, no PTY or other scenario')
        yama=Path('/proc/sys/kernel/yama/ptrace_scope')
        if yama.exists() and yama.read_text().strip()!='0':parser.error('child-startup-failure requires an actually unrestricted Yama environment')
    if args.root_exec_methods and not args.root_self_exec:parser.error('root-exec-methods requires root-self-exec')
    if args.root_self_exec and (args.root_exit or args.legacy_negative or args.unsupported_negative or args.busy_preparation or alias_scenario or args.manager_loss!='none' or args.serve_restart):parser.error('root-self-exec requires its own attachment/run scenario')
    if alias_scenario and (args.root_exit or args.legacy_negative):parser.error('alias cache tests are separate from root-exit and legacy-negative cases')
    if args.thread_creation_regression and (args.origin!='attach' or args.root_self_exec or args.root_exit or alias_scenario or args.busy_preparation or args.unsupported_negative or args.manager_loss!='none' or args.mapping_regression):parser.error('thread-creation-regression requires an isolated external attach scenario')
    if args.mapping_regression and (args.origin!='attach' or args.root_self_exec or args.root_exit or alias_scenario or args.busy_preparation or args.unsupported_negative or args.manager_loss!='none'):parser.error('mapping-regression requires its own external attach scenario')
    binary = args.hyperhub.resolve()
    output = args.output.resolve()
    output.mkdir(parents=True, mode=0o700, exist_ok=False)
    temporary = Path(tempfile.mkdtemp(prefix='hh-attach-test-'))
    temporary.chmod(0o700)
    env = {key:value for key,value in os.environ.items() if key in ['PATH','LANG','LC_ALL','LC_CTYPE','TERM','TZ']}
    # The disposable private HOME also isolates the legacy skill installation
    # path when testing the unchanged stable baseline executable.
    for key,name in [('HOME','home'),('HYPERHUB_HOME','instance'),('XDG_RUNTIME_DIR','runtime'),('TMPDIR','tmp')]:
        directory = temporary/name
        directory.mkdir(mode=0o700)
        env[key] = str(directory)
    password = temporary/'administrator-password'
    password.write_text('disposable-attachment-test-password\n')
    password.chmod(0o600)
    secret_name={'plain':'protected.txt','space':'protected with space.txt','newline':'protected\nwith newline.txt','deleted-literal':'protected (deleted)'}.get(args.mapping_regression,'protected.txt')
    secret = temporary/secret_name
    secret.write_text('S\n')
    secret.chmod(0o600)
    ordinary=Path(str(secret)+'.ordinary');ordinary.write_text('S\n');ordinary.chmod(0o600)
    cli_counter = 0
    commands = []
    checks = []
    approval_replans=[]
    manager_exit_observations=[]
    recent_exchanges = deque(maxlen=40)
    fork_observations = []
    retirement_observations=[]
    exec_error_observations=[]
    exec_error_oracle=None
    root_exec_observations=[]
    native_root_exec_observations=[]
    samples = []
    phase_windows = []
    phase_observations=[]
    soak_intervals = []
    target = None
    target_stdio_captures=[]
    target_stdio_by_process={}
    connect_boundary_oracle=None
    orphan_pid = None
    orphan_pidfd = None
    fault_control_path=None
    fault_oracle=None
    fault_shim=None
    fault_native_oracle=None
    fault_fifo_active=False
    fault_fifo_writer=None
    child_startup_observations=[]
    server = Echo(('127.0.0.1', 0), Handler)
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    dns=FakeDNS(('127.0.0.1',0),FakeDNSHandler)
    dns_thread=threading.Thread(target=dns.serve_forever,daemon=True);dns_thread.start()
    env['HYPERHUB_DNS_PORTS']=str(dns.server_address[1])
    env['HYPERHUB_ATTACHMENT_DIAGNOSTICS']='1'
    if args.manager_frida_diagnostics:
        env['HYPERHUB_FRIDA_DIAGNOSTICS']='1'

    def run(arguments, expected=0, record=True):
        nonlocal cli_counter
        cli_counter += 1
        completed = subprocess.run([str(binary), *arguments], env=env, capture_output=True, timeout=90)
        if record or completed.returncode != expected:
            (output/f'cli-{cli_counter}.stdout').write_bytes(completed.stdout)
            (output/f'cli-{cli_counter}.stderr').write_bytes(completed.stderr)
            commands.append({'args':arguments,'exit_code':completed.returncode})
        assert completed.returncode == expected, (arguments, completed.returncode, completed.stderr.decode(errors='replace'))
        return completed.stdout

    def target_stdio_evidence():
        evidence=[capture.snapshot() for capture in target_stdio_captures]
        (output/'target-stdio.json').write_text(json.dumps(evidence,indent=2)+'\n')
        return evidence

    def write_result(report):
        report.setdefault('phase_observations',phase_observations)
        report.setdefault('target_stdio',target_stdio_evidence())
        (output/'result.json').write_text(json.dumps(report,indent=2)+'\n')

    def track_target_stdio(process, label):
        if isinstance(process,PtyTarget):return
        capture=TargetStdioCapture(label,process.stderr)
        target_stdio_captures.append(capture)
        target_stdio_by_process[process]=capture
        target_stdio_evidence()

    def record_unexpected_target_stdout(process, data):
        capture=target_stdio_by_process.get(process)
        if capture is not None:
            capture.record_unexpected_stdout(data)
            target_stdio_evidence()

    def assert_no_extra_target_stdout(process, stage, grace=.01):
        if isinstance(process,PtyTarget):return
        ready,_,_=select.select([process.stdout],[],[],grace)
        if not ready:return
        data=os.read(process.stdout.fileno(),65536)
        if not data:return
        record_unexpected_target_stdout(process,data)
        raise AssertionError(('target-produced-unrequested-stdout',stage,len(data),hashlib.sha256(data).hexdigest()))

    def assert_target_stderr_empty(process, stage):
        capture=target_stdio_by_process.get(process)
        if capture is None:return
        snapshot=capture.snapshot()
        if snapshot['stderr_bytes']:
            target_stdio_evidence()
            raise AssertionError(('target-stderr-was-not-application-owned',stage,snapshot))

    def read_target_json(process, stage):
        raw_line=process.stdout.readline()
        try:value=json.loads(raw_line)
        except json.JSONDecodeError as error:
            record_unexpected_target_stdout(process,raw_line)
            raise AssertionError(('target-stdout-was-not-json',stage,raw_line[:4096])) from error
        return value

    def finish_target(process, expected, timeout, stage):
        code=process.wait(timeout=timeout)
        if not isinstance(process,PtyTarget):
            drain_deadline=time.monotonic()+timeout
            while True:
                remaining=drain_deadline-time.monotonic()
                assert remaining>0, ('target-stdout-pipe-did-not-close',stage)
                ready,_,_=select.select([process.stdout],[],[],remaining)
                assert ready, ('target-stdout-pipe-did-not-close',stage)
                data=os.read(process.stdout.fileno(),65536)
                if not data:break
                record_unexpected_target_stdout(process,data)
            capture=target_stdio_by_process[process]
            capture.close()
            target_stdio_evidence()
            snapshot=capture.snapshot()
            assert snapshot['drain_closed'], ('target-stderr-drain-did-not-finish',stage,snapshot)
            assert snapshot['stderr_bytes']==0, ('target-stderr-was-not-application-owned',stage,snapshot)
            assert snapshot['unexpected_stdout_bytes']==0, ('target-produced-unrequested-stdout',stage,snapshot)
        assert code==expected, ('target-exit-code-changed',stage,expected,code)
        return code

    def _approve_once(request_id, expected=0, stale_exec=False, config_plan=None, before_yes=None):
        nonlocal cli_counter
        assert request_id is not None or config_plan is not None, 'configuration approval requires the exact submitted proposal'
        cli_counter += 1
        master,slave = pty.openpty()
        command=[str(binary),'approve',*([request_id] if request_id else []),'--admin-password-file',str(password)]
        if args.trace_manager_ptrace and request_id:
            command=['strace','-D','-ff','-e','trace=ptrace','-e','raw=ptrace','-o',str(output/f'private-manager-ptrace-{cli_counter}'),*command]
        process = subprocess.Popen(command,env=env,stdin=slave,stdout=slave,stderr=slave,start_new_session=True)
        os.close(slave)
        transcript = bytearray()
        answered = False
        config_decisions = 0
        config_selected = False
        config_ids=[] if config_plan is None else [request['uuid'] for request in config_plan['requests']]
        if config_plan is not None:
            assert request_id is None and config_plan['status']=='approval_required' and config_plan['approval_token']
            assert config_ids and len(config_ids)==len(set(config_ids))==config_plan['request_count']
        deadline = time.monotonic()+90
        try:
            while True:
                ready,_,_ = select.select([master],[],[],0.05)
                if ready:
                    try:
                        data = os.read(master,65536)
                    except OSError:
                        data = b''
                    transcript.extend(data)
                    if config_plan is not None and not config_selected and b'Select request id' in transcript:
                        os.write(master,b'config\n');config_selected=True
                    if not answered and b'Approve [y], reject [n], or quit [q]:' in transcript:
                        assert config_plan is None, 'configuration approval selected a runtime request'
                        if before_yes is not None:before_yes()
                        os.write(master,b'y\n')
                        answered = True
                    prompt_count=transcript.count('选择 [a]批准'.encode())
                    while config_decisions<prompt_count:
                        assert config_plan is not None and config_decisions<len(config_ids), 'unexpected configuration approval prompt'
                        preview=transcript.decode(errors='replace').split('选择 [a]批准')[config_decisions]
                        assert config_ids[config_decisions] in preview, ('configuration preview UUID does not match the exact submitted proposal',config_ids[config_decisions])
                        os.write(master,b'a\n');config_decisions+=1;answered=True
                    if not data and process.poll() is not None:
                        break
                elif process.poll() is not None:
                    break
                if time.monotonic()>deadline:
                    process.terminate()
                    raise AssertionError('approval did not finish before its bounded deadline')
            code = process.wait(timeout=5)
            (output/f'approval-{cli_counter}.log').write_bytes(transcript)
            commands.append({'args':['approve',request_id],'exit_code':code})
            text=transcript.decode(errors='replace')
            if config_plan is not None:assert config_decisions==len(config_ids), ('configuration approval did not complete its exact request list',config_decisions,config_ids,text)
            assert (answered or stale_exec) and (code==expected if expected is not None else code in [0,2]), (code,text)
            if stale_exec:
                assert code==2 and re.search(r'(?:epoch|executable|identity).{0,100}changed',text,re.I), ('old-exec-request-was-not-explicitly-rejected-as-stale',code,text)
            result=None
            for line in transcript.decode(errors='replace').splitlines():
                try:
                    value=json.loads(re.sub(r'\x1b\[[0-9;]*[A-Za-z]','',line).strip())
                except json.JSONDecodeError:continue
                if isinstance(value,dict) and value.get('status') in ['approved','already_detached','execution_pending','approval_required'] and 'attachment_id' in value:result=value
            if request_id and code==0:assert result is not None, 'runtime approval did not publish its actual attachment identity'
            if stale_exec:assert result is None, ('stale-root-exec-request-was-replanned-or-approved',result)
            return result
        finally:
            os.close(master)
            if process.poll() is None:
                process.terminate()
                process.wait(timeout=5)

    def approve(request_id, expected=0, stale_exec=False, config_plan=None, before_yes=None):
        result=_approve_once(request_id,expected=expected,stale_exec=stale_exec,config_plan=config_plan,before_yes=before_yes)
        if request_id is None or stale_exec or result is None or result.get('status')!='approval_required':return result
        assert result.get('reason')=='attachment_manager_exited_during_review', ('unexpected-runtime-approval-replan',result)
        assert result.get('supersedes_request_id')==request_id, ('runtime-approval-replan-did-not-supersede-reviewed-request',request_id,result)
        replacement_id=result.get('request_id')
        assert isinstance(replacement_id,str) and replacement_id and replacement_id!=request_id, ('runtime-approval-replan-did-not-publish-fresh-request',request_id,result)
        approval_replans.append({'reviewed_request_id':request_id,'replacement_request_id':replacement_id,'reason':result['reason']})
        replacement=_approve_once(replacement_id,expected=expected)
        assert replacement is not None and replacement.get('status')!='approval_required', ('runtime-approval-replanned-more-than-once',request_id,replacement_id,replacement)
        return replacement

    def fault_command(action, *arguments):
        assert fault_control_path is not None and fault_oracle is not None
        completed=subprocess.run([str(fault_oracle),action,str(fault_control_path),*map(str,arguments)],env=env,capture_output=True,timeout=10)
        assert completed.returncode==0, ('bind-fault-control-failed',action,completed.returncode,completed.stderr.decode(errors='replace'))

    def fault_state():
        data=fault_control_path.read_bytes()
        assert len(data)==248, ('bind-fault-layout',len(data))
        version,enabled,root_pid,hits,last_pid,root_passes,child_passes,path_length,prefix,last_path=struct.unpack('=8I108s108s',data)
        assert version==1
        return {'enabled':bool(enabled),'root_pid':root_pid,'hits':hits,'last_pid':last_pid,'root_bind_passes':root_passes,'child_bind_passes':child_passes,'path_length':path_length,'prefix':os.fsdecode(prefix.split(b'\0',1)[0]),'last_path':os.fsdecode(last_path.split(b'\0',1)[0])}

    def accepted_identity(proposal, result):
        if result is not None:
            assert result['status'] in ['approved','already_detached','execution_pending']
            for name in ['attachment_id','request_id','supersedes_request_id']:
                if name in result:proposal[name]=result[name]
        return proposal

    def observe_fork(stop):
        for pause in [.2,1,3,4]:
            if stop.wait(pause):return
            try:
                children=Path(f'/proc/{original_pid}/task/{original_pid}/children').read_text().split()
                processes=[]
                for pid in [str(original_pid),*children]:
                    process={'pid':int(pid),'tasks':[]}
                    status=Path(f'/proc/{pid}/status').read_text()
                    process['status']=[line for line in status.splitlines() if line.split(':',1)[0] in ['State','PPid','TracerPid','Threads','SigBlk']]
                    for task in Path(f'/proc/{pid}/task').iterdir():
                        entry={'tid':int(task.name)}
                        for name in ['wchan','syscall']:
                            try:entry[name]=(task/name).read_text()[:300]
                            except OSError as error:entry[name]=repr(error)
                        process['tasks'].append(entry)
                    processes.append(process)
                fork_observations.append({'observed_unix_ns':time.time_ns(),'processes':processes})
            except OSError as error:fork_observations.append({'error':repr(error)})

    def observe_crash(stop):
        report=output/'fixture-crash.bin'
        while not stop.wait(.025):
            if not report.exists() or report.stat().st_size<struct.calcsize('@6P'):continue
            pid,number,instruction,address,stack,frame=struct.unpack('@6P',report.read_bytes()[-struct.calcsize('@6P'):])
            try:
                status=Path(f'/proc/{pid}/status').read_text()
                parent=int(re.search(r'^PPid:\s+(\d+)',status,re.M)[1])
                assert parent==original_pid, ('crash reporter is not the disposable target child',pid,parent)
                (output/'fixture-crash-addresses.json').write_text(json.dumps({'pid':pid,'signal':number,'instruction':hex(instruction),'fault_address':hex(address)})+'\n')
                diagnostic=subprocess.run(['gdb','--nx','--quiet','--batch','-p',str(pid),
                    '-ex','set confirm off','-ex','set print frame-arguments none','-ex','set print entry-values no',
                    '-ex','info threads','-ex','thread apply all bt 24','-ex','info proc mappings',
                    '-ex','thread 1','-ex','set $saved_pc=$pc','-ex','set $saved_sp=$sp','-ex','set $saved_frame=$fp',
                    '-ex',f'set $pc={instruction:#x}','-ex',f'set $sp={stack:#x}','-ex',f'set $fp={frame:#x}',
                    '-ex','bt 32','-ex','set $pc=$saved_pc','-ex','set $sp=$saved_sp','-ex','set $fp=$saved_frame',
                    '-ex',f'x/16i {instruction:#x}','-ex','detach'],env=env,capture_output=True,timeout=15)
                (output/'fixture-crash-gdb.txt').write_bytes(diagnostic.stdout+diagnostic.stderr)
                os.kill(pid,signal.SIGCONT)
            except Exception as error:
                (output/'fixture-crash-debugger-error.txt').write_text(repr(error)+'\n')
                try:os.kill(pid,signal.SIGCONT)
                except ProcessLookupError:pass
            return

    def exchange(command):
        assert target is not None, 'target was not started'
        if orphan_pidfd is None:assert target.poll() is None, 'target unexpectedly exited'
        else:assert not select.select([orphan_pidfd],[],[],0)[0], 'approved surviving descendant unexpectedly exited'
        observer=None;stop=None;crash_observer=None;crash_stop=None
        if args.diagnostic_fork and command=='fork-read':
            stop=threading.Event();observer=threading.Thread(target=observe_fork,args=(stop,),daemon=True);observer.start()
        if args.diagnostic_crash and command=='fork-read':
            crash_stop=threading.Event();crash_observer=threading.Thread(target=observe_crash,args=(crash_stop,),daemon=True);crash_observer.start()
        started=time.perf_counter_ns()
        target.stdin.write(command.encode()+b'\n')
        target.stdin.flush()
        ready,_,_=select.select([target.stdout],[],[],30)
        assert ready, ('target stopped making progress',command)
        value=read_target_json(target,command)
        if command=='fork-exit' and 'neutral_child_ready_to_exit'in value:
            assert value['neutral_child_ready_to_exit'], ('neutral-child-did-not-return-from-fork',value)
            fork_observations.append({'observed_unix_ns':time.time_ns(),'neutral_child_ready_to_exit':True,'neutral_child_pid':value['neutral_child_pid']})
            remaining=max(0,30-(time.perf_counter_ns()-started)/1e9)
            ready,_,_=select.select([target.stdout],[],[],remaining)
            assert ready, ('child returned from fork but did not complete libc exit',value)
            value=read_target_json(target,command+'-completion')
        assert_no_extra_target_stdout(target,command)
        assert_target_stderr_empty(target,command)
        if crash_stop is not None:crash_stop.set();crash_observer.join(timeout=16)
        elapsed=time.perf_counter_ns()-started
        recent_exchanges.append({'command':command,'response':value,'elapsed_ns':elapsed})
        if stop is not None:stop.set();observer.join(timeout=1)
        return value,elapsed

    def distribution(values):
        if not values:return {'samples':0}
        ordered=sorted(values)
        def percentile(fraction):return ordered[min(len(ordered)-1,int((len(ordered)-1)*fraction))]
        return {'samples':len(values),'p50_ns':percentile(.5),'p95_ns':percentile(.95),'p99_ns':percentile(.99),'max_ns':ordered[-1]}

    def measure_window(name, expected_pid):
        raw=[]
        started_wall=time.time_ns();started_clock=time.perf_counter_ns()
        for _ in range(32):
            snapshot,latency=exchange('snapshot')
            assert snapshot['pid']==expected_pid and snapshot['stable_stdio_cwd'] and snapshot['stable_environment'] and snapshot['stable_terminal']
            raw.append({'command':'snapshot','latency_ns':latency})
            value,latency=exchange('socket')
            assert value['old_stream'], 'measurement payload did not echo correctly'
            raw.append({'command':'socket','latency_ns':latency})
        elapsed=time.perf_counter_ns()-started_clock
        phase_windows.append({'phase':name,'pid':expected_pid,'started_unix_ns':started_wall,'ended_unix_ns':time.time_ns(),'elapsed_ns':elapsed,'completed_valid_commands':len(raw),'completed_valid_commands_per_second':len(raw)*1e9/elapsed,'latencies':raw,'snapshot_latency':distribution([sample['latency_ns'] for sample in raw if sample['command']=='snapshot']),'socket_latency':distribution([sample['latency_ns'] for sample in raw if sample['command']=='socket']),'measurement':'fixed 32-pair closed loop; no approvals, setup or pacing sleeps in window; not a capacity measurement'})

    def soak_window(name, until, expected_read):
        nonlocal workload_count
        started_wall=time.time_ns();started_clock=time.perf_counter_ns()
        raw=[];valid=0;totals={}
        while time.monotonic()<until:
            for command in ['snapshot','socket','read','new-socket']:
                value,latency=exchange(command)
                if command=='snapshot':assert value['stable_stdio_cwd'] and value['stable_environment'] and value['stable_terminal']
                elif command=='socket':assert value['old_stream']
                elif command=='read':assert value['read_result']==expected_read
                else:assert value['new_stream']
                valid+=1;workload_count+=1
                aggregate=totals.setdefault(command,{'count':0,'total_latency_ns':0,'max_latency_ns':0})
                aggregate['count']+=1;aggregate['total_latency_ns']+=latency;aggregate['max_latency_ns']=max(aggregate['max_latency_ns'],latency)
                if len(raw)<128:raw.append({'command':command,'latency_ns':latency})
                if command=='snapshot' and len(workload_latencies)<10000:workload_latencies.append(latency)
            time.sleep(.05)
        elapsed=time.perf_counter_ns()-started_clock
        soak_intervals.append({'phase':name,'started_unix_ns':started_wall,'ended_unix_ns':time.time_ns(),'elapsed_ns':elapsed,'completed_valid_commands':valid,'completed_valid_commands_per_second':valid*1e9/max(1,elapsed),'per_command_aggregates':totals,'bounded_prefix_latency_samples':raw,'measurement':'paced closed-loop soak interval; 50ms between four-command batches; approval and setup excluded; prefix samples are diagnostics, not a whole-soak percentile estimate'})

    def kernel_identity(pid):
        proc=Path('/proc')/str(pid)
        fields=(proc/'stat').read_text().rsplit(') ',1)[1].split()
        return {'pid':pid,'birth':int(fields[19]),'owner':str(proc.stat().st_uid),'executable':os.readlink(proc/'exe'),'executable_sha256':hashlib.sha256((proc/'exe').read_bytes()).hexdigest()}

    def record_fixture_fds(label, pid, descendants=True):
        if not args.manager_frida_diagnostics:
            return
        # Observe only this runner's source fixture, and read metadata only.
        # The application owns all descriptor lifetime decisions.
        identity=kernel_identity(pid)
        assert identity['owner']==str(os.getuid()) and identity['executable_sha256']==hashlib.sha256(fixture.read_bytes()).hexdigest()
        proc=Path('/proc')/str(pid)
        descriptors=[]
        for descriptor in sorted((proc/'fd').iterdir(),key=lambda path:int(path.name)):
            try:
                flags=next(line.split(':',1)[1].strip() for line in (proc/'fdinfo'/descriptor.name).read_text().splitlines() if line.startswith('flags:'))
                descriptors.append({'fd':int(descriptor.name),'target':os.readlink(descriptor),'flags_octal':flags,'cloexec':bool(int(flags,8)&os.O_CLOEXEC)})
            except (FileNotFoundError,ProcessLookupError):
                continue
        assert kernel_identity(pid)==identity, 'fixture changed identity during descriptor observation'
        with (output/'fixture-fd-metadata.jsonl').open('a') as log:
            log.write(json.dumps({'stage':label,'identity':identity,'descriptors':descriptors})+'\n')
        if descendants:
            pending=[pid]
            seen={pid}
            while pending and len(seen)<64:
                parent=pending.pop()
                try:
                    children=Path(f'/proc/{parent}/task/{parent}/children').read_text().split()
                except (FileNotFoundError,ProcessLookupError):
                    continue
                for value in children:
                    child=int(value)
                    if child in seen:continue
                    seen.add(child)
                    try:
                        child_identity=kernel_identity(child)
                        if child_identity['owner']!=identity['owner'] or child_identity['executable_sha256']!=identity['executable_sha256']:continue
                        record_fixture_fds(label+'_descendant_of_'+str(parent),child,False)
                        pending.append(child)
                    except (FileNotFoundError,ProcessLookupError):
                        continue

    def exec_errors(label):
        nonlocal exec_error_oracle
        value=exchange('exec-fd-errors')[0]
        expected=['fexecve_invalid_fd','execveat_invalid_flags','execveat_bad_path','execveat_none_path','fexecve_none_argv','execveat_none_argv','fexecve_none_envp','execveat_none_envp','execveat_none_argv_element','fexecve_cloexec_script','execveat_nofollow']
        assert value.get('temporary_resources_removed') and [item['call']for item in value.get('exec_errors',[])]==expected, ('exec-error-source-actor-incomplete',label,value)
        assert all(item['result']==-1 and item['fd_flags_preserved'] for item in value['exec_errors']), ('native-exec-failure-or-fd-flags-changed',label,value)
        if exec_error_oracle is None:
            assert label.startswith('native'), ('exec-errno-oracle-was-not-native',label)
            exec_error_oracle=value
        else:assert value==exec_error_oracle, ('exec-errno-differs-from-native',label,exec_error_oracle,value)
        exec_error_observations.append({'phase':label,**value})

    def native_root_execs(snapshot):
        if not args.root_self_exec:return snapshot
        pid=snapshot['pid']
        original_identity=kernel_identity(pid);birth=original_identity['birth']
        if args.exec_family_regression:exec_errors('native_initial')
        for method in args.root_exec_methods or ['path']:
            next_image=exchange(EXEC_COMMANDS[method])[0]
            assert next_image['pid']==pid, ('native-root-exec-changed-pid',method,next_image)
            assert next_image['null_argv_image']==method.endswith('-nullargv'), ('native-null-argv-did-not-reach-new-image',method,next_image)
            for key in ['stable_stdio_cwd','stable_environment','has_terminal','stable_terminal']:assert next_image[key]==snapshot[key], ('native-root-exec-behavior',method,key,next_image)
            current_identity=kernel_identity(pid)
            assert all(current_identity[key]==original_identity[key]for key in ['pid','birth','owner','executable_sha256']), ('native-exec-changed-incarnation-or-image-bytes',method,current_identity,original_identity)
            if args.exec_family_regression:exec_errors('native_after_'+method)
            assert exchange('socket')[0]['old_stream'], ('native-exec-stream',method)
            native_root_exec_observations.append({'method':method,'pid':pid,'birth':int(birth),'native_stdio_cwd_environment_terminal_preserved':True,'native_stream':True})
            snapshot=next_image
        checks.append('unmanaged_root_exec_sequence_native_oracle')
        return snapshot

    def observed_identity(value):
        identity_keys=['pid','birth','owner','uid','executable','executable_sha256','incarnation','instance_id','role_epoch','exec_epoch']
        if isinstance(value,dict):return {key:value[key] for key in identity_keys if key in value}
        if isinstance(value,list):return [observed_identity(item) for item in value]
        return value

    def phase_observation(attachment_id, allowed, record):
        observation={'observed_at_unix_ns':time.time_ns(),'attachment_id':attachment_id,'allowed':list(allowed),'record_present':record is not None}
        if record is not None:
            observation.update({
                'phase':record.get('phase'),
                'error':record.get('error') or record.get('last_error'),
                'compatibility_reasons':record.get('compatibility_reasons'),
                'manager':observed_identity(record.get('manager')),
                'manager_identity':observed_identity(record.get('manager_identity')),
                'members':observed_identity(record.get('members')),
                'current_target':observed_identity(record.get('current_target')),
                'pending_injection':record.get('pending_injection'),
            })
        return observation

    def phase(attachment_id, allowed, transient=()):
        deadline=time.monotonic()+30
        last_signature=None
        last_observation=None
        while time.monotonic()<deadline:
            status=json.loads(run(['status','--json'],record=False))
            records=status.get('attachments',[])
            record=next((record for record in records if record['spec']['id']==attachment_id),None)
            current=phase_observation(attachment_id,allowed,record)
            signature=json.dumps({key:value for key,value in current.items() if key!='observed_at_unix_ns'},sort_keys=True)
            if signature!=last_signature:
                phase_observations.append(current)
                last_signature=signature
            last_observation=current
            if record and record['phase'] in allowed:
                return record
            if record and phase_is_terminal_failure(record['phase'], transient):
                raise AssertionError(('attachment operation failed',record,current))
            time.sleep(0.05)
        raise AssertionError(('attachment did not reach expected phase',attachment_id,allowed,last_observation))

    def thread_details(pid):
        details=[]
        try:tasks=list(Path(f'/proc/{pid}/task').iterdir())
        except FileNotFoundError:return details
        for task in tasks:
            try:
                status=(task/'status').read_text()
                details.append({'tid':int(task.name),'comm':(task/'comm').read_text().strip(),'state':re.search(r'^State:\s+(.+)',status,re.M)[1],'wchan':(task/'wchan').read_text().strip()})
            except FileNotFoundError:continue
        return sorted(details,key=lambda entry:entry['tid'])

    def await_control_retirement(attachment_id,pid,requested_at):
        path=Path(env['HYPERHUB_HOME'])/'runtime'/'attachments'/attachment_id/'host-states.json'
        started_wait=time.perf_counter_ns();deadline=time.monotonic()+30;observations=[];last=None
        while True:
            host_state=None
            try:host_state=json.loads(path.read_text())
            except (FileNotFoundError,json.JSONDecodeError):pass
            record=phase(attachment_id,['detached','detached_resident','draining'])
            threads=thread_details(pid)
            current={'host_state':host_state,'record_phase':record['phase'],'record_reasons':record['compatibility_reasons'],'threads':threads}
            signature=json.dumps(current,sort_keys=True)
            if signature!=last:
                item={'observed_at_unix_ns':time.time_ns(),**current}
                if len(observations)<128:observations.append(item)
                else:observations[-1]=item
                last=signature
            control_threads=[entry for entry in threads if entry['comm'].startswith(('hyperhub-engine','hyperhub-sandbo'))]
            if host_state and host_state['sampled_at_unix_ns']>=requested_at and host_state['hosts'] and all(host.get('native_ready') is True and host['phase'] in ['detached','detached_resident','detaching'] and host['control_workers']==0 and host['pending_alias_publications']==0 for host in host_state['hosts']) and not control_threads:
                retirement_observations.append({'attachment_id':attachment_id,'barrier_wait_ns':time.perf_counter_ns()-started_wait,'observations':observations})
                return record,time.perf_counter_ns()-started_wait
            if time.monotonic()>=deadline:
                retirement_observations.append({'attachment_id':attachment_id,'timed_out':True,'observations':observations})
                raise AssertionError(('SDK control workers did not physically retire',current))
            time.sleep(.025)

    try:
        fixture=output/'dynamic-attach-target'
        subprocess.run(['cc','-std=c11','-Wall','-Wextra','-Werror','-pthread','-rdynamic',str(ROOT/'tests/fixtures/dynamic_attach_target.c'),'-ldl','-o',str(fixture)],check=True)
        if args.child_startup_failure:
            source=ROOT/'tests/fixtures/attachment_bind_fault.c'
            fault_shim=output/'attachment-bind-fault.so'
            fault_oracle=output/'attachment-bind-fault-oracle'
            fault_control_path=temporary/'bind-fault-control'
            subprocess.run(['cc','-std=c11','-Wall','-Wextra','-Werror','-fPIC','-shared',str(source),'-o',str(fault_shim)],check=True)
            subprocess.run(['cc','-std=c11','-Wall','-Wextra','-Werror','-DATTACHMENT_BIND_FAULT_ORACLE',str(source),'-o',str(fault_oracle)],check=True)
            native_namespace=temporary/'native-bind-namespace';native_namespace.mkdir(mode=0o700)
            fault_command('--initialize',str(native_namespace)+os.sep)
            fault_command('--enable')
            native_env=env.copy();native_env['LD_PRELOAD']=str(fault_shim);native_env['HH_FIXTURE_BIND_FAULT_FILE']=str(fault_control_path)
            native=subprocess.run([str(fault_oracle),'--oracle',str(fault_control_path),str(temporary/'native-business.sock')],env=native_env,capture_output=True,timeout=10)
            (output/'bind-fault-native.stdout').write_bytes(native.stdout);(output/'bind-fault-native.stderr').write_bytes(native.stderr)
            assert native.returncode==0, ('native-bind-fault-oracle-failed',native.returncode,native.stdout.decode(errors='replace'),native.stderr.decode(errors='replace'))
            fault_native_oracle=json.loads(native.stdout)
            assert fault_native_oracle['status']=='pass' and fault_native_oracle['fifo_native_read'] and fault_native_oracle['fault_hits']>0
            checks.append('source_bind_fault_native_root_child_abstract_business_release_and_fifo_oracle')
            host_namespace=Path(env['XDG_RUNTIME_DIR'])/('hyperhub-attach-'+str(os.geteuid()))
            if len(os.fsencode(host_namespace))>65:host_namespace=Path(env['TMPDIR'])/('hyperhub-attach-'+str(os.geteuid()))
            fault_command('--initialize',str(host_namespace)+os.sep)
        pattern=json.dumps('^'+re.escape(str(secret))+'$')
        config=temporary/'config.toml'
        config.write_text(f'''schema_version = 2
environment_variables = []
[gateway]
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
id = "deny-disposable-secret"
enabled = true
priority = 100
action = "deny"
operations = ["read"]
[[sandbox.file.rules.patterns]]
enabled = true
pattern = {pattern}
''')
        run(['import',str(config),'--admin-password-file',str(password)])
        # Avoid automatic release checks during deterministic loopback tests.
        (Path(env['HYPERHUB_HOME'])/'upgrade-check.json').write_text(json.dumps({'last_check_ms':int(time.time()*1000)}))
        run(['start','--admin-password-file',str(password)])
        target_argv=[str(fixture),str(secret),str(server.server_address[1]),'--dns-port',str(dns.server_address[1])]
        target_env=env.copy()
        target_env.pop('HYPERHUB_ATTACHMENT_DIAGNOSTICS',None)
        target_env.pop('HYPERHUB_FRIDA_DIAGNOSTICS',None)
        if args.child_startup_failure:
            target_env['LD_PRELOAD']=str(fault_shim)
            target_env['HH_FIXTURE_BIND_FAULT_FILE']=str(fault_control_path)
        if args.exec_family_regression:target_env['PATH']=str(output)+os.pathsep+target_env.get('PATH','')
        if args.diagnostic_crash:target_env['HH_TEST_CRASH_REPORT']=str(output/'fixture-crash.bin')
        if args.fixture_child_debugger:target_env['HH_TEST_CHILD_DEBUGGER_OPT_IN']='1'
        if alias_scenario:
            native_route=output/'fixture-native-route.so'
            subprocess.run(['cc','-std=c11','-O2','-Wall','-Wextra','-Werror','-shared','-fPIC',str(ROOT/'tests/fixtures/dynamic_attach_native_route.c'),'-ldl','-o',str(native_route)],check=True)
            target_env['LD_PRELOAD']=str(native_route)
            if args.fake_ip:target_env['HH_TEST_OBSERVED_ALIAS']='1'
        if args.unsupported_negative and args.origin=='run':
            marker=temporary/'target-main-entered'
            run(['run','--backend','gum','--',str(fixture),str(secret),str(server.server_address[1]),'--startup-marker',str(marker)],expected=2)
            error=(output/f'cli-{cli_counter}.stderr').read_text()
            assert 'gum_tree_requires_unrestricted_ptrace' in error or 'gum_injection_permission_unproven' in error, error
            assert not marker.exists(), 'unsupported Gum run executed target main'
            assert not json.loads(run(['status','--json']))['attachments']
            checks.append('unsupported_gum_run_rejected_before_target_start')
            write_result({'status':'pass','scenario':'unsupported_gum_run','backend':args.backend,'checks':checks,'commands':commands})
            return
        if args.origin == 'run':
            # The same fixture/backend workload needs its own unmanaged control,
            # rather than calling the already-protected run baseline native.
            target=PtyTarget(target_argv,target_env) if args.target_pty else subprocess.Popen(target_argv,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=target_env,bufsize=0)
            track_target_stdio(target,'unmanaged-control')
            assert select.select([target.stdout],[],[],30)[0]
            unmanaged=read_target_json(target,'unmanaged-ready')
            assert_no_extra_target_stdout(target,'unmanaged-ready')
            assert_target_stderr_empty(target,'unmanaged-ready')
            unmanaged=native_root_execs(unmanaged)
            assert exchange('read')[0]['read_result']==0
            if args.backend=='gum' and not alias_scenario:connect_boundary_oracle=exchange('connect-boundaries')[0]
            measure_window('unmanaged_baseline',unmanaged['pid'])
            target.stdin.write(b'exit\n');target.stdin.flush();finish_target(target,37,30,'unmanaged-control-exit')
            if isinstance(target,PtyTarget):target.close()
            target=None
            target_argv=[str(binary),'run','--backend',args.backend,'--',*target_argv]
        if args.legacy_negative:
            legacy=output/'generic-legacy-instrumentation.so'
            subprocess.run(['rustc','--crate-type','cdylib',str(ROOT/'tests/fixtures/dynamic_attach_legacy_marker.rs'),'-o',str(legacy)],check=True)
            target_env['LD_PRELOAD']=str(legacy)
        launch_env=target_env.copy()
        if args.origin=='run':launch_env['HYPERHUB_ATTACHMENT_DIAGNOSTICS']='1'
        target=PtyTarget(target_argv,launch_env) if args.target_pty else subprocess.Popen(target_argv,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=launch_env,bufsize=0)
        track_target_stdio(target,'managed-target')
        assert select.select([target.stdout],[],[],30)[0], 'fixture did not become ready'
        baseline=read_target_json(target,'managed-ready')
        assert_no_extra_target_stdout(target,'managed-ready')
        assert_target_stderr_empty(target,'managed-ready')
        original_pid=baseline['pid']
        if args.origin == 'attach':assert original_pid==target.pid
        assert baseline['stable_stdio_cwd'] and baseline['stable_environment'] and baseline['stable_terminal']
        assert baseline['has_terminal']==args.target_pty
        if args.origin=='attach':baseline=native_root_execs(baseline)
        baseline_latencies=[exchange('snapshot')[1] for _ in range(10)]
        measure_window('unmanaged_baseline' if args.origin=='attach' else 'same_backend_run_baseline',original_pid)
        if not args.thread_creation_regression:assert exchange('read')[0]['read_result']==(0 if args.origin=='attach' else 13)
        assert exchange('socket')[0]['old_stream']
        checks.append(('unmanaged' if args.origin=='attach' else 'same_backend_run')+'_baseline_and_existing_connection')
        if args.thread_creation_regression:
            thread_samples=[]
            def thread_workload(label,rounds):
                for index in range(rounds):
                    value,_=exchange('allocator-growth')
                    thread_samples.append({'phase':label,'round':index,**value})
                    assert value['allocator_growth_preserved'], ('ordinary-pthread-runtime-failure',label,index,value)
            fork_samples=[]
            def neutral_forks(label,rounds):
                if not args.allocator_fork_regression:return
                for index in range(rounds):
                    if index%4==0:thread_workload(label+'_before_fork_epoch_'+str(index//4),1)
                    value,latency=exchange('fork-exit')
                    fork_samples.append({'phase':label,'round':index,'latency_ns':latency,**value})
                    assert value['neutral_child_result']==0 and value['neutral_fork_errno']==0,('neutral-fork-child-exit',label,index,value)
            thread_workload('native_before',4)
            neutral_forks('native_before',16)
            churn=exchange('start-map-churn')[0]
            assert churn['map_churn_threads']==2 and churn['map_churn_create_error']==0,churn
            proposal=json.loads(run(['attach',str(original_pid),'--scope',args.scope,'--backend',args.backend]))
            accepted_identity(proposal,approve(proposal['request_id']))
            active_record=phase(proposal['attachment_id'],['active'])
            thread_workload('active',32)
            neutral_forks('active',32)
            requested_at=time.time_ns()
            detach_proposal=json.loads(run(['detach',proposal['attachment_id']]))
            if args.allocator_fork_regression:assert detach_proposal.get('action',{}).get('recovery') is None, ('neutral-child-exit-lost-manager',detach_proposal)
            accepted_identity(proposal,approve(detach_proposal['request_id']))
            detached_record=phase(proposal['attachment_id'],['detached','detached_resident','draining'])
            if args.allocator_fork_regression:assert detached_record['manager']==active_record['manager'], ('neutral-child-exit-replaced-manager',active_record,detached_record)
            stopped=exchange('stop-map-churn')[0]
            assert stopped['map_churn_mprotect_errors']==0,('ordinary-anonymous-mprotect-failed',stopped)
            thread_workload('detached',4)
            neutral_forks('detached',32)
            if args.backend=='gum':await_control_retirement(proposal['attachment_id'],original_pid,requested_at)
            target.stdin.write(b'exit\n');target.stdin.flush();finish_target(target,37,30,'thread-regression-exit')
            write_result({'status':'pass','backend':args.backend,'scenario':'allocator_fork_continuation' if args.allocator_fork_regression else 'ordinary_thread_creation','samples':thread_samples,'fork_samples':fork_samples,'checks':['native_pthread_oracle','concurrent_anonymous_vma_changes','active_pthread_creation_and_allocator_contents','detached_pthread_creation','anonymous_mprotect_no_errors','target_exit37']+(['native_active_detached_libc_child_exit_and_parent_reap','repeated_cold_thread_epochs_before_neutral_fork'] if args.allocator_fork_regression else []),'commands':commands})
            return
        if args.mapping_regression:
            assert exchange('allocator-growth')[0]['allocator_growth_preserved']
            assert exchange('prepare-mapping')[0]['mapping_prepared']
            assert exchange('probe-mapping')[0]['mapping_result']==0
            pressure=exchange('probe-mapping-pressure')[0]
            assert pressure['fd_pressure'] and pressure['mapping_result']==0, ('native-mapping-pressure-oracle',pressure)
            checks.append('native_allocator_and_preexisting_closed_fd_mapping_oracle')
        if args.backend=='gum' and not alias_scenario and args.origin=='attach':connect_boundary_oracle=exchange('connect-boundaries')[0]
        if args.unsupported_negative:
            before=exchange('snapshot')[0]
            run(['attach',str(original_pid),'--scope',args.scope,'--backend','gum'],expected=2)
            error=(output/f'cli-{cli_counter}.stderr').read_text()
            assert any(marker in error for marker in ['gum_tree_requires_unrestricted_ptrace','gum_injection_permission_unproven','gum_requires_unrestricted_ptrace']), error
            assert not json.loads(run(['status','--json']))['attachments'], 'unsupported proposal created a runtime attachment'
            after=exchange('snapshot')[0]
            for key in ['pid','fd_count','thread_count','native_mappings','stable_stdio_cwd','stable_environment','stable_terminal']:assert after[key]==before[key], ('unsupported-target-mutated',key,before,after)
            assert re.search(r'^TracerPid:\s+0$',Path(f'/proc/{original_pid}/status').read_text(),re.M)
            for command,key in [('fork-read','child_result'),('exec-read','child_result'),('vfork-read','vfork_child_result')]:assert exchange(command)[0][key]==0, ('native-child-after-refusal',command)
            assert exchange('read')[0]['read_result']==0 and exchange('socket')[0]['old_stream']
            assert exchange('signal-check')[0]['signal_delivery_and_mask_preserved']
            checks.append('unsupported_gum_'+args.scope+'_rejected_before_mutation_and_native_children_survive')
            automatic=json.loads(run(['attach',str(original_pid),'--scope',args.scope]))
            yama_mode=Path('/proc/sys/kernel/yama/ptrace_scope').read_text().strip()
            accepted_identity(automatic,approve(automatic['request_id'],expected=0 if yama_mode=='1' else None))
            auto_record=phase(automatic['attachment_id'],['active','failed','cleanup_pending','degraded'])
            assert auto_record['spec']['backend']=='ptrace'
            if auto_record['phase']=='active':
                assert yama_mode!='3', 'Yama no-attach mode unexpectedly admitted a new tracer'
                assert exchange('read')[0]['read_result']==13
                removal=json.loads(run(['detach',automatic['attachment_id']]));approve(removal['request_id']);phase(automatic['attachment_id'],['detached'])
                assert exchange('read')[0]['read_result']==0 and exchange('fork-read')[0]['child_result']==0
                checks.append('automatic_backend_uses_reversible_ptrace_under_restricted_yama')
            else:
                assert yama_mode in ['2','3'], ('mode1-auto-ptrace-regressed',auto_record)
                refusal=json.dumps(auto_record).lower()
                assert any(reason in refusal for reason in ['operation not permitted','permission denied','os error 1','os error 13']), ('auto-refusal-was-not-kernel-permission',auto_record)
                assert re.search(r'^TracerPid:\s+0$',Path(f'/proc/{original_pid}/status').read_text(),re.M)
                native=exchange('snapshot')[0]
                for key in ['pid','fd_count','thread_count','native_mappings','stable_stdio_cwd','stable_environment','stable_terminal']:assert native[key]==before[key], ('auto-permission-refusal-mutated-target',key,before,native)
                assert exchange('read')[0]['read_result']==0 and exchange('socket')[0]['old_stream']
                for command,key in [('fork-read','child_result'),('exec-read','child_result'),('vfork-read','vfork_child_result')]:assert exchange(command)[0][key]==0, ('native-child-after-auto-permission-refusal',command)
                checks.append('automatic_ptrace_kernel_permission_refusal_preserves_native_target')
            target.stdin.write(b'exit\n');target.stdin.flush();finish_target(target,37,30,'unsupported-negative-exit')
            write_result({'status':'pass','scenario':'unsupported_gum_'+args.scope,'scope':args.scope,'backend':args.backend,'checks':checks,'commands':commands,'phase_windows':phase_windows})
            return
        if args.child_startup_failure:
            assert fault_state()['root_pid']==original_pid, ('fault-root-identity',fault_state(),original_pid)
            proposal=json.loads(run(['attach',str(original_pid),'--scope','tree','--backend','gum']))
            accepted_identity(proposal,approve(proposal['request_id']))
            active=phase(proposal['attachment_id'],['active'])
            assert exchange('read')[0]['read_result']==13 and exchange('socket')[0]['old_stream']
            assert fault_state()['hits']==0, ('initial-root-bind-was-faulted',fault_state())
            assert fault_state()['root_bind_passes']>0, ('SDK-root-bind-did-not-reach-source-shim',fault_state())
            fault_command('--enable')
            initial=exchange('busy-fork-start')[0]
            assert initial['busy_workers']==1
            deadline=time.monotonic()+30
            while fault_state()['hits']==0:
                sample=exchange('busy-fork-stats')[0]
                assert sample['busy_completed']==0 and sample['busy_errors']==0, ('future-child-returned-without-reaching-selected-bind-shim',sample,fault_state())
                assert time.monotonic()<deadline, ('SDK-bind-did-not-hit-source-shim',fault_state(),sample)
                time.sleep(.02)
            hit=fault_state();held_since=time.monotonic()
            child_pid=hit['last_pid']
            child_identity=kernel_identity(child_pid)
            assert child_pid!=original_pid and child_identity['owner']==str(os.getuid()) and child_identity['executable_sha256']==hashlib.sha256(fixture.read_bytes()).hexdigest()
            parent_status=Path(f'/proc/{child_pid}/status').read_text()
            assert int(re.search(r'^PPid:\s+(\d+)',parent_status,re.M)[1])==original_pid
            assert hit['last_path'].startswith(hit['prefix']) and hit['path_length']>len(os.fsencode(hit['prefix']))
            exchange('busy-fork-pause')
            # Keep the sole resumed child alive in its existing read_secret()
            # operation while verifying unknown-resource completion is refused.
            secret.unlink();os.mkfifo(secret,0o600);fault_fifo_active=True
            def no_fifo_reader():
                try:writer=os.open(secret,os.O_WRONLY|os.O_NONBLOCK|os.O_CLOEXEC)
                except OSError as error:
                    assert error.errno==errno.ENXIO, ('unexpected-fifo-error',error)
                    return
                os.close(writer)
                raise AssertionError('future child entered application open before approved Detach')
            def held_sample(stage):
                no_fifo_reader()
                stats=exchange('busy-fork-stats')[0]
                snapshot=exchange('snapshot')[0]
                assert stats['busy_completed']==0 and stats['busy_errors']==0 and stats['busy_workers']==1, ('held-child-returned',stage,stats)
                assert kernel_identity(child_pid)==child_identity, ('held-child-incarnation-changed',child_identity)
                assert snapshot['stable_stdio_cwd'] and snapshot['stable_environment'] and snapshot['stable_terminal']
                child_startup_observations.append({'stage':stage,'elapsed_from_fault_seconds':time.monotonic()-held_since,'busy':stats,'progress':snapshot['progress'],'child_pid':child_pid,'fault':fault_state()})
                return snapshot
            first=held_sample('fault_enabled')
            while time.monotonic()-held_since<12.25:
                held_sample('fault_enabled');time.sleep(.2)
            before_clear=held_sample('past_original_ten_second_deadline')
            assert before_clear['progress']>first['progress']
            assert exchange('read')[0]['read_result']==13, 'child startup failure silently disabled parent policy'
            checks.append('active_future_child_bind_fault_holds_application_past_twelve_seconds_and_parent_progresses')
            fault_command('--disable')
            clear_since=time.monotonic()
            while time.monotonic()-clear_since<2.25:
                held_sample('fault_cleared_without_detach');time.sleep(.2)
            checks.append('removing_bind_fault_alone_does_not_release_protected_child')
            removal=json.loads(run(['detach',proposal['attachment_id']]))
            assert removal.get('request_id') and removal.get('status')!='already_detached', ('missing-new-detach-approval',removal)
            approved=approve(removal['request_id'],expected=None)
            assert approved is not None and approved['status'] in ['approved','execution_pending'], ('new-detach-not-accepted',approved)
            accepted_identity(proposal,approved)
            deadline=time.monotonic()+30
            while fault_fifo_writer is None:
                assert kernel_identity(child_pid)==child_identity
                try:fault_fifo_writer=os.open(secret,os.O_WRONLY|os.O_NONBLOCK|os.O_CLOEXEC)
                except OSError as error:
                    assert error.errno==errno.ENXIO
                    assert time.monotonic()<deadline, ('approved-detach-did-not-release-application-fork',fault_state())
                    time.sleep(.02)
            # An open writer proves the original thread passed its fork gate.
            # No S byte is sent yet, so this exact child stays alive for Core's
            # Resident/Pending proof and cannot be erased as a dead member.
            reader_deadline=time.monotonic()+2
            while True:
                reader_fds=[]
                for descriptor in Path(f'/proc/{child_pid}/fd').iterdir():
                    try:
                        metadata=descriptor.stat()
                        if metadata.st_dev==secret.stat().st_dev and metadata.st_ino==secret.stat().st_ino:reader_fds.append(int(descriptor.name))
                    except FileNotFoundError:pass
                if reader_fds:break
                assert time.monotonic()<reader_deadline, 'FIFO writer connected without the sole fixture child reader'
                time.sleep(.01)
            pending=phase(proposal['attachment_id'],['cleanup_pending','detached_resident','draining','detaching'])
            pending_since=time.monotonic()
            completion_observations=[]
            while time.monotonic()-pending_since<2:
                public=json.loads(run(['status','--json'],record=False))
                pending=next(record for record in public['attachments'] if record['spec']['id']==proposal['attachment_id'])
                assert pending['phase'] in ['cleanup_pending','detached_resident','draining','detaching'], ('live-unknown-child-falsely-completed',pending)
                assert any(session.get('session_id')==active['session_id'] for session in public.get('sessions',[])), ('unknown-child-session-falsely-revoked',pending,public)
                proofs=[str(path) for directory in Path(env['HYPERHUB_HOME']).rglob('completion-proofs') for path in (directory/proposal['attachment_id']).glob('*') if path.is_file()]
                assert not proofs, ('live-unknown-child-has-full-completion-proof',proofs)
                assert kernel_identity(child_pid)==child_identity
                snapshot=exchange('snapshot')[0]
                assert snapshot['progress']>before_clear['progress'] and snapshot['stable_stdio_cwd'] and snapshot['stable_environment'] and snapshot['stable_terminal']
                assert exchange('socket')[0]['old_stream']
                completion_observations.append({'phase':pending['phase'],'reasons':pending['compatibility_reasons'],'progress':snapshot['progress'],'completion_proofs':proofs})
                time.sleep(.2)
            checks.append('new_detach_releases_only_original_child_and_keeps_live_unknown_runtime_resident_pending')
            assert os.write(fault_fifo_writer,b'S')==1
            os.close(fault_fifo_writer);fault_fifo_writer=None
            completed=exchange('busy-fork-stop')[0]
            assert completed['busy_workers']==1 and completed['busy_completed']==1 and completed['busy_errors']==0, ('native-only-child-read-or-parent-join-failed',completed)
            # read_secret returns 13 only when open fails; the witnessed FIFO
            # reader excludes that branch. errors==0 excludes a bad S/EOF read.
            native_read={'result':0,'evidence':'sole child FIFO reader, S byte, completed busy waitpid with no invalid exit','reader_fds':reader_fds,'busy':completed}
            secret.unlink();secret.write_text('S\n');secret.chmod(0o600);fault_fifo_active=False
            checks.append('cancelled_child_reads_native_S_and_busy_worker_joins_without_error')
            assert exchange('snapshot')[0]['progress']>baseline['progress']
            target.stdin.write(b'exit\n');target.stdin.flush();finish_target(target,37,30,'child-startup-failure-exit')
            checks.append('original_parent_stdio_progress_and_exit37_preserved')
            write_result({'status':'pass','scenario':'child_startup_failure','origin':args.origin,'backend':args.backend,'scope':args.scope,'checks':checks,'native_oracle':fault_native_oracle,'fault_hits':hit,'child_identity':child_identity,'held_samples':child_startup_observations,'approval':approved,'native_read':native_read,'unknown_resource_observations':completion_observations,'commands':commands})
            return
        if args.busy_preparation:
            busy_samples=[]
            busy_start='busy-fork-start-two' if args.busy_fork_workers==2 else 'busy-fork-start'
            def check_busy_totals(sample):
                assert sample['busy_workers']==args.busy_fork_workers, ('busy-worker-count',sample)
                assert sample['busy_completed']==sum(sample['busy_worker_completed']), ('busy-completed-accounting',sample)
                assert sample['busy_marked']==sum(sample['busy_worker_marked']), ('busy-marked-accounting',sample)
            def busy_until(field,minimum):
                deadline=time.monotonic()+30
                while True:
                    sample=exchange('busy-fork-stats')[0]
                    assert sample['busy_errors']==0, ('busy-child-crash-or-fork-error',sample)
                    worker_field={'busy_completed':'busy_worker_completed','busy_marked':'busy_worker_marked'}[field]
                    assert sample['busy_workers']==args.busy_fork_workers and len(sample[worker_field])==args.busy_fork_workers, ('busy-worker-count',sample)
                    if min(sample[worker_field])>=minimum:return sample
                    assert time.monotonic()<deadline, ('busy-fork-made-no-progress',field,minimum,sample)
                    time.sleep(.005)
            exchange(busy_start);exchange('busy-fork-mark');busy_until('busy_marked',3)
            oracle=exchange('busy-fork-stop')[0]
            check_busy_totals(oracle)
            assert oracle['busy_allowed']==oracle['busy_marked'] and oracle['busy_denied']==0 and oracle['busy_errors']==0, ('busy-native-oracle',oracle)
            checks.append('busy_fork_native_source_oracle')
            for busy_cycle in range(args.cycles):
                exchange(busy_start);busy_until('busy_completed',3)
                proposal=json.loads(run(['attach',str(original_pid),'--scope','tree','--backend','gum']))
                accepted_identity(proposal,approve(proposal['request_id'],expected=None))
                settled=phase(proposal['attachment_id'],['active','cleanup_pending','failed','degraded'])
                if settled['phase']=='active':
                    exchange('busy-fork-mark');busy_until('busy_marked',3)
                    sample=exchange('busy-fork-stop')[0]
                    assert sample['busy_marked']>=3 and sample['busy_denied']==sample['busy_marked'] and sample['busy_allowed']==0 and sample['busy_errors']==0, ('active-busy-child-bypass',busy_cycle,sample)
                    checks.append('busy_active_descendants_enforced_epoch_'+str(busy_cycle))
                else:
                    reason=json.dumps(settled).lower()
                    assert any(marker in reason for marker in ['prepar','activation_busy','capture','changed during gum injection','changed image']), ('unrelated-busy-preparation-failure',settled)
                    exchange('busy-fork-pause')
                    sample=None
                removal=json.loads(run(['detach',proposal['attachment_id']]))
                if settled['phase']=='failed':
                    assert removal.get('status')=='already_detached' and removal.get('preparation_rollback')=='verified', ('failed-display-without-trusted-preparation-rollback',removal,settled)
                    assert not removal.get('request_id'), ('verified-pre-mutation-rollback-created-unnecessary-recovery',removal)
                    rolled_back_status=json.loads(run(['status','--json']))
                    assert not any(session.get('session_id')==settled['session_id'] for session in rolled_back_status.get('sessions',[])), ('verified-pre-mutation-rollback-retained-session',rolled_back_status)
                    checks.append('busy_initial_capture_refusal_has_verified_rollback_without_recovery_file_epoch_'+str(busy_cycle))
                else:
                    approve(removal['request_id'])
                    # The synchronous approval reply proves that the live manager
                    # accepted Detach, but its previous cleanup round can still
                    # have a CleanupPending publication in flight. Only this
                    # post-approval wait treats that phase as transitional.
                    phase(
                        proposal['attachment_id'],
                        ['detached','detached_resident'],
                        transient=['cleanup_pending'],
                    )
                if sample is None:sample=exchange('busy-fork-stop')[0]
                check_busy_totals(sample)
                assert sample['busy_errors']==0, ('preparation-refusal-crashed-a-child',sample)
                assert exchange('read')[0]['read_result']==0 and exchange('fork-read')[0]['child_result']==0
                assert exchange('socket')[0]['old_stream']
                current=exchange('snapshot')[0]
                for key in ['pid','stable_stdio_cwd','stable_environment','stable_terminal']:assert current[key]==baseline[key], ('busy-preparation-target-mutated',key,current)
                busy_samples.append({'cycle':busy_cycle,'settled_phase':settled['phase'],'children':sample})
                checks.append('busy_preparation_approved_cleanup_preserves_native_target_epoch_'+str(busy_cycle))
            target.stdin.write(b'exit\n');target.stdin.flush();finish_target(target,37,30,'busy-preparation-exit')
            write_result({'status':'pass','scenario':'busy_preparation','busy_fork_workers':args.busy_fork_workers,'origin':args.origin,'backend':args.backend,'checks':checks,'native_oracle':oracle,'busy_samples':busy_samples,'commands':commands,'diagnostic_controls':{'manager_host_states':True,'manager_frida_stages_and_fd_metadata':args.manager_frida_diagnostics}})
            return
        if args.fake_ip and args.origin=='attach':
            assert exchange('cache-fake-name')[0]['cached_fake_alias']
            native_oracle=exchange('cached-connect')[0]
            assert native_oracle['cached_alias_stream'] and native_oracle['cached_alias_native_peer'], ('observed-alias-native-oracle',native_oracle)
            checks.append('observed_alias_preexisting_native_route_verified_before_attach')
        if args.legacy_negative:
            proposal=json.loads(run(['attach',str(original_pid),'--scope',args.scope,'--backend',args.backend]))
            approve(proposal['request_id'],expected=2)
            status=json.loads(run(['status','--json']))
            record=next(record for record in status['attachments'] if record['spec']['id']==proposal['attachment_id'])
            assert record['phase'] in ['failed','cleanup_pending'], record
            assert 'incompatible' in str(record).lower() or 'overlapping' in str(record).lower(), record
            assert exchange('read')[0]['read_result']==0
            assert exchange('socket')[0]['old_stream']
            assert exchange('snapshot')[0]['stable_terminal']
            target.stdin.write(b'exit\n');target.stdin.flush()
            finish_target(target,37,30,'legacy-negative-exit')
            checks.append('intrinsic_loaded_legacy_abi_rejected_without_mutation')
            write_result({'status':'pass','backend':args.backend,'checks':checks,'commands':commands})
            return
        started=time.monotonic()
        cycle=0
        workload_count=0
        workload_latencies=[]
        resources_after_warmup=None
        next_extra_cycle=started
        while cycle<args.cycles or time.monotonic()-started<args.duration:
            # After the required cycles, measure real active work and admit at
            # most one additional approval cycle per minute. Do not equate
            # waiting or failed attempts with completed throughput.
            if cycle>=args.cycles and time.monotonic()<next_extra_cycle:
                soak_window('detached',min(started+args.duration,next_extra_cycle),0)
                continue
            attach_started=time.perf_counter_ns()
            if args.origin=='run' and cycle==0:
                records=json.loads(run(['status','--json']))['attachments']
                owned=next(record for record in records if record['spec']['target']['pid']==original_pid and record['origin']=='run')
                proposal={'attachment_id':owned['spec']['id']}
                checks.append('owned_run_registered_before_target_progress')
            else:
                record_fixture_fds('before_attach_cycle_'+str(cycle),original_pid)
                proposal=json.loads(run(['attach',str(original_pid),'--scope',args.scope,'--backend',args.backend]))
                assert proposal['status']=='approval_required'
                assert exchange('read')[0]['read_result']==0, 'proposal changed target before approval'
                accepted_identity(proposal,approve(proposal['request_id']))
            active=phase(proposal['attachment_id'],['active'])
            record_fixture_fds('active_cycle_'+str(cycle),original_pid)
            assert exchange('read')[0]['read_result']==13, 'managed read bypassed deny policy'
            if args.root_self_exec:
                previous_epoch=active['exec_epoch']
                expected_current=active.get('current_target') or active['spec']['target']
                if cycle>0:
                    prior=root_exec_observations[-1]
                    if proposal['attachment_id']==prior['attachment_id']:
                        assert previous_epoch==prior['exec_epoch'], ('resident-reattach-reset-root-exec-epoch',active,prior)
                    else:
                        assert previous_epoch==0 and active['spec']['target']==prior['current_target'], ('fresh-attachment-did-not-bind-current-image-at-initial-epoch',active,prior)
            if args.mapping_regression:
                allocator=exchange('allocator-growth')[0]
                assert allocator['allocator_growth_preserved'], ('allocator-growth-failed',allocator)
                mapped=exchange('probe-mapping')[0]
                assert mapped['mapping_result']==13, ('protected-file-mprotect-bypass',args.mapping_regression,mapped)
                pressure=exchange('probe-mapping-pressure')[0]
                assert pressure['fd_pressure'] and pressure['mapping_result']==13, ('protected-file-mprotect-fd-pressure-bypass',pressure)
                if cycle==0:checks.append('allocator_growth_and_file_mprotect_deny_under_fd_pressure_'+args.mapping_regression)
            if cycle==0 and args.root_self_exec:
                if args.exec_family_regression:exec_errors('active_initial')
                initial_spec=json.loads(json.dumps(active['spec']))
                previous_epoch=active['exec_epoch']
                expected_current=active.get('current_target') or active['spec']['target']
                for method in args.root_exec_methods or ['path']:
                    null_arguments=method.endswith('-nullargv')
                    if null_arguments:
                        # A missing argv snapshot must deny here. A valid NULL
                        # argv must instead reach the normal executable policy.
                        policy_patch=temporary/'null-argv-process-policy.json'
                        policy_patch.write_text(json.dumps([{'op':'replace','path':'/sandbox/process/enabled','value':True},{'op':'replace','path':'/sandbox/process/error_action','value':'deny'}]));policy_patch.chmod(0o600)
                        approve(None,config_plan=json.loads(run(['config','patch',str(policy_patch)])))
                    stale=json.loads(run(['detach',proposal['attachment_id']]))
                    assert stale['attachment_id']==proposal['attachment_id'] and stale['action']['exec_epoch']==previous_epoch, ('pending-detach-did-not-bind-pre-exec-epoch',stale,previous_epoch)
                    next_image=exchange(EXEC_COMMANDS[method])[0]
                    assert next_image['pid']==original_pid, ('self-exec-changed-root-pid',method,next_image)
                    assert next_image['null_argv_image']==null_arguments, ('null-argv-did-not-reach-new-image',method,next_image)
                    for key in ['stable_stdio_cwd','stable_environment','has_terminal','stable_terminal']:assert next_image[key]==baseline[key], ('self-exec-changed-native-behavior',method,key,next_image)
                    # This is the first postexec policy probe. Never retry a
                    # successful native read while waiting for eventual policy.
                    assert exchange('read')[0]['read_result']==13, ('approved-root-self-exec-lost-policy',method,next_image)
                    observed=phase(proposal['attachment_id'],['active'])
                    current=observed.get('current_target') or observed['spec']['target']
                    assert observed['spec']==initial_spec, ('exec-rewrote-immutable-approval-spec',observed)
                    kernel_current=kernel_identity(original_pid)
                    assert current==kernel_current and all(current[key]==expected_current[key]for key in ['pid','birth','owner','executable_sha256']), ('same-image-exec-current-record-mismatches-kernel',method,current,kernel_current,expected_current)
                    expected_current=current
                    assert observed['exec_epoch']==previous_epoch+1, ('exec-did-not-advance-exactly-one-trusted-epoch',method,previous_epoch,observed)
                    approve(stale['request_id'],expected=2,stale_exec=True)
                    still_active=phase(proposal['attachment_id'],['active'])
                    assert still_active['exec_epoch']==observed['exec_epoch'] and still_active['spec']==initial_spec, ('stale-approval-mutated-current-root',still_active)
                    assert exchange('read')[0]['read_result']==13 and exchange('snapshot')[0]['pid']==original_pid, 'stale exec approval altered live policy or target'
                    root_exec_observations.append({'method':method,'attachment_id':proposal['attachment_id'],'previous_exec_epoch':previous_epoch,'exec_epoch':observed['exec_epoch'],'immutable_target':initial_spec['target'],'current_target':current,'rejected_stale_request_id':stale['request_id']})
                    previous_epoch=observed['exec_epoch'];baseline=next_image
                    record_fixture_fds('after_exec_'+str(previous_epoch)+'_'+method,original_pid)
                    if null_arguments:
                        policy_patch.write_text(json.dumps([{'op':'replace','path':'/sandbox/process/enabled','value':False},{'op':'replace','path':'/sandbox/process/error_action','value':'allow'}]))
                        approve(None,config_plan=json.loads(run(['config','patch',str(policy_patch)])))
                        checks.append('valid_'+method+'_new_image_under_process_error_deny')
                    if args.exec_family_regression:exec_errors('active_after_'+method)
                checks.append('approved_original_root_self_exec_preserves_identity_terminal_and_policy')
                checks.append('every_root_exec_advances_epoch_and_rejects_prior_pending_detach')
                if args.exec_family_regression:
                    for command in ['fexecve-read','execveat-read']:
                        child=exchange(command)[0]
                        assert child['child_result']==(13 if args.scope=='tree' else 0), ('fd-exec-child-scope-policy',command,args.scope,child)
                    checks.append('standard_fd_exec_preserves_child_scope_policy')
            ordinary_result=exchange('read-other')[0]
            assert ordinary_result['other_read_result']==(0 if cycle==0 else 13), ('first-reattach-policy',cycle,ordinary_result)
            assert exchange('socket')[0]['old_stream'], 'existing TCP stream was replaced or broken'
            assert exchange('new-socket')[0]['new_stream']
            if cycle>0:
                for command,key in [('fork-read','child_result'),('exec-read','child_result'),('vfork-read','vfork_child_result')]:
                    result=exchange(command)[0]
                    assert result[key]==(13 if args.scope=='tree' else 0), ('reattached-child-policy',cycle,command,result,args.scope)
                checks.append('reattached_epoch_fork_exec_and_vfork_policy')
            if cycle==0:measure_window('active',original_pid)
            if alias_scenario:
                if cycle==0:
                    if args.cross_producer_issued:
                        assert exchange('existing-child-read')[0]['existing_child_result']==13
                        producer=exchange('producer-issued-address')[0]
                        assert producer['producer_result']==0 and producer['parent_did_not_resolve_name'], producer
                        handle=os.pidfd_open(producer['producer_pid'])
                        try:
                            exited=exchange('producer-exit')[0]
                            assert exited['producer_exit_code']==0 and exited['producer_pid']==producer['producer_pid'], exited
                            assert select.select([handle],[],[],10)[0], 'issuer did not actually exit'
                        finally:os.close(handle)
                        checks.append('existing_child_issues_alias_parent_only_consumes_sockaddr_and_issuer_really_exits')
                    else:assert exchange('cache-issued-name' if args.issued_fake_ip else 'cache-fake-name')[0]['cached_fake_alias']
                assert exchange('cached-connect')[0]['cached_alias_stream'], 'cached FAKE-IP failed under active/re-attached policy'
                if cycle==1 and args.alias_serve_offline and args.issued_fake_ip:
                    second_alias=exchange('cache-second-issued-name')[0]
                    assert second_alias['distinct_second_issued_alias'], ('restored-alias-allocator-reused-cached-address',second_alias)
                    assert exchange('second-cached-connect')[0]['second_alias_stream']
                    assert exchange('cached-connect')[0]['cached_alias_stream']
                    checks.append('fresh_reattach_restores_issued_alias_allocator_without_reusing_cached_address')
                if cycle==0 and args.inherited_issued and args.scope=='process':
                    for command in ['fork-cached-connect','fork-cached-connect-nonblocking','double-fork-cached-connect','double-fork-cached-connect-nonblocking']:
                        inherited=exchange(command)[0]
                        assert inherited['cached_alias_child_result']==0, ('process-scope-inherited-issued-alias-native-only',command,inherited)
                    checks.append('process_scope_child_and_grandchild_inherit_native_only_issued_aliases')
                    collision=exchange('fork-alias-collision')[0]
                    assert collision['alias_collision_child_result']==0, ('unmanaged-child-dns-alias-collision',collision)
                    assert exchange('cached-connect')[0]['cached_alias_stream'], 'child collision modified parent alias'
                    checks.append('unmanaged_child_dns_alias_collision_is_rejected_without_parent_retarget')
            if cycle>=args.cycles:
                active_until=min(started+args.duration,time.monotonic()+30)
                soak_window('active',active_until,13)
            if cycle==0:
                assert exchange('preopened-socket')[0]['preopened_nonblocking_preserved']
                checks.append('preexisting_unconnected_nonblocking_socket')
                if not args.cross_producer_issued:assert exchange('existing-child-read')[0]['existing_child_result']==(13 if args.scope=='tree' else 0)
                thread_result=exchange('thread-read')[0]
                assert thread_result['thread_read_result']==13, ('new-thread-policy',thread_result)
                assert exchange('signal-check')[0]['signal_delivery_and_mask_preserved']
                fork_result=exchange('fork-read')[0]
                assert fork_result['child_result']==(13 if args.scope=='tree' else 0), ('fork-read',fork_result,args.scope)
                exec_result=exchange('exec-read')[0]
                assert exec_result['child_result']==(13 if args.scope=='tree' else 0), ('exec-read',exec_result,args.scope)
                vfork_result=exchange('vfork-read')[0]
                assert vfork_result['vfork_child_result']==(13 if args.scope=='tree' else 0), ('vfork-read',vfork_result,args.scope)
                checks.append('thread_creation_signal_delivery_child_atfork_mask_and_vfork_exec')
                assert exchange('exec-env')[0]['child_environment_result']==0
                assert exchange('spawn-env')[0]['child_environment_result']==0
                checks.append('existing_and_future_child_policy')
                checks.append('explicit_child_exec_and_spawn_environment_preserved')
                if args.backend=='gum' and args.scope=='process' and not alias_scenario:
                    boundaries=exchange('fork-connect-boundaries')[0]
                    assert boundaries==connect_boundary_oracle, ('unmanaged-connect-native-errno-oracle',connect_boundary_oracle,boundaries)
                    checks.append('unmanaged_child_connect_bad_pointer_length_alignment_and_fd_match_native')
                patch=temporary/'hot-update.json'
                patch.write_text(json.dumps([{'op':'replace','path':'/gateway/debug','value':True}]))
                patch.chmod(0o600)
                plan=json.loads(run(['config','patch',str(patch)]))
                assert plan['status']=='approval_required'
                approve(None,config_plan=plan)
                assert exchange('read')[0]['read_result']==13
                checks.append('config_hot_update_before_detach')
                if alias_scenario:
                    network_patch=temporary/'deny-new-gateway-connections.json'
                    network_patch.write_text(json.dumps([{'op':'replace','path':'/gateway/routing/default/decision/action','value':'deny'}]));network_patch.chmod(0o600)
                    network_plan=json.loads(run(['config','patch',str(network_patch)]))
                    assert network_plan['status']=='approval_required'
                    approve(None,config_plan=network_plan)
                    denied_alias=exchange('cached-connect')[0]
                    assert not denied_alias['cached_alias_stream'], ('active-alias-must-follow-tightened-policy',denied_alias)
                    with socket.create_connection(server.server_address,timeout=5) as oracle:
                        oracle.sendall(b'F');assert oracle.recv(1)==b'F'
                    checks.append('native_oracle_allows_while_active_gateway_policy_denies_new_alias_connection')
                if args.serve_restart:
                    before=json.loads(run(['status','--json']))
                    session=next(record['session_id'] for record in before['attachments'] if record['spec']['id']==proposal['attachment_id'])
                    replacement=run(['restart','--admin-password-file',str(password)])
                    assert b'serve replaced by successor (pid ' in replacement, ('restart-did-not-use-controlled-successor',replacement)
                    assert exchange('read')[0]['read_result']==13
                    assert exchange('socket')[0]['old_stream']
                    if alias_scenario:assert not exchange('cached-connect')[0]['cached_alias_stream']
                    after=json.loads(run(['status','--json']))
                    assert after['pid']!=before['pid'], ('successor-pid-did-not-change',before['pid'],after['pid'])
                    assert after['approval_trust']==before['approval_trust'], ('successor-lost-approval-memory',before['approval_trust'],after['approval_trust'])
                    before_record=next(record for record in before['attachments'] if record['spec']['id']==proposal['attachment_id'])
                    after_record=next(record for record in after['attachments'] if record['spec']['id']==proposal['attachment_id'])
                    for key in ['exec_epoch','current_target']:
                        assert after_record.get(key)==before_record.get(key), ('successor-lost-root-image',key,before_record,after_record)
                    assert next(record['session_id'] for record in after['attachments'] if record['spec']['id']==proposal['attachment_id'])==session
                    checks.append('controlled_child_successor_preserves_approval_root_epoch_session_cached_policy_and_original_direct_stream')
                if args.manager_loss!='none':
                    if args.manager_loss=='dirty':assert exchange('idle-socket')[0]['idle_nonblocking_created']
                    record=phase(proposal['attachment_id'],['active'])
                    manager=record['manager']
                    status=Path(f"/proc/{manager['pid']}/stat").read_text().rsplit(') ',1)[1].split()
                    assert int(status[19])==manager['birth'], 'manager PID identity changed before disposable fault'
                    handle=os.pidfd_open(manager['pid'])
                    signal.pidfd_send_signal(handle,signal.SIGKILL)
                    assert select.select([handle],[],[],10)[0];os.close(handle)
                    assert exchange('socket')[0]['old_stream']
                    assert exchange('read')[0]['read_result']==(0 if args.backend=='ptrace' else 13)
                    # status reconciles OS liveness; there is no timer-as-proof.
                    degraded=json.loads(run(['status','--json']))
                    lost=next(item for item in degraded['attachments'] if item['spec']['id']==proposal['attachment_id'])
                    assert lost['phase']=='degraded', lost
                    recovery=json.loads(run(['attach',str(original_pid),'--scope',args.scope,'--backend',args.backend]))
                    assert recovery['attachment_id']==proposal['attachment_id']
                    recovery_result=approve(recovery['request_id'],expected=None if args.manager_loss=='dirty' else 0)
                    accepted_identity(recovery,recovery_result)
                    if recovery_result is not None:proposal['attachment_id']=recovery['attachment_id']
                    if args.manager_loss=='dirty':
                        deadline=time.monotonic()+30
                        while True:
                            refusal=phase(proposal['attachment_id'],['degraded','cleanup_pending'])
                            if 'unproven' in str(refusal).lower() or time.monotonic()>=deadline:break
                            time.sleep(.05)
                        assert refusal['phase'] in ['degraded','cleanup_pending'] and 'unproven' in str(refusal).lower(), refusal
                        trace=Path(f'/proc/{original_pid}/status').read_text()
                        assert re.search(r'^TracerPid:\s+0$',trace,re.M), 'unsafe recovery changed tracer ownership'
                        assert exchange('read')[0]['read_result']==0
                        assert not exchange('idle-flags')[0]['idle_native_nonblocking'], 'fixture did not reach the intended lost virtual-flag state'
                        checks.append('dirty_virtual_descriptor_crash_recovery_explicitly_refused')
                        target.stdin.write(b'exit\n');target.stdin.flush();finish_target(target,37,30,'unsafe-recovery-refusal-exit')
                        write_result({'status':'pass','scenario':'unsafe_recovery_refusal','backend':args.backend,'checks':checks,'phase_windows':phase_windows,'commands':commands})
                        return
                    phase(proposal['attachment_id'],['active'])
                    assert exchange('read')[0]['read_result']==13
                    assert exchange('socket')[0]['old_stream']
                    fork_result=exchange('fork-read')[0]
                    assert fork_result['child_result']==(13 if args.scope=='tree' else 0), ('fork-read',fork_result,args.scope)
                    checks.append('approved_manager_loss_recovery_reuses_session_and_restores_enforcement')
                if args.root_exit:
                    transition,_=exchange('orphan-root')
                    orphan_pid=transition['orphan_pid']
                    orphan_pidfd=os.pidfd_open(orphan_pid)
                    assert target.wait(timeout=10)==37, 'foreground did not promptly return the original root status'
                    baseline=exchange('snapshot')[0]
                    assert baseline['pid']==orphan_pid and baseline['stable_terminal']
                    assert exchange('read')[0]['read_result']==13, 'surviving descendant lost enforcement when root exited'
                    checks.append('original_root_exit_returns_while_descendant_remains_managed')
            assert exchange('idle-socket')[0]['idle_nonblocking_created']
            assert exchange('block')[0]['blocked']
            detach_proposal=json.loads(run(['detach',proposal['attachment_id']]))
            if args.root_self_exec:
                assert detach_proposal['action']['exec_epoch']==previous_epoch and detach_proposal['action']['target']==expected_current, ('fresh-detach-did-not-bind-current-exec-state',detach_proposal,previous_epoch,expected_current)
            assert exchange('read')[0]['read_result']==13, 'detach proposal removed policy before approval'
            detach_started=time.perf_counter_ns()
            detach_requested_at=time.time_ns()
            before_detach_yes=None
            if args.approval_manager_exit:
                manager=active.get('manager')
                assert manager is not None, ('active-attachment-has-no-manager',active)
                manager_pidfd=os.pidfd_open(manager['pid'])
                signal.pidfd_send_signal(manager_pidfd,signal.SIGSTOP)
                stop_deadline=time.monotonic()+5
                while True:
                    status=(Path('/proc')/str(manager['pid'])/'status').read_text()
                    state=re.search(r'^State:\s+(\S)',status,re.M)[1]
                    if state in ['T','t']:break
                    assert time.monotonic()<stop_deadline, ('manager-did-not-stop-before-review',manager,state)
                    time.sleep(.01)
                exit_observation={'manager':manager,'stopped_before_approval':True}
                manager_exit_observations.append(exit_observation)
                (output/'manager-exit-observation.json').write_text(json.dumps(exit_observation,indent=2)+'\n')
                def terminate_manager_after_prompt(manager=manager,pidfd=manager_pidfd,observation=exit_observation):
                    observed=kernel_identity(manager['pid'])
                    assert observed==manager, ('manager-changed-before-review-prompt',manager,observed)
                    try:
                        signal.pidfd_send_signal(pidfd,signal.SIGKILL)
                        assert select.select([pidfd],[],[],10)[0], ('manager-did-not-exit-after-exact-pidfd-signal',manager)
                    finally:os.close(pidfd)
                    reap_deadline=time.monotonic()+10
                    while True:
                        try:
                            fields=(Path('/proc')/str(manager['pid'])/'stat').read_text().rsplit(') ',1)[1].split()
                            current_birth=int(fields[19])
                        except (FileNotFoundError,ProcessLookupError):break
                        if current_birth!=manager['birth']:break
                        assert time.monotonic()<reap_deadline, ('exited-manager-incarnation-remained-visible',manager,current_birth)
                        time.sleep(.01)
                    observation.update({'after_review_prompt':True,'signal':'SIGKILL','incarnation_no_longer_visible':True})
                    (output/'manager-exit-observation.json').write_text(json.dumps(observation,indent=2)+'\n')
                before_detach_yes=terminate_manager_after_prompt
            accepted_identity(proposal,approve(detach_proposal['request_id'],before_yes=before_detach_yes))
            if args.approval_manager_exit:
                assert len(manager_exit_observations)==1 and len(approval_replans)==1, ('manager-exit-did-not-require-one-fresh-review',manager_exit_observations,approval_replans)
                checks.append('manager_exit_after_review_prompt_supersedes_old_confirmation_and_requires_fresh_approval')
                pending_detach=phase(proposal['attachment_id'],['detaching','draining','detached','detached_resident'])
                assert pending_detach['manager']!=manager, ('recovery-did-not-publish-a-new-manager',manager,pending_detach)
                blocked_release=exchange('unblock')[0]
            else:blocked_release=None
            detach_approved_at=time.perf_counter_ns()
            detached=phase(proposal['attachment_id'],['detached','detached_resident','draining'])
            record_fixture_fds('detached_cycle_'+str(cycle),original_pid)
            if blocked_release is None:blocked_release=exchange('unblock')[0]
            assert blocked_release['blocked_original_preserved'], 'blocked original returned differently after detach'
            assert exchange('idle-connect')[0]['idle_nonblocking_preserved'], 'detach lost virtualized socket flags'
            assert exchange('read')[0]['read_result']==0
            if args.mapping_regression:
                assert exchange('allocator-growth')[0]['allocator_growth_preserved']
                assert exchange('probe-mapping')[0]['mapping_result']==0, 'detached-file-mprotect-still-enforced'
            if cycle==0:
                detached_fork=exchange('fork-read')[0]
                assert detached_fork['child_result']==0, ('detached-native-fork',detached_fork)
                detached_exec=exchange('exec-read')[0]
                assert detached_exec['child_result']==0, ('detached-native-exec',detached_exec)
                checks.append('detached_native_fork_and_exec_preserved')
                if args.backend=='gum' and not alias_scenario:
                    boundaries=exchange('fork-connect-boundaries')[0]
                    assert boundaries==connect_boundary_oracle, ('detached-connect-native-errno-oracle',connect_boundary_oracle,boundaries)
                    checks.append('detached_child_connect_boundaries_match_native')
            if alias_scenario:
                native_alias=exchange('cached-connect')[0]
                assert native_alias['cached_alias_stream'] and native_alias['cached_alias_native_peer'], ('detached-cached-alias-must-use-native-target-without-old-gateway-policy',native_alias)
                native_nonblocking_alias=exchange('cached-connect-nonblocking')[0]
                assert native_nonblocking_alias['cached_alias_stream'] and native_nonblocking_alias['cached_alias_native_peer'], ('detached-cached-alias-nonblocking-native-target',native_nonblocking_alias)
                if cycle==0:checks.append('detached_cached_alias_uses_native_target_despite_gateway_deny')
                if cycle==0 and args.inherited_issued:
                    for command in ['fork-cached-connect','fork-cached-connect-nonblocking','double-fork-cached-connect','double-fork-cached-connect-nonblocking']:
                        inherited=exchange(command)[0]
                        assert inherited['cached_alias_child_result']==0, ('detached-inherited-issued-alias-native-only',command,inherited)
                    checks.append('detached_child_and_grandchild_inherit_native_only_issued_aliases')
                    collision=exchange('fork-alias-collision')[0]
                    assert collision['alias_collision_child_result']==0, ('detached-child-dns-alias-collision',collision)
                    assert exchange('cached-connect')[0]['cached_alias_stream'], 'child collision modified detached parent alias'
                if cycle==0 and args.alias_serve_offline:
                    run(['stop'])
                    for command in ['cached-connect','cached-connect-nonblocking']:
                        offline_alias=exchange(command)[0]
                        assert offline_alias['cached_alias_stream'] and offline_alias['cached_alias_native_peer'], ('detached-alias-with-serve-offline',command,offline_alias)
                    assert exchange('read')[0]['read_result']==0 and exchange('socket')[0]['old_stream']
                    run(['start','--admin-password-file',str(password)])
                    restarted_alias=exchange('cached-connect')[0]
                    assert restarted_alias['cached_alias_stream'] and restarted_alias['cached_alias_native_peer']
                    checks.append('detached_cached_alias_native_compatibility_survives_serve_offline_and_restart')
            if orphan_pid is None and not args.cross_producer_issued:assert exchange('existing-child-read')[0]['existing_child_result']==0
            assert exchange('socket')[0]['old_stream']
            if args.exec_family_regression:
                exec_errors('detached_cycle_'+str(cycle))
                for command in ['fexecve-read','execveat-read']:
                    child=exchange(command)[0]
                    assert child['child_result']==0, ('detached-fd-exec-child-native-continuity',command,child)
            if args.root_self_exec:
                replacement=exchange('replace-stream-native')[0]
                assert replacement['old_stream_closed'] and replacement['replacement_stream'], ('application-owned-stream-retirement',replacement)
                if cycle==0:checks.append('self_exec_stream_survives_logical_detach_until_application_closes_it')
            if args.backend=='ptrace' and args.origin=='attach' and not alias_scenario:
                detached=phase(proposal['attachment_id'],['detached'])
                for member in detached['members']:
                    status_path=Path(f"/proc/{member['pid']}/status")
                    if status_path.exists():assert re.search(r'^TracerPid:\s+0$',status_path.read_text(),re.M), ('physical-detach-tracer-still-present',member)
                if 'physical_ptrace_detach_verified_in_proc' not in checks:checks.append('physical_ptrace_detach_verified_in_proc')
            immediate_snapshot,latency=exchange('snapshot')
            immediate_threads=thread_details(orphan_pid or original_pid)
            drain_wait=0
            if args.backend=='gum':detached,drain_wait=await_control_retirement(proposal['attachment_id'],orphan_pid or original_pid,detach_requested_at)
            snapshot,latency=exchange('snapshot')
            assert snapshot['pid']==(orphan_pid or original_pid) and snapshot['stable_stdio_cwd'] and snapshot['stable_environment'] and snapshot['stable_terminal']
            assert snapshot['progress']>baseline['progress']
            assert exchange('read-other')[0]['other_read_result']==0, 'new file policy continued after logicaldetach'
            assert exchange('signal-check')[0]['signal_delivery_and_mask_preserved']
            assert exchange('thread-read')[0]['thread_read_result']==0
            if cycle==0:measure_window('detached',orphan_pid or original_pid)
            if cycle==0 and alias_scenario:
                restore=temporary/'restore-gateway-allow.json';restore.write_text(json.dumps([{'op':'replace','path':'/gateway/routing/default/decision/action','value':'allow'}]));restore.chmod(0o600)
                restore_plan=json.loads(run(['config','patch',str(restore)]))
                assert restore_plan['status']=='approval_required'
                approve(None,config_plan=restore_plan)
            if cycle==0 and (args.cycles>=2 or args.duration>0):
                tightening=temporary/'tighten-before-reattach.json'
                rule={'id':'deny-after-reattach','enabled':True,'priority':101,'action':'deny','operations':['read'],'patterns':[{'enabled':True,'pattern':'^'+re.escape(str(ordinary))+'$'}]}
                tightening.write_text(json.dumps([{'op':'add','path':'/sandbox/file/rules/-','value':rule}]))
                tightening.chmod(0o600)
                tightening_plan=json.loads(run(['config','patch',str(tightening)]))
                assert tightening_plan['status']=='approval_required'
                approve(None,config_plan=tightening_plan)
                assert exchange('read-other')[0]['other_read_result']==0, 'config update re-enabled detached enforcement'
            samples.append({'cycle':cycle,'attach_with_approval_ns':detach_started-attach_started,'detach_with_approval_ns':detach_approved_at-detach_started,'detach_scenario_elapsed_ns':time.perf_counter_ns()-detach_started,'resource_retirement_wait_ns':drain_wait,'command_roundtrip_ns':latency,'phase':detached['phase'],'compatibility_reasons':detached['compatibility_reasons'],'immediate_resources':{key:immediate_snapshot[key] for key in ['fd_count','thread_count','native_mappings']},'immediate_threads':immediate_threads,'steady_threads':thread_details(orphan_pid or original_pid),'resources':{key:snapshot[key] for key in ['fd_count','thread_count','native_mappings']}})
            if cycle==1:resources_after_warmup={key:snapshot[key] for key in ['fd_count','thread_count','native_mappings']}
            elif cycle>1:
                # Exact stable counts after a complete logical detach catch
                # per-cycle retained workers, sockets and duplicate modules.
                assert all(snapshot[key]<=resources_after_warmup[key] for key in resources_after_warmup), ('resources grew after warmup',resources_after_warmup,snapshot)
            cycle+=1
            next_extra_cycle=time.monotonic()+60
            if cycle%10==0:
                print(json.dumps({'cycles':cycle,'elapsed_seconds':time.monotonic()-started}),flush=True)
        checks.extend(['approval_before_mutation','file_policy_enforced','connection_continuity','unconnected_nonblocking_socket_flags_survive_detach','blocked_original_call_survives_detach','target_identity_environment_stdio_and_cwd_preserved'])
        if cycle>=2:checks.extend(['repeated_attach_detach','tightened_policy_enforced_on_first_reattach'])
        if alias_scenario:checks.append('application_cached_fake_ip_survives_detach_and_reattach')
        if cycle>=3:checks.append('no_resource_count_growth_after_warmup')
        if args.origin=='run' and not args.root_exit:
            assert target.poll() is None, 'foreground launcher stopped waiting at detach'
            checks.append('owned_run_launcher_waits_after_detach')
        if args.target_pty:checks.append('real_controlling_terminal_termios_and_foreground_preserved')
        target.stdin.write(b'exit\n');target.stdin.flush()
        finish_target(target,37,30,'final-exit')
        if orphan_pidfd is not None:
            assert select.select([orphan_pidfd],[],[],30)[0], 'surviving descendant did not exit on its own command'
            checks.append('surviving_descendant_accepts_detach_after_original_root_exit')
        checks.append('original_target_exit_code')
        phase_valid_commands={}
        for window in phase_windows:phase_valid_commands[window['phase']]=phase_valid_commands.get(window['phase'],0)+window['completed_valid_commands']
        soak_elapsed_ns=sum(interval['elapsed_ns'] for interval in soak_intervals)
        assert workload_count==sum(interval['completed_valid_commands'] for interval in soak_intervals)
        report={'status':'pass','origin':args.origin,'backend':args.backend,'cycles':cycle,'successful_cycles':cycle,'elapsed_seconds':time.monotonic()-started,'checks':checks,'samples':samples,'phase_windows':phase_windows,'bounded_phase_valid_commands':phase_valid_commands,'soak_intervals':soak_intervals,'commands':commands,'target_pty':args.target_pty,'root_exit':args.root_exit,'alias_origin':'issued' if args.issued_fake_ip else ('observed' if args.fake_ip else None),'scope':args.scope,'baseline_roundtrip_ns':baseline_latencies,'paced_soak_valid_commands':workload_count,'paced_soak_elapsed_ns':soak_elapsed_ns,'paced_soak_valid_commands_per_soak_second':workload_count*1e9/soak_elapsed_ns if soak_elapsed_ns else None,'bounded_paced_soak_snapshot_roundtrip_ns':workload_latencies,'baseline_latency_distribution':distribution(baseline_latencies),'paced_soak_snapshot_latency_distribution':distribution(workload_latencies),'performance_scope':'fixed phase windows and paced soak are counted separately; functional cycle checks and approvals are outside those command counts; no aggregate capacity or production SLA claim'}
        report['diagnostic_controls']={'fixture_child_debugger_opt_in':args.fixture_child_debugger,'crash_debugger':args.diagnostic_crash,'manager_ptrace_trace':args.trace_manager_ptrace,'manager_host_states':True,'manager_frida_stages_and_fd_metadata':args.manager_frida_diagnostics}
        report['alias_serve_offline']=args.alias_serve_offline
        report['inherited_issued']=args.inherited_issued
        report['cross_producer_issued']=args.cross_producer_issued
        report['mapping_regression']=args.mapping_regression
        report['root_self_exec']=args.root_self_exec
        report['root_exec_observations']=root_exec_observations
        report['exec_family_regression']=args.exec_family_regression
        report['exec_error_observations']=exec_error_observations
        report['native_root_exec_observations']=native_root_exec_observations
        report['root_exec_methods']=args.root_exec_methods or (['path'] if args.root_self_exec else [])
        report['retirement_observations']=retirement_observations
        report['approval_replans']=approval_replans
        report['manager_exit_observations']=manager_exit_observations
        report['phase_observations']=phase_observations
        report['target_stdio']=target_stdio_evidence()
        write_result(report)
        print(json.dumps({'status':'pass','backend':args.backend,'cycles':cycle,'checks':len(checks)}),flush=True)
    except Exception as error:
        try:
            (output/'failure-status.json').write_bytes(run(['status','--json']))
        except Exception as diagnostic_error:
            (output/'failure-status-error.txt').write_text(repr(diagnostic_error)+'\n')
        private_attachments=Path(env['HYPERHUB_HOME'])/'runtime'/'attachments'
        if private_attachments.is_dir():
            for directory in private_attachments.iterdir():
                if not directory.is_dir() or directory.is_symlink():continue
                for name in ['manager.log','keeper.log','worker.log','record.json','handoff-progress.json','host-states.json']:
                    source=directory/name
                    if source.is_file() and not source.is_symlink():
                        destination=output/'failure-state'/directory.name/name
                        destination.parent.mkdir(parents=True,exist_ok=True)
                        shutil.copyfile(source,destination)
        failure={'status':'fail','origin':args.origin,'backend':args.backend,'scope':args.scope,'target_pty':args.target_pty,'checks_completed':checks,'samples':samples,'phase_windows':phase_windows,'soak_intervals':soak_intervals,'commands':commands,'error':repr(error),'recent_fixture_exchanges':list(recent_exchanges),'fork_observations':fork_observations}
        failure['diagnostic_controls']={'fixture_child_debugger_opt_in':args.fixture_child_debugger,'crash_debugger':args.diagnostic_crash,'manager_ptrace_trace':args.trace_manager_ptrace,'manager_host_states':True,'manager_frida_stages_and_fd_metadata':args.manager_frida_diagnostics}
        failure['alias_serve_offline']=args.alias_serve_offline
        failure['inherited_issued']=args.inherited_issued
        failure['cross_producer_issued']=args.cross_producer_issued
        failure['allocator_fork_regression']=args.allocator_fork_regression
        failure['mapping_regression']=args.mapping_regression
        failure['root_self_exec']=args.root_self_exec
        failure['root_exec_observations']=root_exec_observations
        failure['exec_family_regression']=args.exec_family_regression
        failure['exec_error_observations']=exec_error_observations
        failure['native_root_exec_observations']=native_root_exec_observations
        failure['root_exec_methods']=args.root_exec_methods or (['path'] if args.root_self_exec else [])
        failure['child_startup_failure']=args.child_startup_failure
        failure['child_startup_observations']=child_startup_observations
        if fault_control_path is not None:
            try:failure['bind_fault_state']=fault_state()
            except Exception as diagnostic_error:failure['bind_fault_state_error']=repr(diagnostic_error)
        failure['busy_preparation']=args.busy_preparation
        failure['retirement_observations']=retirement_observations
        failure['phase_observations']=phase_observations
        failure['target_stdio']=target_stdio_evidence()
        if target is not None:failure['current_threads']=thread_details(orphan_pid or target.pid)
        (output/'failure.json').write_text(json.dumps(failure,indent=2)+'\n')
        raise
    finally:
        if fault_control_path is not None:
            try:fault_command('--disable')
            except Exception:pass
        if fault_fifo_writer is not None:
            os.close(fault_fifo_writer)
        if fault_fifo_active:
            try:
                secret.unlink();secret.write_text('S\n');secret.chmod(0o600)
            except OSError:pass
        if args.manager_frida_diagnostics or (output/'failure.json').is_file():
            copy_manager_logs(Path(env['HYPERHUB_HOME']),output)
        if orphan_pidfd is not None:
            if not select.select([orphan_pidfd],[],[],0)[0]:
                signal.pidfd_send_signal(orphan_pidfd,signal.SIGTERM)
                if not select.select([orphan_pidfd],[],[],5)[0]:signal.pidfd_send_signal(orphan_pidfd,signal.SIGKILL)
            os.close(orphan_pidfd)
        if target is not None and target.poll() is None:
            target.terminate()
            try:
                target.wait(timeout=5)
            except subprocess.TimeoutExpired:
                target.kill();target.wait(timeout=5)
        # A diagnostic crash can leave a stopped grandchild after its parent
        # exits. Cleanup is pinned to this run's unique fixture executable.
        fixture_path=output/'dynamic-attach-target'
        for process_path in Path('/proc').iterdir():
            if not process_path.name.isdigit():continue
            try:
                if process_path.stat().st_uid!=os.geteuid() or Path(os.readlink(process_path/'exe'))!=fixture_path:continue
                identity=(process_path/'stat').read_text().rsplit(') ',1)[1].split()[19]
                handle=os.pidfd_open(int(process_path.name))
                try:
                    if Path(os.readlink(process_path/'exe'))==fixture_path and (process_path/'stat').read_text().rsplit(') ',1)[1].split()[19]==identity:
                        signal.pidfd_send_signal(handle,signal.SIGKILL)
                finally:os.close(handle)
            except (FileNotFoundError,ProcessLookupError,PermissionError):continue
        for process,capture in target_stdio_by_process.items():
            try:
                while select.select([process.stdout],[],[],0)[0]:
                    data=os.read(process.stdout.fileno(),65536)
                    if not data:break
                    capture.record_unexpected_stdout(data)
            except (OSError,ValueError):
                pass
            capture.close()
        if target_stdio_captures:target_stdio_evidence()
        try:
            subprocess.run([str(binary),'stop'],env=env,capture_output=True,timeout=15)
        except (OSError,subprocess.TimeoutExpired):
            pass
        if isinstance(target,PtyTarget):target.close()
        dns.shutdown();dns.server_close();dns_thread.join(timeout=5)
        server.shutdown();server.server_close();server_thread.join(timeout=5)
        shutil.rmtree(temporary)

if __name__=='__main__':
    main()
