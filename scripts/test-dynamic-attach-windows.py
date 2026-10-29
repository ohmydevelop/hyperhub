#!/usr/bin/env python3
"""Native Windows live attachment, real ConPTY approval and detach continuity.

Runs only disposable fixture processes, dummy credentials and local echo I/O.
Exit status reports any assertion, command or cleanup failure. Never installs or
restarts a user's Serve or attaches to any process outside this fixture tree.
"""
import argparse
import contextlib
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
from windows_conpty import Console
from windows_test_env import isolated_environment, compiler_environment
ROOT=Path(__file__).resolve().parents[1]
class Echo(socketserver.ThreadingTCPServer):
    allow_reuse_address=True
    daemon_threads=True
class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        while True:
            data=self.request.recv(65536)
            if not data:return
            self.request.sendall(data)
def free_port():
    with socket.socket() as stream:
        stream.bind(('127.0.0.1',0));return stream.getsockname()[1]
def native_agent_modules(pid):
    # Inspect the OS loader independently of the manager's reported phase.
    import ctypes
    from ctypes import wintypes as w
    class Module(ctypes.Structure):
        _fields_=[('size',w.DWORD),('id',w.DWORD),('pid',w.DWORD),('global_usage',w.DWORD),('usage',w.DWORD),('base',ctypes.c_void_p),('length',w.DWORD),('handle',w.HMODULE),('name',w.WCHAR*256),('path',w.WCHAR*260)]
    kernel=ctypes.WinDLL('kernel32',use_last_error=True)
    kernel.CreateToolhelp32Snapshot.argtypes=[w.DWORD,w.DWORD];kernel.CreateToolhelp32Snapshot.restype=w.HANDLE
    kernel.Module32FirstW.argtypes=[w.HANDLE,ctypes.POINTER(Module)];kernel.Module32FirstW.restype=w.BOOL
    kernel.Module32NextW.argtypes=[w.HANDLE,ctypes.POINTER(Module)];kernel.Module32NextW.restype=w.BOOL
    kernel.CloseHandle.argtypes=[w.HANDLE];kernel.CloseHandle.restype=w.BOOL
    deadline=time.monotonic()+3
    while True:
        snapshot=kernel.CreateToolhelp32Snapshot(0x18,pid)
        if snapshot!=ctypes.c_void_p(-1).value:break
        error=ctypes.get_last_error()
        if error!=24 or time.monotonic()>=deadline:raise ctypes.WinError(error)
        time.sleep(.01)
    result=[]
    try:
        module=Module();module.size=ctypes.sizeof(Module);found=kernel.Module32FirstW(snapshot,ctypes.byref(module))
        while found:
            if module.name.lower()=='hyperhub_gum_agent.dll':result.append(module.path)
            module.size=ctypes.sizeof(Module);found=kernel.Module32NextW(snapshot,ctypes.byref(module))
    finally:kernel.CloseHandle(snapshot)
    return result

def wait_disposable_child(pid,expected=37):
    import ctypes
    from ctypes import wintypes as w
    k=ctypes.WinDLL('kernel32',use_last_error=True)
    k.OpenProcess.argtypes=[w.DWORD,w.BOOL,w.DWORD];k.OpenProcess.restype=w.HANDLE
    k.WaitForSingleObject.argtypes=[w.HANDLE,w.DWORD];k.WaitForSingleObject.restype=w.DWORD
    k.GetExitCodeProcess.argtypes=[w.HANDLE,ctypes.POINTER(w.DWORD)];k.GetExitCodeProcess.restype=w.BOOL
    k.CloseHandle.argtypes=[w.HANDLE];k.CloseHandle.restype=w.BOOL
    handle=k.OpenProcess(0x00101000,False,pid)
    if not handle:raise ctypes.WinError(ctypes.get_last_error())
    try:
        assert k.WaitForSingleObject(handle,30000)==0,'owned child did not exit'
        code=w.DWORD();assert k.GetExitCodeProcess(handle,ctypes.byref(code)) and code.value==expected,('owned child exit status changed',code.value)
    finally:k.CloseHandle(handle)

class Resources:
    """Read-only native resource sampling for the exact disposable target PID."""
    def __init__(self,pid):
        import ctypes
        from ctypes import wintypes as w
        self.ctypes=ctypes;self.w=w;self.pid=pid;self.phase='warmup';self.anchor=time.monotonic();self.samples=[];self.errors=[];self.stop=threading.Event()
        class Memory(ctypes.Structure):
            _fields_=[('cb',w.DWORD),('page_faults',w.DWORD),*[(name,ctypes.c_size_t) for name in ['peak_working_set','working_set','peak_paged','paged','peak_nonpaged','nonpaged','private_commit','peak_private_commit']]]
        class Thread(ctypes.Structure):
            _fields_=[('size',w.DWORD),('usage',w.DWORD),('id',w.DWORD),('owner',w.DWORD),('priority',w.LONG),('delta',w.LONG),('flags',w.DWORD)]
        self.Memory=Memory;self.Thread=Thread
        k=ctypes.WinDLL('kernel32',use_last_error=True);self.k=k
        k.OpenProcess.argtypes=[w.DWORD,w.BOOL,w.DWORD];k.OpenProcess.restype=w.HANDLE
        k.CloseHandle.argtypes=[w.HANDLE];k.CloseHandle.restype=w.BOOL
        k.GetProcessHandleCount.argtypes=[w.HANDLE,ctypes.POINTER(w.DWORD)];k.GetProcessHandleCount.restype=w.BOOL
        k.K32GetProcessMemoryInfo.argtypes=[w.HANDLE,ctypes.POINTER(Memory),w.DWORD];k.K32GetProcessMemoryInfo.restype=w.BOOL
        k.CreateToolhelp32Snapshot.argtypes=[w.DWORD,w.DWORD];k.CreateToolhelp32Snapshot.restype=w.HANDLE
        k.Thread32First.argtypes=[w.HANDLE,ctypes.POINTER(Thread)];k.Thread32First.restype=w.BOOL
        k.Thread32Next.argtypes=[w.HANDLE,ctypes.POINTER(Thread)];k.Thread32Next.restype=w.BOOL
        k.WaitForSingleObject.argtypes=[w.HANDLE,w.DWORD];k.WaitForSingleObject.restype=w.DWORD
        self.handle=k.OpenProcess(0x00101410,False,pid)
        if not self.handle:raise ctypes.WinError(ctypes.get_last_error())
        self.worker=threading.Thread(target=self._watch,daemon=True);self.worker.start()
    def sample(self):
        c=self.ctypes;k=self.k;w=self.w
        handles=w.DWORD();memory=self.Memory();memory.cb=c.sizeof(memory)
        if not k.GetProcessHandleCount(self.handle,c.byref(handles)) or not k.K32GetProcessMemoryInfo(self.handle,c.byref(memory),memory.cb):raise c.WinError(c.get_last_error())
        snapshot=k.CreateToolhelp32Snapshot(4,0)
        if snapshot==c.c_void_p(-1).value:raise c.WinError(c.get_last_error())
        threads=0
        try:
            entry=self.Thread();entry.size=c.sizeof(entry);found=k.Thread32First(snapshot,c.byref(entry))
            while found:
                threads+=entry.owner==self.pid;entry.size=c.sizeof(entry);found=k.Thread32Next(snapshot,c.byref(entry))
        finally:k.CloseHandle(snapshot)
        value={'elapsed_seconds':time.monotonic()-self.anchor,'phase':self.phase,'handles':handles.value,'threads':threads,'working_set_bytes':memory.working_set,'private_commit_bytes':memory.private_commit}
        self.samples.append(value);return value
    def _watch(self):
        while not self.stop.wait(.5):
            if self.k.WaitForSingleObject(self.handle,0)==0:return
            try:self.sample()
            except OSError as error:self.errors.append(str(error));return
    def close(self):
        self.stop.set();self.worker.join(timeout=3);self.k.CloseHandle(self.handle)

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--hyperhub',required=True,type=Path)
    parser.add_argument('--backend',choices=['gum'],default='gum')
    parser.add_argument('--init-failure-probe',type=Path,default=ROOT/'target'/'release'/'examples'/'attachment_init_failure.exe')
    parser.add_argument('--origin',choices=['attach','run'],default='attach')
    parser.add_argument('--cycles',type=int,default=1)
    parser.add_argument('--duration',type=float,default=0)
    parser.add_argument('--output',required=True,type=Path)
    args=parser.parse_args()
    if os.name!='nt':parser.error('native Windows is required; this is not a cross-build execution test')
    if args.cycles<1 or args.duration<0:parser.error('cycles must be positive and duration nonnegative')
    binary=args.hyperhub.resolve();output=args.output.resolve();output.mkdir(parents=True,exist_ok=False)
    temporary=Path(tempfile.mkdtemp(prefix='hh-dynamic-attach-'))
    env=isolated_environment(os.environ,temporary)
    for key in ['HOME','USERPROFILE','HYPERHUB_HOME','TMP','TEMP','APPDATA','LOCALAPPDATA']:
        Path(env[key]).mkdir(parents=True,exist_ok=True)
    build_env=compiler_environment(os.environ)
    password=temporary/'administrator-password';password.write_text('disposable-attachment-test-password\n')
    secret=temporary/'protected.txt';secret.write_bytes(b'S\n')
    server=Echo(('127.0.0.1',0),Handler);server_thread=threading.Thread(target=server.serve_forever,daemon=True);server_thread.start()
    counter=0;commands=[];checks=[];samples=[];performance=[];spawn_boundary_evidence=None;held_child=None;resources=None;resource_samples=[];resource_errors=[];resource_baselines={};baseline_target=None;passive=None;target=None;legacy=None;cycle=0;failure=None;started=time.monotonic();harness_started=started;pressure_finished=None;final_workload=None;cleanup_errors=[]
    def run(arguments,expected=0):
        nonlocal counter
        counter+=1;result=subprocess.run([str(binary),*map(str,arguments)],env=env,capture_output=True,timeout=90)
        (output/f'cli-{counter}.stdout').write_bytes(result.stdout);(output/f'cli-{counter}.stderr').write_bytes(result.stderr)
        commands.append({'args':list(map(str,arguments)),'exit_code':result.returncode})
        assert result.returncode==expected,(arguments,result.returncode,result.stderr.decode(errors='replace'))
        return result.stdout
    def approve(request_id):
        nonlocal counter
        counter+=1
        with Console([str(binary),'approve',request_id,'--admin-password-file',str(password)],env) as console:
            console.wait_for(b'Approve [y], reject [n], or quit [q]:')
            console.send('y\r');status=console.wait(90);transcript=console.transcript()
        (output/f'cli-{counter}.conpty').write_bytes(transcript)
        commands.append({'args':['approve',request_id,'--admin-password-file','<private-test-file>'],'exit_code':status,'terminal':'native-conpty'})
        assert status==0,('interactive approval failed',status,transcript.decode(errors='replace'))
    def spawn(extra=(),owned=False,environment=None):
        arguments=[str(fixture),str(secret),str(server.server_address[1]),*extra]
        if owned:arguments=[str(binary),'run','--backend','gum','--',*arguments]
        process=subprocess.Popen(arguments,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=env if environment is None else environment,bufsize=0)
        messages=queue.Queue();errors=bytearray()
        def receive():
            for line in iter(process.stdout.readline,b''):messages.put(line)
            messages.put(None)
        def receive_errors():
            for data in iter(lambda:process.stderr.read(8192),b''):errors.extend(data)
        threading.Thread(target=receive,daemon=True).start();threading.Thread(target=receive_errors,daemon=True).start()
        def exchange(command=None):
            before=time.perf_counter_ns()
            if command is not None:process.stdin.write(command.encode()+b'\n');process.stdin.flush()
            data=messages.get(timeout=30)
            assert data is not None,('fixture unexpectedly exited',process.poll(),bytes(errors).decode(errors='replace'))
            return json.loads(data),time.perf_counter_ns()-before
        return process,exchange,errors
    def measure(exchange,label,origin):
        values=[];window_started=time.perf_counter_ns()
        for _ in range(50):
            snapshot,elapsed=exchange('snapshot')
            assert snapshot['stable_stdio_cwd'] and snapshot['stable_environment']
            values.append(elapsed)
        elapsed=time.perf_counter_ns()-window_started;ordered=sorted(values)
        performance.append({'elapsed_ns':elapsed,'effective_operations_per_second':len(values)*1e9/elapsed,'phase':label,'origin':origin,'workload':'same_fixture_snapshot_command','count':len(values),'samples_ns':values,'p50_ns':ordered[len(ordered)//2],'p95_ns':ordered[int((len(ordered)-1)*.95)],'max_ns':ordered[-1]})

    def phase(attachment_id,allowed,previous_manager=None):
        deadline=time.monotonic()+45
        while time.monotonic()<deadline:
            status=json.loads(run(['status','--json']))
            record=next((r for r in status.get('attachments',[]) if r['spec']['id']==attachment_id),None)
            if record and record['phase'] in allowed:return record
            stale_manager=record and previous_manager is not None and (record.get('manager') or {}).get('pid')==previous_manager
            if record and record['phase'] in ['failed','cleanup_pending','degraded'] and not stale_manager:raise AssertionError(('attachment operation failed',record))
            time.sleep(.05)
        raise AssertionError(('attachment did not reach phase',attachment_id,allowed))
    def terminate_disposable_manager(record):
        import ctypes
        from ctypes import wintypes as w
        manager=record['manager'];pid=manager['pid']
        assert Path(manager['executable']).resolve()==binary and manager['executable_sha256']==hashlib.sha256(binary.read_bytes()).hexdigest()
        assert pid!=record['spec']['target']['pid']
        kernel=ctypes.WinDLL('kernel32',use_last_error=True)
        kernel.OpenProcess.argtypes=[w.DWORD,w.BOOL,w.DWORD];kernel.OpenProcess.restype=w.HANDLE
        kernel.QueryFullProcessImageNameW.argtypes=[w.HANDLE,w.DWORD,w.LPWSTR,ctypes.POINTER(w.DWORD)];kernel.QueryFullProcessImageNameW.restype=w.BOOL
        kernel.GetProcessTimes.argtypes=[w.HANDLE,*([ctypes.POINTER(w.FILETIME)]*4)];kernel.GetProcessTimes.restype=w.BOOL
        kernel.TerminateProcess.argtypes=[w.HANDLE,w.UINT];kernel.TerminateProcess.restype=w.BOOL
        kernel.WaitForSingleObject.argtypes=[w.HANDLE,w.DWORD];kernel.WaitForSingleObject.restype=w.DWORD
        kernel.CloseHandle.argtypes=[w.HANDLE];kernel.CloseHandle.restype=w.BOOL
        handle=kernel.OpenProcess(0x00101001,False,pid)
        if not handle:raise ctypes.WinError(ctypes.get_last_error())
        try:
            name=ctypes.create_unicode_buffer(32768);length=w.DWORD(len(name))
            assert kernel.QueryFullProcessImageNameW(handle,0,name,ctypes.byref(length))
            assert Path(name.value).resolve()==binary
            creation=w.FILETIME();exit_time=w.FILETIME();system=w.FILETIME();user=w.FILETIME()
            assert kernel.GetProcessTimes(handle,ctypes.byref(creation),ctypes.byref(exit_time),ctypes.byref(system),ctypes.byref(user))
            birth=(creation.dwHighDateTime<<32)|creation.dwLowDateTime
            assert birth==manager['birth'],'test manager PID incarnation changed'
            assert kernel.TerminateProcess(handle,97) and kernel.WaitForSingleObject(handle,5000)==0
        finally:kernel.CloseHandle(handle)
        return pid

    @contextlib.contextmanager
    def suspend_disposable_serve():
        # A real Core outage tests completion retries after physical unload.
        # The fixture's already-drained sockets use the independent local echo
        # server. No user instance or unrelated process is suspended.
        import ctypes
        from ctypes import wintypes as w
        status=json.loads(run(['status','--json']));pid=status['pid']
        assert pid!=original_pid and pid!=(status.get('attachments',[{}])[0].get('manager') or {}).get('pid')
        kernel=ctypes.WinDLL('kernel32',use_last_error=True);nt=ctypes.WinDLL('ntdll')
        kernel.OpenProcess.argtypes=[w.DWORD,w.BOOL,w.DWORD];kernel.OpenProcess.restype=w.HANDLE
        kernel.QueryFullProcessImageNameW.argtypes=[w.HANDLE,w.DWORD,w.LPWSTR,ctypes.POINTER(w.DWORD)];kernel.QueryFullProcessImageNameW.restype=w.BOOL
        kernel.CloseHandle.argtypes=[w.HANDLE];kernel.CloseHandle.restype=w.BOOL
        nt.NtSuspendProcess.argtypes=[w.HANDLE];nt.NtSuspendProcess.restype=ctypes.c_long
        nt.NtResumeProcess.argtypes=[w.HANDLE];nt.NtResumeProcess.restype=ctypes.c_long
        handle=kernel.OpenProcess(0x00101800,False,pid)
        if not handle:raise ctypes.WinError(ctypes.get_last_error())
        resumed=False;lock=threading.Lock();watchdog=None
        def resume():
            nonlocal resumed
            with lock:
                if not resumed:
                    code=nt.NtResumeProcess(handle)
                    if code<0:cleanup_errors.append(f'private Serve resume failed: 0x{code & 0xffffffff:08x}')
                    resumed=True
        try:
            name=ctypes.create_unicode_buffer(32768);length=w.DWORD(len(name))
            assert kernel.QueryFullProcessImageNameW(handle,0,name,ctypes.byref(length)) and Path(name.value).resolve()==binary
            code=nt.NtSuspendProcess(handle)
            assert code>=0,('private Core suspension failed',hex(code & 0xffffffff))
            watchdog=threading.Timer(30,resume);watchdog.daemon=True;watchdog.start()
            yield
        finally:
            if watchdog is not None:
                resume();watchdog.cancel();watchdog.join(timeout=3)
            kernel.CloseHandle(handle)

    try:
        fixture=output/'dynamic-attach-target.exe';marker=output/'generic-legacy-marker.dll'
        for source,destination,extra in [('dynamic_attach_windows.rs',fixture,[]),('dynamic_attach_legacy_marker.rs',marker,['--crate-type','cdylib'])]:
            result=subprocess.run(['rustc','--edition=2021','-C','opt-level=1',*extra,str(ROOT/'tests/fixtures'/source),'-o',str(destination)],env=build_env,capture_output=True,timeout=180)
            (output/(source+'.build.log')).write_bytes(result.stdout+result.stderr)
            assert result.returncode==0,('native fixture build failed',source,result.returncode)
        pattern=json.dumps(r'protected\.txt$')
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
        run(['import',config,'--admin-password-file',password]);run(['start','--admin-password-file',password])
        # Capture a separate unmanaged baseline with the same native executable,
        # arguments, local echo server, pipes and environment as the measured run.
        baseline_target,baseline_exchange,baseline_errors=spawn();baseline_info,_=baseline_exchange()
        assert baseline_exchange('credential')[0]['credential_status']==0
        assert baseline_exchange('free-all-credentials')[0]['credentials_freed']
        anonymous_heap_baseline=baseline_exchange('anon-map-heap-lock')[0]
        assert anonymous_heap_baseline['setup_ok'] and anonymous_heap_baseline['heap_locked'] and anonymous_heap_baseline['completed_while_locked'],anonymous_heap_baseline
        assert all(anonymous_heap_baseline[name]==0 for name in ('create_status','map_status','unmap_status','close_status')),anonymous_heap_baseline
        native_success_baseline=baseline_exchange('exec-last-error')[0]
        native_failure_baseline=baseline_exchange('exec-last-error-fail')[0]
        assert native_success_baseline['native_success'] and not native_failure_baseline['native_success']
        bad_sockaddr_baseline=baseline_exchange('bad-sockaddr')[0]
        assert len(bad_sockaddr_baseline['native_errors'])==6 and all(value['status']==-1 for value in bad_sockaddr_baseline['native_errors'])
        bad_sockaddr_v6_baseline=baseline_exchange('bad-sockaddr-v6')[0]
        assert len(bad_sockaddr_v6_baseline['native_errors'])==6 and all(value['status']==-1 for value in bad_sockaddr_v6_baseline['native_errors'])
        dns_numeric_baseline=baseline_exchange('dns-invalid-numeric')[0]
        dns_hints_baseline=baseline_exchange('cache-dns-hints')[0]
        assert dns_numeric_baseline['native_status']!=0 and not dns_numeric_baseline['cached']
        assert dns_hints_baseline['native_status']==0 and dns_hints_baseline['cached']
        native_dns_baseline=baseline_exchange('cache-dns')[0]
        assert native_dns_baseline['cached'] and native_dns_baseline['cached_address']=='127.0.0.1'
        mapped_baseline={command:baseline_exchange(command)[0] for command in ('cached-mapped-blocking','cached-mapped-nonblocking')}
        assert all(value['cached_stream'] and value['peer_family']==6 for value in mapped_baseline.values()),mapped_baseline
        time.sleep(1)
        baseline_resources=Resources(baseline_info['pid'])
        try:resource_baselines['unmanaged']=baseline_resources.sample()
        finally:baseline_resources.close()
        measure(baseline_exchange,'unmanaged_baseline','unmanaged')
        baseline_target.stdin.write(b'exit\n');baseline_target.stdin.flush();assert baseline_target.wait(timeout=30)==37;baseline_target=None
        target,exchange,errors=spawn(owned=args.origin=='run');baseline,_=exchange();original_pid=baseline['pid']
        assert baseline['pid']==original_pid and baseline['stable_stdio_cwd'] and baseline['stable_environment']
        resources=Resources(original_pid);time.sleep(1);resource_baselines['initial_'+args.origin]=resources.sample()
        assert exchange('read')[0]['read_result']==(13 if args.origin=='run' else 0) and exchange('socket')[0]['old_stream']
        checks.append('unmanaged_baseline_and_existing_connection')
        # An ABI marker in an unrelatedly named DLL must prevent double injection.
        legacy,legacy_exchange,legacy_errors=spawn(['--legacy-marker',str(marker)]);legacy_exchange()
        rejected=run(['attach',str(legacy.pid),'--backend','gum'],expected=2)
        assert legacy_exchange('read')[0]['read_result']==0
        legacy.stdin.write(b'exit\n');legacy.stdin.flush();assert legacy.wait(timeout=30)==37;legacy=None
        checks.append('generic_existing_native_base_rejected_before_mutation')
        if args.origin=='attach':
            held_child=exchange('spawn-survivor')[0]['child_pid']
            held_result=Path(str(secret)+'.survivor-result');deadline=time.monotonic()+30
            while True:
                try:value=json.loads(held_result.read_text())
                except (OSError,ValueError):value={}
                if value.get('pid')==held_child and value.get('read_result')==0:break
                assert time.monotonic()<deadline,'preexisting child did not reach unmanaged baseline'
                time.sleep(.05)
            assert exchange('stress-start')[0]['spawn_stress']
        started=time.monotonic();resources.anchor=started;resources.phase='pressure_preparing'
        while cycle<args.cycles or time.monotonic()-started<args.duration:
            resources.phase='preparing';tick=time.perf_counter_ns()
            if cycle==0 and args.origin=='run':
                records=json.loads(run(['status','--json']))['attachments']
                record=next(record for record in records if record['spec']['target']['pid']==original_pid and record['origin']=='run')
                proposal={'attachment_id':record['spec']['id']}
            else:
                proposal=json.loads(run(['attach',str(original_pid),'--scope','tree','--backend','gum']))
                assert proposal['status']=='approval_required'
                assert exchange('read')[0]['read_result']==0
                approve(proposal['request_id'])
            active_record=phase(proposal['attachment_id'],['active']);attached=time.perf_counter_ns()-tick
            resources.phase='active';resources.sample()
            assert exchange('read')[0]['read_result']==13
            if cycle==0:
                assert exchange('anon-map-heap-lock')[0]==anonymous_heap_baseline,'anonymous memory callback allocated or changed native errors under the heap lock'
                checks.append('anonymous_native_mapping_completes_before_foreign_heap_unlock')
            if cycle==0:measure(exchange,'active',args.origin)
            if cycle==0:
                probe=args.init_failure_probe.resolve();assert probe.is_file(),'build hyperhub-runtime example attachment_init_failure before native suite'
                initialized=subprocess.run([str(probe),native_agent_modules(original_pid)[0]],env=env,capture_output=True,timeout=20)
                (output/'native-init-failure.stdout').write_bytes(initialized.stdout);(output/'native-init-failure.stderr').write_bytes(initialized.stderr)
                assert initialized.returncode==0,('native init-failure admission regression',initialized.returncode,initialized.stderr.decode(errors='replace'))
                initialization=json.loads(initialized.stdout);assert initialization['phase']=='preparing' and not initialization['native_ready'] and initialization['fresh_control_requests']==0
                checks.append('valid_approval_cannot_activate_failed_unready_native_base')
                native_success=exchange('exec-last-error')[0];native_failure=exchange('exec-last-error-fail')[0]
                assert native_success['native_success'] and native_success['child_result']==13
                assert native_success['last_error']==native_success_baseline['last_error'],('successful process creation changed caller last-error',native_success_baseline,native_success)
                assert not native_failure['native_success'] and native_failure['last_error']==native_failure_baseline['last_error']
                checks.append('native_process_creation_preserves_original_success_and_failure_last_error')
                passive_log=temporary/'passive-load-must-not-initialize.log'
                passive_env=dict(env,HYPERHUB_AGENT_PATH=native_agent_modules(original_pid)[0],HYPERHUB_AGENT_DEBUG='1',HYPERHUB_AGENT_INIT_LOG=str(passive_log))
                passive,passive_exchange,passive_errors=spawn(['--legacy-marker',passive_env['HYPERHUB_AGENT_PATH']],environment=passive_env)
                passive_exchange();assert passive_exchange('read')[0]['read_result']==0
                passive.stdin.write(b'exit\n');passive.stdin.flush();assert passive.wait(timeout=30)==37;passive=None
                assert not passive_errors and not passive_log.exists(),'LoadLibrary or app environment caused implicit Agent startup'
                checks.append('verified_native_dll_load_is_passive_even_with_legacy_environment')
            if cycle==0:
                before_recovery=phase(proposal['attachment_id'],['active'])
                old_manager=terminate_disposable_manager(before_recovery)
                assert exchange('read')[0]['read_result']==13 and exchange('socket')[0]['old_stream']
                recovery=json.loads(run(['attach',str(original_pid),'--scope','tree','--backend','gum']))
                assert recovery['attachment_id']==proposal['attachment_id'] and recovery['status']=='approval_required'
                assert exchange('read')[0]['read_result']==13
                approve(recovery['request_id'])
                recovered=phase(proposal['attachment_id'],['active'],previous_manager=old_manager)
                assert recovered['manager']['pid']!=old_manager
                assert len(native_agent_modules(original_pid))==1 and exchange('read')[0]['read_result']==13
                checks.append('approved_manager_loss_recovery_reuses_exact_native_host')
            if cycle==0 and args.origin=='attach':
                assert any(member['pid']==held_child for member in active_record['members']), 'preexisting child missing from committed tree'
                deadline=time.monotonic()+30
                while True:
                    try:value=json.loads(held_result.read_text())
                    except (OSError,ValueError):value={}
                    if value.get('pid')==held_child and value.get('read_result')==13:break
                    assert time.monotonic()<deadline,'preexisting child remained unprotected after commit'
                    time.sleep(.05)
                commit_ms=active_record['updated_at_ms'];events_directory=Path(str(secret)+'.spawn-events')
                while True:
                    events=[]
                    for event in events_directory.glob('*.json'):
                        try:events.append(json.loads(event.read_text()))
                        except (OSError,ValueError):pass
                    post=[event for event in events if event['read_started_ms']>commit_ms+1]
                    assert all(event['read_result']==13 for event in post), ('post-commit in-flight child escaped',commit_ms,post)
                    if len(post)>=10:break
                    assert time.monotonic()<deadline,'busy-spawn target stopped making progress'
                    time.sleep(.05)
                assert exchange('stress-stop')[0]['stress_stopped']
                totals=exchange('stress-check')[0];assert totals['other']==0,('native child startup failed during busy tree transaction',totals)
                events=[json.loads(event.read_text()) for event in events_directory.glob('*.json')]
                post=[event for event in events if event['read_started_ms']>commit_ms+1]
                assert len(post)>=10 and all(event['read_result']==13 for event in post),('final in-flight child escaped commit boundary',post)
                spawn_boundary_evidence={'commit_record_updated_at_ms':commit_ms,'clock_guard_ms':1,'events':events,'strict_post_commit_count':len(post),'preexisting_child_pid':held_child}
                Path(str(secret)+'.survivor-stop').write_bytes(b'stop\n')
                wait_disposable_child(held_child)
                held_child=None;held_result.unlink(missing_ok=True);Path(str(secret)+'.survivor-stop').unlink(missing_ok=True)
                checks.append('busy_creation_gate_covers_preexisting_and_actual_commit_boundary_children')
            assert exchange('socket')[0]['old_stream'] and exchange('new-socket')[0]['new_stream']
            if cycle==0:assert exchange('exec-read')[0]['child_result']==13
            if cycle==0:assert exchange('credential')[0]['credential_status']==0
            assert exchange('block')[0]['blocked']
            request=json.loads(run(['detach',proposal['attachment_id']]));assert exchange('read')[0]['read_result']==13
            resources.phase='detaching';tick=time.perf_counter_ns();approve(request['request_id']);phase(proposal['attachment_id'],['draining','detached_resident','detaching'])
            assert native_agent_modules(original_pid), 'module unloaded while original ReadFile return was outstanding'
            assert exchange('unblock')[0]['blocked_original_preserved']
            assert exchange('socket')[0]['old_stream'], 'detach disturbed an existing connection'
            assert exchange('close-old')[0]['old_stream_closed']
            assert exchange('quiesce')[0]['quiescent']
            if cycle==0:
                retained=phase(proposal['attachment_id'],['detached_resident'])
                assert 'retained_schannel_credentials_or_contexts' in retained['compatibility_reasons']
                assert native_agent_modules(original_pid)
                old_manager=terminate_disposable_manager(retained)
                cleanup=json.loads(run(['detach',proposal['attachment_id']]))
                assert cleanup['status']=='approval_required' and exchange('read')[0]['read_result']==0
                approve(cleanup['request_id'])
                recovered=phase(proposal['attachment_id'],['detached_resident'],previous_manager=old_manager)
                assert recovered['manager']['pid']!=old_manager
                checks.append('approved_cleanup_recovery_preserves_detached_native_resources')
                # New detached credentials keep their caller's native flags.
                # They must neither depend on the Host nor prevent its unload.
                assert exchange('credential')[0]['credential_status']==0
                resources.phase='session_revocation_fault'
                with suspend_disposable_serve():
                    assert exchange('free-first-credential')[0]['credential_freed']
                    assert exchange('quiesce')[0]['quiescent']
                    record_path=Path(env['HYPERHUB_HOME'])/'runtime'/'attachments'/proposal['attachment_id']/'record.json'
                    deadline=time.monotonic()+20
                    while True:
                        try:pending=json.loads(record_path.read_text())
                        except (OSError,ValueError):pending={}
                        absent=not native_agent_modules(original_pid)
                        if absent and pending.get('phase')=='cleanup_pending' and 'physical_native_modules_absent_pending_session_revocation' in pending.get('compatibility_reasons',[]):break
                        assert time.monotonic()<deadline,('physical absence did not retain incomplete Core cleanup',pending)
                        time.sleep(.05)
                    assert exchange('read')[0]['read_result']==0
                    assert exchange('snapshot')[0]['stable_environment']
                checks.append('physical_native_absence_waits_for_core_revocation_ack_and_retries')
            final=phase(proposal['attachment_id'],['detached'])
            resources.phase='fully_detached';resource=resources.sample()
            if cycle==0:resource_baselines['post_detach_warmup']=resource
            else:
                warm=resource_baselines['post_detach_warmup']
                assert resource['handles']<=warm['handles']+8,('native handle growth after warmup',warm,resource)
                assert resource['threads']<=warm['threads']+1,('native thread growth after warmup',warm,resource)
            assert not native_agent_modules(original_pid), 'eligible target still has a native Agent module'
            if cycle==0:
                assert exchange('free-all-credentials')[0]['credentials_freed']
                checks.append('modified_schannel_credential_compatibility_drains_after_native_release')
            detached=time.perf_counter_ns()-tick
            assert exchange('read')[0]['read_result']==0 and exchange('socket')[0]['old_stream']
            if cycle==0:measure(exchange,'fully_detached',args.origin)
            snapshot,latency=exchange('snapshot')
            assert snapshot['pid']==original_pid and snapshot['stable_stdio_cwd'] and snapshot['stable_environment']
            assert snapshot['progress']>baseline['progress']
            assert snapshot['load_errors']==0 and snapshot['load_tcp_errors']==0,('mixed I/O workload failed',snapshot)
            samples.append({'cycle':cycle+1,'attach_ns':attached,'detach_ns':detached,'snapshot_ns':latency,'detach_phase':final['phase']})
            cycle+=1
        pressure_finished=time.monotonic();final_workload=snapshot
        checks.extend(['real_human_conpty_approval','proposal_before_mutation','file_policy_enforced','future_child_policy','connection_continuity','blocked_original_read_preserved','eligible_module_physically_absent','target_identity_environment_stdio_cwd_preserved','repeated_attach_detach'])
        if args.origin=='run':assert target.poll() is None, 'foreground launcher exited before original target'
        resources.phase='pressure_complete';resources.sample();resource_samples=resources.samples;resource_errors=resources.errors;resources.close();resources=None
        target.stdin.write(b'exit\n');target.stdin.flush();assert target.wait(timeout=30)==37
        assert not errors,('unexpected target stderr',bytes(errors).decode(errors='replace'));target=None
        checks.append('original_exit_status_37')
        # Keep issued-alias residency separate from the eligible-unload cases.
        # The ordinary native loopback connection is the reachability oracle;
        # cached issued addresses must reach that same peer while Core is paused.
        target,exchange,errors=spawn(owned=args.origin=='run');alias_baseline,_=exchange();alias_pid=alias_baseline['pid']
        if args.origin=='run':
            records=json.loads(run(['status','--json']))['attachments']
            alias_record=next(record for record in records if record['spec']['target']['pid']==alias_pid and record['origin']=='run')
            alias_id=alias_record['spec']['id']
        else:
            alias_proposal=json.loads(run(['attach',str(alias_pid),'--scope','process','--backend','gum']))
            approve(alias_proposal['request_id']);alias_id=alias_proposal['attachment_id']
        phase(alias_id,['active']);assert exchange('read')[0]['read_result']==13
        assert exchange('dns-invalid-numeric')[0]==dns_numeric_baseline, 'numeric-only DNS changed native failure or last-error'
        hints=exchange('cache-dns-hints')[0]
        assert hints['native_status']==dns_hints_baseline['native_status'] and hints['last_error']==dns_hints_baseline['last_error'] and hints['cached']
        assert exchange('cached-socket')[0]['cached_stream'], 'original DNS hints did not produce a usable alias'
        native_dns=exchange('cache-dns')[0]
        if args.origin=='attach':
            assert native_dns==native_dns_baseline,('external attach changed native DNS answers',native_dns_baseline,native_dns)
            checks.append('external_native_dns_answers_preserved_without_issued_reclassification')
        alias=exchange('cache-sdk-dns')[0];assert alias['sdk_status']==0 and alias['cached'] and alias['cached_address']!='127.0.0.1',('explicit SDK did not publish a dedicated-pool alias',alias)
        active_alias=exchange('cached-socket')[0];assert active_alias['cached_stream']
        assert exchange('bad-sockaddr-v6')[0]==bad_sockaddr_v6_baseline,'active mapped-address path changed native IPv6 argument errors'
        for command in mapped_baseline:
            mapped=exchange(command)[0]
            assert mapped['cached_stream'] and mapped['peer_family']==6,('active mapped alias changed socket family or failed',command,mapped)
        alias_detach=json.loads(run(['detach',alias_id]));approve(alias_detach['request_id'])
        assert exchange('close-old')[0]['old_stream_closed'];assert exchange('quiesce')[0]['quiescent']
        alias_resident=phase(alias_id,['detached_resident']);assert 'application_may_cache_fake_addresses' in alias_resident['compatibility_reasons']
        assert exchange('read')[0]['read_result']==0 and native_agent_modules(alias_pid)
        with suspend_disposable_serve():
            assert exchange('new-socket')[0]['new_stream'], 'native reachability oracle failed without Core'
            assert exchange('bad-sockaddr')[0]==bad_sockaddr_baseline, 'invalid sockaddr/descriptor changed native WSA errors or crashed'
            assert exchange('bad-sockaddr-v6')[0]==bad_sockaddr_v6_baseline,'detached mapped-address path changed native IPv6 argument errors'
            detached_alias=exchange('cached-socket')[0]
            assert detached_alias['cached_stream'] and detached_alias['native_peer']==f'127.0.0.1:{server.server_address[1]}',('detached alias used old gateway/Core rather than native cached peer',detached_alias)
            for command,expected in mapped_baseline.items():
                actual=exchange(command)[0]
                assert actual==expected,('detached mapped alias changed native fallback/family without Core',command,expected,actual)
        target.stdin.write(b'exit\n');target.stdin.flush();assert target.wait(timeout=30)==37
        assert not errors,('issued alias target stderr',bytes(errors).decode(errors='replace'));target=None
        checks.append('issued_cached_alias_uses_native_peer_without_core_and_retains_honest_residency')
        checks.append('issued_ipv4_alias_uses_same_dual_stack_family_blocking_and_nonblocking_without_core')
        checks.append('original_native_dns_hints_numeric_failure_and_last_error_preserved')
        checks.append('detached_invalid_socket_and_null_short_inaccessible_sockaddr_preserve_native_errors')
        # The keeper must outlive the original foreground root without owning
        # that root's stdio lifetime or substituting the keeper's exit status.
        target,exchange,errors=spawn(owned=True);owned_baseline,_=exchange();root_pid=owned_baseline['pid']
        records=json.loads(run(['status','--json']))['attachments']
        owned_record=next(record for record in records if record['spec']['target']['pid']==root_pid and record['origin']=='run')
        survivor_pid=exchange('spawn-survivor')[0]['child_pid']
        result_file=Path(str(secret)+'.survivor-result');stop_file=Path(str(secret)+'.survivor-stop')
        def survivor_result(expected):
            deadline=time.monotonic()+30
            while time.monotonic()<deadline:
                try:
                    value=json.loads(result_file.read_text())
                    if value.get('pid')==survivor_pid and value.get('read_result')==expected:return value
                except (OSError,ValueError):pass
                time.sleep(.05)
            raise AssertionError(('surviving descendant result unavailable',expected))
        survivor_result(13)
        target.stdin.write(b'exit\n');target.stdin.flush();assert target.wait(timeout=30)==37;target=None
        record=phase(owned_record['spec']['id'],['active'])
        assert any(member['pid']==survivor_pid for member in record['members']), 'keeper lost surviving child'
        request=json.loads(run(['detach',owned_record['spec']['id']]));approve(request['request_id']);survivor_result(0)
        phase(owned_record['spec']['id'],['detached'])
        assert not native_agent_modules(survivor_pid)
        stop_file.write_bytes(b'stop\n')
        checks.append('owned_run_root_exit_preserves_surviving_descendant_detach')
    except BaseException as error:
        failure=f'{type(error).__name__}: {error}'
    finally:
        if resources is not None:
            resource_samples=resources.samples;resource_errors=resources.errors;resources.close()
        try:Path(str(secret)+'.survivor-stop').write_bytes(b'stop\n')
        except OSError:pass
        for process in [baseline_target,passive,target,legacy]:
            if process is not None and process.poll() is None:
                try:process.stdin.write(b'exit\n');process.stdin.flush();process.wait(timeout=5)
                except BaseException:
                    process.terminate()
                    try:process.wait(timeout=5)
                    except BaseException as error:cleanup_errors.append(str(error))
        try:run(['stop'])
        except BaseException as error:cleanup_errors.append(str(error))
        server.shutdown();server.server_close();server_thread.join(timeout=3)
        try:shutil.rmtree(temporary)
        except BaseException as error:cleanup_errors.append(str(error))
        report={'schema_version':1,'status':'pass' if failure is None and not cleanup_errors and not resource_errors else 'failed','platform':'windows','backend':'gum','origin':args.origin,'cycles':cycle,'requested_cycles':args.cycles,'requested_duration_seconds':args.duration,'elapsed_seconds':(pressure_finished or time.monotonic())-started,'total_elapsed_seconds':time.monotonic()-harness_started,'spawn_boundary_evidence':spawn_boundary_evidence,'mixed_workload_final':final_workload,'mixed_workload_interval_seconds':.02,'intentional_quiescence_seconds_per_cycle':5,'checks':checks,'samples':samples,'performance':performance,'resource_baselines':resource_baselines,'resource_samples':resource_samples,'resource_errors':resource_errors,'phase_counts':{entry['phase']:entry['count'] for entry in performance},'commands':commands,'error':failure,'cleanup_errors':cleanup_errors,'cli_sha256':hashlib.sha256(binary.read_bytes()).hexdigest()}
        (output/'result.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    if failure or cleanup_errors or resource_errors:raise SystemExit(failure or str(cleanup_errors or resource_errors))
    print(f'Windows dynamic attachment passed: cycles={cycle}, duration={report["elapsed_seconds"]:.3f}s')
if __name__=='__main__':main()
