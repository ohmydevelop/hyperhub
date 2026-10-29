"""Minimal native ConPTY host for interactive CLI regression tests.

The child sees real console handles. Tests do not bypass is_terminal() or the
administrator approval boundary. All I/O stays in disposable private pipes.
"""
import ctypes
from ctypes import wintypes as w
import os
import subprocess
import threading
import time

class COORD(ctypes.Structure):
    _fields_=[('X',ctypes.c_short),('Y',ctypes.c_short)]
class STARTUPINFO(ctypes.Structure):
    _fields_=[('cb',w.DWORD),('lpReserved',w.LPWSTR),('lpDesktop',w.LPWSTR),('lpTitle',w.LPWSTR),('dwX',w.DWORD),('dwY',w.DWORD),('dwXSize',w.DWORD),('dwYSize',w.DWORD),('dwXCountChars',w.DWORD),('dwYCountChars',w.DWORD),('dwFillAttribute',w.DWORD),('dwFlags',w.DWORD),('wShowWindow',w.WORD),('cbReserved2',w.WORD),('lpReserved2',ctypes.POINTER(ctypes.c_byte)),('hStdInput',w.HANDLE),('hStdOutput',w.HANDLE),('hStdError',w.HANDLE)]
class STARTUPINFOEX(ctypes.Structure):
    _fields_=[('StartupInfo',STARTUPINFO),('lpAttributeList',ctypes.c_void_p)]
class PROCESS_INFORMATION(ctypes.Structure):
    _fields_=[('hProcess',w.HANDLE),('hThread',w.HANDLE),('dwProcessId',w.DWORD),('dwThreadId',w.DWORD)]

class Console:
    def __init__(self,arguments,environment,cwd=None):
        if os.name!='nt':
            raise RuntimeError('native Windows ConPTY is required')
        k=ctypes.WinDLL('kernel32',use_last_error=True)
        k.CreatePipe.argtypes=[ctypes.POINTER(w.HANDLE),ctypes.POINTER(w.HANDLE),ctypes.c_void_p,w.DWORD];k.CreatePipe.restype=w.BOOL
        k.CloseHandle.argtypes=[w.HANDLE];k.CloseHandle.restype=w.BOOL
        k.CreatePseudoConsole.argtypes=[COORD,w.HANDLE,w.HANDLE,w.DWORD,ctypes.POINTER(w.HANDLE)];k.CreatePseudoConsole.restype=ctypes.c_long
        k.ClosePseudoConsole.argtypes=[w.HANDLE];k.ClosePseudoConsole.restype=None
        k.InitializeProcThreadAttributeList.argtypes=[ctypes.c_void_p,w.DWORD,w.DWORD,ctypes.POINTER(ctypes.c_size_t)];k.InitializeProcThreadAttributeList.restype=w.BOOL
        k.UpdateProcThreadAttribute.argtypes=[ctypes.c_void_p,w.DWORD,ctypes.c_size_t,ctypes.c_void_p,ctypes.c_size_t,ctypes.c_void_p,ctypes.c_void_p];k.UpdateProcThreadAttribute.restype=w.BOOL
        k.DeleteProcThreadAttributeList.argtypes=[ctypes.c_void_p];k.DeleteProcThreadAttributeList.restype=None
        k.CreateProcessW.argtypes=[w.LPCWSTR,w.LPWSTR,ctypes.c_void_p,ctypes.c_void_p,w.BOOL,w.DWORD,ctypes.c_void_p,w.LPCWSTR,ctypes.POINTER(STARTUPINFOEX),ctypes.POINTER(PROCESS_INFORMATION)];k.CreateProcessW.restype=w.BOOL
        k.ReadFile.argtypes=[w.HANDLE,ctypes.c_void_p,w.DWORD,ctypes.POINTER(w.DWORD),ctypes.c_void_p];k.ReadFile.restype=w.BOOL
        k.WriteFile.argtypes=[w.HANDLE,ctypes.c_void_p,w.DWORD,ctypes.POINTER(w.DWORD),ctypes.c_void_p];k.WriteFile.restype=w.BOOL
        k.WaitForSingleObject.argtypes=[w.HANDLE,w.DWORD];k.WaitForSingleObject.restype=w.DWORD
        k.TerminateProcess.argtypes=[w.HANDLE,w.UINT];k.TerminateProcess.restype=w.BOOL
        k.GetExitCodeProcess.argtypes=[w.HANDLE,ctypes.POINTER(w.DWORD)];k.GetExitCodeProcess.restype=w.BOOL
        self.k=k;self.handles=[];self.console=None;self.attributes=None;self.process=None;self.data=bytearray();self.lock=threading.Lock()
        incoming_read=w.HANDLE();incoming_write=w.HANDLE();outgoing_read=w.HANDLE();outgoing_write=w.HANDLE()
        try:
            self._check(k.CreatePipe(ctypes.byref(incoming_read),ctypes.byref(incoming_write),None,0))
            self.handles.extend([incoming_read,incoming_write])
            self._check(k.CreatePipe(ctypes.byref(outgoing_read),ctypes.byref(outgoing_write),None,0))
            self.handles.extend([outgoing_read,outgoing_write])
            console=w.HANDLE();status=k.CreatePseudoConsole(COORD(160,50),incoming_read,outgoing_write,0,ctypes.byref(console))
            if status!=0:
                raise OSError(f'CreatePseudoConsole failed: HRESULT 0x{status & 0xffffffff:08x}')
            self.console=console
            size=ctypes.c_size_t();k.InitializeProcThreadAttributeList(None,1,0,ctypes.byref(size))
            self.attribute_storage=ctypes.create_string_buffer(size.value);self.attributes=ctypes.cast(self.attribute_storage,ctypes.c_void_p)
            self._check(k.InitializeProcThreadAttributeList(self.attributes,1,0,ctypes.byref(size)))
            self._check(k.UpdateProcThreadAttribute(self.attributes,0,0x00020016,console,ctypes.sizeof(w.HANDLE),None,None))
            startup=STARTUPINFOEX();startup.StartupInfo.cb=ctypes.sizeof(startup);startup.lpAttributeList=self.attributes
            self.environment=ctypes.create_unicode_buffer('\0'.join(f'{key}={value}' for key,value in sorted(environment.items(),key=lambda pair:pair[0].upper()))+'\0\0')
            command=ctypes.create_unicode_buffer(subprocess.list2cmdline([str(a) for a in arguments]));info=PROCESS_INFORMATION()
            self._check(k.CreateProcessW(str(arguments[0]),command,None,None,False,0x00080000|0x00000400,self.environment,str(cwd) if cwd else None,ctypes.byref(startup),ctypes.byref(info)))
            self.process=info.hProcess;self.handles.extend([info.hProcess,info.hThread]);self.input=incoming_write;self.output=outgoing_read
            # Conhost owns its pipe ends now. Retaining these would hide EOF.
            for handle in [incoming_read,outgoing_write]:
                k.CloseHandle(handle);self.handles.remove(handle)
            self.reader=threading.Thread(target=self._read,daemon=True);self.reader.start()
        except BaseException:
            self.close();raise
    def _check(self,result):
        if not result:raise ctypes.WinError(ctypes.get_last_error())
    def _read(self):
        buffer=ctypes.create_string_buffer(8192)
        while True:
            count=w.DWORD()
            if not self.k.ReadFile(self.output,buffer,len(buffer),ctypes.byref(count),None) or count.value==0:return
            with self.lock:self.data.extend(buffer.raw[:count.value])
    def transcript(self):
        with self.lock:return bytes(self.data)
    def send(self,text):
        data=text.encode('utf-8');buffer=ctypes.create_string_buffer(data);written=w.DWORD()
        self._check(self.k.WriteFile(self.input,buffer,len(data),ctypes.byref(written),None))
        if written.value!=len(data):raise OSError('incomplete ConPTY input')
    def wait_for(self,needle,timeout=30):
        deadline=time.monotonic()+timeout
        while time.monotonic()<deadline:
            if needle in self.transcript():return
            if self.k.WaitForSingleObject(self.process,0)==0:raise AssertionError('console child exited before expected prompt')
            time.sleep(.01)
        raise TimeoutError('console child did not produce expected prompt')
    def wait(self,timeout=90):
        if self.k.WaitForSingleObject(self.process,int(timeout*1000))!=0:raise TimeoutError('console child did not exit')
        result=w.DWORD();self._check(self.k.GetExitCodeProcess(self.process,ctypes.byref(result)));return result.value
    def close(self):
        # Only this harness-created console child is terminated on test failure.
        # Real user targets are never passed here.
        if self.process and self.k.WaitForSingleObject(self.process,0)!=0:
            self.k.TerminateProcess(self.process,1);self.k.WaitForSingleObject(self.process,5000)
        if self.attributes:
            self.k.DeleteProcThreadAttributeList(self.attributes);self.attributes=None
        if self.console:
            self.k.ClosePseudoConsole(self.console);self.console=None
        for handle in reversed(self.handles):self.k.CloseHandle(handle)
        self.handles=[]
        if hasattr(self,'reader'):self.reader.join(timeout=3)
    def __enter__(self):return self
    def __exit__(self,*_):self.close()
