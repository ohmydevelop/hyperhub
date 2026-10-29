//! Disposable native Windows target for runtime attachment regressions.
use std::io::{self,BufRead,Read,Write};
use std::net::{TcpStream,ToSocketAddrs};
use std::sync::{Arc,atomic::{AtomicBool,AtomicU64,Ordering}};
use std::time::Duration;
use std::os::windows::io::{FromRawHandle};
use std::ffi::c_void;
#[repr(C)]struct Startup{size:u32,reserved:*mut u16,desktop:*mut u16,title:*mut u16,dimensions:[u32;8],show:u16,reserved_length:u16,reserved_bytes:*mut u8,input:*mut c_void,output:*mut c_void,error:*mut c_void}
#[repr(C)]struct ProcessInfo{process:*mut c_void,thread:*mut c_void,pid:u32,tid:u32}
#[link(name="kernel32")]
extern "system" {
 fn GetStdHandle(kind:u32)->*mut c_void;
 fn SetLastError(error:u32);fn GetLastError()->u32;
 fn CreateProcessW(application:*const u16,command:*mut u16,process_security:*const c_void,thread_security:*const c_void,inherit:i32,flags:u32,environment:*const c_void,cwd:*const u16,startup:*const Startup,information:*mut ProcessInfo)->i32;
 fn WaitForSingleObject(handle:*mut c_void,milliseconds:u32)->u32;fn GetExitCodeProcess(handle:*mut c_void,code:*mut u32)->i32;fn CloseHandle(handle:*mut c_void)->i32;

 fn LoadLibraryW(path:*const u16)->*mut c_void;
 fn K32EnumProcessModules(process:*mut c_void,modules:*mut usize,bytes:u32,needed:*mut u32)->i32;
 fn GetProcAddress(module:*mut c_void,name:*const u8)->*mut c_void;
 fn VirtualAlloc(address:*mut c_void,size:usize,kind:u32,protection:u32)->*mut c_void;fn VirtualFree(address:*mut c_void,size:usize,kind:u32)->i32;
 fn GetProcessHeap()->*mut c_void;fn HeapLock(heap:*mut c_void)->i32;fn HeapUnlock(heap:*mut c_void)->i32;
 fn CreateEventW(security:*const c_void,manual:i32,initial:i32,name:*const u16)->*mut c_void;fn SetEvent(event:*mut c_void)->i32;
 fn CreatePipe(read:*mut *mut c_void,write:*mut *mut c_void,security:*const c_void,size:u32)->i32;
}
#[link(name="ntdll")]extern "system"{
 fn NtCreateSection(out:*mut *mut c_void,access:u32,attributes:*const c_void,size:*const i64,protection:u32,flags:u32,file:*mut c_void)->i32;
 fn NtMapViewOfSection(section:*mut c_void,process:*mut c_void,base:*mut *mut c_void,zero:usize,commit:usize,offset:*const i64,size:*mut usize,inherit:u32,allocation:u32,protection:u32)->i32;
 fn NtUnmapViewOfSection(process:*mut c_void,base:*mut c_void)->i32;fn NtClose(handle:*mut c_void)->i32;
}
/// All Rust/loader setup precedes the heap lock. A separate waiting worker must
/// finish the actual anonymous NT memory calls before the heap owner unlocks.
fn anonymous_heap_oracle()->String{
 let events=unsafe{[CreateEventW(std::ptr::null(),1,0,std::ptr::null()),CreateEventW(std::ptr::null(),1,0,std::ptr::null()),CreateEventW(std::ptr::null(),1,0,std::ptr::null())]};
 if events.iter().any(|event|event.is_null()){for event in events{if !event.is_null(){unsafe{CloseHandle(event);}}}return "{\"setup_ok\":false}".into();}
 let handles=events.map(|event|event as usize);
 let worker=std::thread::spawn(move||unsafe{
  SetEvent(handles[0]as *mut c_void);if WaitForSingleObject(handles[1]as *mut c_void,10_000)!=0{SetEvent(handles[2]as *mut c_void);return [-1,-1,-1,-1,0];}
  let mut section=std::ptr::null_mut();let extent=4096i64;SetLastError(0x5a31);
  let create=NtCreateSection(&mut section,0xF001F,std::ptr::null(),&extent,4,0x08000000,std::ptr::null_mut());
  let mut base=std::ptr::null_mut();let mut length=4096usize;let process=usize::MAX as *mut c_void;
  let map=if create==0{NtMapViewOfSection(section,process,&mut base,0,0,std::ptr::null(),&mut length,1,0,4)}else{-1};
  let unmap=if map==0{NtUnmapViewOfSection(process,base)}else{-1};let close=if create==0{NtClose(section)}else{-1};let error=GetLastError()as i32;
  SetEvent(handles[2]as *mut c_void);[create,map,unmap,close,error]
 });
 let ready=unsafe{WaitForSingleObject(events[0],10_000)}==0;
 let heap=unsafe{GetProcessHeap()};let locked=ready && unsafe{HeapLock(heap)}!=0;
 unsafe{SetEvent(events[1]);}let completed=locked && unsafe{WaitForSingleObject(events[2],2_000)}==0;
 if locked{unsafe{HeapUnlock(heap);}}
 // JSON, joining and handle teardown may allocate only after the unlock.
 let statuses=worker.join().unwrap_or([-2,-2,-2,-2,0]);for event in events{unsafe{CloseHandle(event);}}
 format!("{{\"setup_ok\":{ready},\"heap_locked\":{locked},\"completed_while_locked\":{completed},\"create_status\":{},\"map_status\":{},\"unmap_status\":{},\"close_status\":{},\"last_error\":{}}}",statuses[0],statuses[1],statuses[2],statuses[3],statuses[4])
}

#[link(name="ws2_32")]extern "system"{#[link_name="socket"]fn native_socket(family:i32,kind:i32,protocol:i32)->usize;#[link_name="connect"]fn native_connect(socket:usize,address:*const u8,length:i32)->i32;#[link_name="closesocket"]fn native_close(socket:usize)->i32;fn WSAGetLastError()->i32;fn WSASetLastError(error:i32);}
fn bad_sockaddrs(cached:Option<std::net::SocketAddr>,family:i32)->String{
 let mut address=[0u8;28];address[..2].copy_from_slice(&2u16.to_ne_bytes());address[4..8].copy_from_slice(&[127,0,0,1]);if let Some(std::net::SocketAddr::V4(cached))=cached{address[4..8].copy_from_slice(&cached.ip().octets());address[2..4].copy_from_slice(&cached.port().to_be_bytes());}
 if family==23{let ip=match cached{Some(std::net::SocketAddr::V4(address))=>*address.ip(),_=>std::net::Ipv4Addr::LOCALHOST};address.fill(0);address[..2].copy_from_slice(&23u16.to_ne_bytes());address[8..24].copy_from_slice(&ip.to_ipv6_mapped().octets());}
 let inaccessible=unsafe{VirtualAlloc(std::ptr::null_mut(),4096,0x3000,1)};if inaccessible.is_null(){return "[]".into();}
 let cases=[(address.as_ptr(),16,true),(std::ptr::null(),16,false),(address.as_ptr(),0,false),(address.as_ptr(),1,false),(address.as_ptr(),2,false),(inaccessible.cast::<u8>() as *const u8,if family==23{28}else{16},false)];let mut result=Vec::new();
 for(pointer,length,invalid)in cases{let socket=if invalid{usize::MAX}else{unsafe{native_socket(family,1,6)}};unsafe{WSASetLastError(0x5a31);}let status=unsafe{native_connect(socket,pointer,length)};let error=unsafe{WSAGetLastError()};if socket!=usize::MAX{unsafe{native_close(socket);}}result.push(format!("{{\"status\":{status},\"error\":{error}}}"));}
 unsafe{VirtualFree(inaccessible,0,0x8000);}format!("[{}]",result.join(","))
}
#[repr(C)]struct AddrInfoW{flags:i32,family:i32,socktype:i32,protocol:i32,length:usize,canonical:*mut u16,address:*mut u8,next:*mut AddrInfoW}
#[link(name="ws2_32")]extern "system"{fn GetAddrInfoW(node:*const u16,service:*const u16,hints:*const AddrInfoW,result:*mut *mut AddrInfoW)->i32;fn FreeAddrInfoW(result:*mut AddrInfoW);}
fn native_lookup(port:u16,flags:i32)->(i32,u32,Option<std::net::SocketAddr>){
 let node:Vec<_>="localhost".encode_utf16().chain(Some(0)).collect();let service:Vec<_>=port.to_string().encode_utf16().chain(Some(0)).collect();
 let mut hints:AddrInfoW=unsafe{std::mem::zeroed()};hints.flags=flags;hints.family=2;hints.socktype=1;hints.protocol=6;let mut result=std::ptr::null_mut();
 unsafe{SetLastError(0x5a31);}let status=unsafe{GetAddrInfoW(node.as_ptr(),service.as_ptr(),&hints,&mut result)};let error=unsafe{GetLastError()};
 let mut cursor=result;let mut chosen=None;
 unsafe{while let Some(info)=cursor.as_ref(){if info.family==2 && !info.address.is_null() && info.length>=16{let bytes=std::slice::from_raw_parts(info.address,info.length);chosen=Some(std::net::SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::new(bytes[4],bytes[5],bytes[6],bytes[7])),u16::from_be_bytes([bytes[2],bytes[3]])));break;}cursor=info.next;}if !result.is_null(){FreeAddrInfoW(result);}}
 (status,error,chosen)
}
fn sdk_lookup(port:u16)->(i32,Option<std::net::SocketAddr>){
 type Resolve=unsafe extern "C" fn(*const i8,u32,*mut u32,*mut u8,usize,*mut usize)->i32;
 let mut modules=[0usize;1024];let mut needed=0;
 if unsafe{K32EnumProcessModules(usize::MAX as *mut c_void,modules.as_mut_ptr(),std::mem::size_of_val(&modules)as u32,&mut needed)}==0 || needed as usize>std::mem::size_of_val(&modules){return(-900,None);}
 for module in modules.iter().take(needed as usize/std::mem::size_of::<usize>()){
  let address=unsafe{GetProcAddress(*module as *mut c_void,b"hh_agent_resolve_name\0".as_ptr())};if address.is_null(){continue;}
  let resolve:Resolve=unsafe{std::mem::transmute(address)};let mut family=0;let mut bytes=[0u8;16];let mut written=0;
  let status=unsafe{resolve(b"localhost\0".as_ptr().cast(),4,&mut family,bytes.as_mut_ptr(),bytes.len(),&mut written)};
  let result=(status==0 && family==4 && written==4).then(||std::net::SocketAddr::new(std::net::Ipv4Addr::new(bytes[0],bytes[1],bytes[2],bytes[3]).into(),port));return(status,result);
 }
 (-901,None)
}
fn cached_connection(cached:Option<std::net::SocketAddr>,mapped:bool,nonblocking:bool)->String{
 let address=cached.map(|address|if mapped{match address{std::net::SocketAddr::V4(address)=>std::net::SocketAddr::V6(std::net::SocketAddrV6::new(address.ip().to_ipv6_mapped(),address.port(),0,0)),address=>address}}else{address});
 let mut peer=String::new();let mut peer_family=0;
 let ok=address.and_then(|address|{if nonblocking{TcpStream::connect_timeout(&address,Duration::from_secs(5))}else{TcpStream::connect(address)}}.ok()).is_some_and(|mut stream|{if let Ok(address)=stream.peer_addr(){peer_family=if address.is_ipv6(){6}else{4};peer=address.to_string();}stream.set_read_timeout(Some(Duration::from_secs(5))).is_ok() && stream.set_write_timeout(Some(Duration::from_secs(5))).is_ok() && echo(&mut stream)});
 format!("{{\"cached_stream\":{ok},\"native_peer\":\"{peer}\",\"peer_family\":{peer_family}}}")
}
#[repr(C)]#[derive(Clone,Copy,Default)]struct SecurityHandle{lower:usize,upper:usize}
#[repr(C)]struct SchannelCredential{version:u32,count:u32,certificates:*mut c_void,root:*mut c_void,mappers:u32,mapper_list:*mut c_void,algorithms:u32,algorithm_list:*mut c_void,protocols:u32,min_cipher:u32,max_cipher:u32,lifespan:u32,flags:u32,format:u32}
#[link(name="secur32")]extern "system"{
 fn AcquireCredentialsHandleW(principal:*mut u16,package:*mut u16,usage:u32,logon:*mut c_void,auth:*mut c_void,key:*mut c_void,key_arg:*mut c_void,handle:*mut SecurityHandle,expiry:*mut i64)->i32;
 fn FreeCredentialsHandle(handle:*mut SecurityHandle)->i32;
}
fn acquire_credential()->Result<SecurityHandle,i32>{
 let mut configuration:SchannelCredential=unsafe{std::mem::zeroed()};configuration.version=4;
 let mut package:Vec<u16>="Schannel".encode_utf16().chain(Some(0)).collect();let mut handle=SecurityHandle::default();let mut expiry=0;
 let code=unsafe{AcquireCredentialsHandleW(std::ptr::null_mut(),package.as_mut_ptr(),2,std::ptr::null_mut(),(&mut configuration as *mut SchannelCredential).cast(),std::ptr::null_mut(),std::ptr::null_mut(),&mut handle,&mut expiry)};
 if code==0{Ok(handle)}else{Err(code)}
}
fn read_secret(path:&str)->i32 {
 match std::fs::read(path){Ok(bytes) if bytes==b"S\n"=>0,Ok(_)=>21,Err(e) if e.kind()==io::ErrorKind::PermissionDenied=>13,Err(_)=>20}
}
fn echo(stream:&mut TcpStream)->bool {stream.write_all(b"E").is_ok() && {let mut byte=[0];stream.read_exact(&mut byte).is_ok() && byte==*b"E"}}
fn connect(port:u16)->io::Result<TcpStream>{let stream=TcpStream::connect(("127.0.0.1",port))?;stream.set_read_timeout(Some(Duration::from_secs(10)))?;stream.set_write_timeout(Some(Duration::from_secs(10)))?;Ok(stream)}
#[derive(Default)]struct LoadCounts{allowed:AtomicU64,denied:AtomicU64,errors:AtomicU64,tcp_ok:AtomicU64,tcp_errors:AtomicU64}
fn main(){std::process::exit(run());}
fn run()->i32 {
 let args:Vec<_>=std::env::args().collect();if args.len()<3{return 2;}
 let path=&args[1];let port:u16=match args[2].parse(){Ok(p)=>p,Err(_)=>return 3};
 if args.get(3).is_some_and(|arg|arg=="--read-once"){return read_secret(path);}
 if args.get(3).is_some_and(|arg|arg=="--read-trace"){
  let Some(directory)=args.get(4)else{return 26;};
  let before=std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();let code=read_secret(path);let after=std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
  let report=format!("{{\"pid\":{},\"read_started_ms\":{},\"read_finished_ms\":{},\"read_result\":{code}}}",std::process::id(),before/1_000_000,after/1_000_000);
  if std::fs::write(std::path::Path::new(directory).join(format!("{}-{before}.json",std::process::id())),report).is_err(){return 27;}return code;
 }
 if args.get(3).is_some_and(|arg|arg=="--survivor-controlled"){
  let result=format!("{path}.survivor-result");let stop=format!("{path}.survivor-stop");
  while !std::path::Path::new(&stop).exists(){let report=format!("{{\"pid\":{},\"read_result\":{}}}",std::process::id(),read_secret(path));if std::fs::write(&result,report).is_err(){return 22;}std::thread::sleep(Duration::from_millis(100));}
  return 37;
 }
 if args.get(3).is_some_and(|arg|arg=="--legacy-marker"){
  let Some(path)=args.get(4)else{return 18;};let wide:Vec<_>=path.encode_utf16().chain(Some(0)).collect();
  if unsafe{LoadLibraryW(wide.as_ptr())}.is_null(){return 19;}
 }
 let environment:Vec<_>=["HOME","USERPROFILE","PATH","SSL_CERT_FILE","CURL_CA_BUNDLE"].iter().map(|key|((*key).to_owned(),std::env::var_os(key))).collect();
 let cwd=match std::env::current_dir(){Ok(cwd)=>cwd,Err(_)=>return 4};
 let streams=unsafe{[GetStdHandle((-10i32) as u32) as usize,GetStdHandle((-11i32) as u32) as usize,GetStdHandle((-12i32) as u32) as usize]};
 let progress=Arc::new(AtomicU64::new(0));let running=Arc::new(AtomicBool::new(true));
 let load=Arc::new(LoadCounts::default());let load_pause=Arc::new(AtomicBool::new(false));let load_paused=Arc::new(AtomicBool::new(false));
 let worker_running=running.clone();let worker_progress=progress.clone();let worker_load=load.clone();let pause=load_pause.clone();let paused=load_paused.clone();let worker_path=path.clone();
 let worker=std::thread::spawn(move||{let mut stream=None;while worker_running.load(Ordering::Acquire){
  if pause.load(Ordering::Acquire){drop(stream.take());paused.store(true,Ordering::Release);while pause.load(Ordering::Acquire) && worker_running.load(Ordering::Acquire){std::thread::sleep(Duration::from_millis(1));}paused.store(false,Ordering::Release);continue;}
  match read_secret(&worker_path){0=>{worker_load.allowed.fetch_add(1,Ordering::Relaxed);},13=>{worker_load.denied.fetch_add(1,Ordering::Relaxed);},_=>{worker_load.errors.fetch_add(1,Ordering::Relaxed);}}
  if stream.is_none(){stream=connect(port).ok();}
  if stream.as_mut().is_some_and(echo){worker_load.tcp_ok.fetch_add(1,Ordering::Relaxed);}else{worker_load.tcp_errors.fetch_add(1,Ordering::Relaxed);drop(stream.take());}
  worker_progress.fetch_add(1,Ordering::Relaxed);std::thread::sleep(Duration::from_millis(20));
 }});
 let snapshot=||{
  let stable_env=environment.iter().all(|(key,value)|std::env::var_os(key)==*value);
  let handles=unsafe{[GetStdHandle((-10i32) as u32) as usize,GetStdHandle((-11i32) as u32) as usize,GetStdHandle((-12i32) as u32) as usize]};
  let stable=handles==streams && std::env::current_dir().is_ok_and(|value|value==cwd);
  println!("{{\"pid\":{},\"progress\":{},\"stable_stdio_cwd\":{},\"stable_environment\":{},\"load_allowed\":{},\"load_denied\":{},\"load_errors\":{},\"load_tcp_ok\":{},\"load_tcp_errors\":{}}}",std::process::id(),progress.load(Ordering::Relaxed),stable,stable_env,load.allowed.load(Ordering::Relaxed),load.denied.load(Ordering::Relaxed),load.errors.load(Ordering::Relaxed),load.tcp_ok.load(Ordering::Relaxed),load.tcp_errors.load(Ordering::Relaxed));
 };
 let mut initial=match connect(port){Ok(stream)=>stream,Err(_)=>return 5};if !echo(&mut initial){return 6;}let mut old=Some(initial);
 let mut credentials:Vec<Option<SecurityHandle>>=Vec::new();
 let mut blocked:Option<(std::fs::File,std::thread::JoinHandle<bool>)>=None;
 let stress_epoch=Arc::new(AtomicU64::new(0));let stress_allowed=Arc::new(AtomicU64::new(0));let stress_denied=Arc::new(AtomicU64::new(0));let stress_other=Arc::new(AtomicU64::new(0));
 let mut stress:Option<(Arc<AtomicBool>,std::thread::JoinHandle<()>)>=None;
 let mut cached=None;snapshot();let _=io::stdout().flush();
 for line in io::stdin().lock().lines(){
  let Ok(line)=line else{break;};
  match line.as_str(){
   "anon-map-heap-lock"=>println!("{}",anonymous_heap_oracle()),
   "credential"=>match acquire_credential(){Ok(handle)=>{credentials.push(Some(handle));println!("{{\"credential_slot\":{},\"credential_status\":0}}",credentials.len()-1);},Err(code)=>println!("{{\"credential_status\":{code}}}")},
   "free-first-credential"=>{let code=credentials.first_mut().and_then(Option::take).map(|mut handle|unsafe{FreeCredentialsHandle(&mut handle)}).unwrap_or(-1);println!("{{\"credential_freed\":{}}}",code==0);},
   "free-all-credentials"=>{let mut okay=true;for handle in &mut credentials{if let Some(mut handle)=handle.take(){okay &= unsafe{FreeCredentialsHandle(&mut handle)}==0;}}println!("{{\"credentials_freed\":{okay}}}");},
   "read"=>println!("{{\"read_result\":{}}}",read_secret(path)),
   "socket"=>{if old.is_none(){old=connect(port).ok();}println!("{{\"old_stream\":{}}}",old.as_mut().is_some_and(echo));},
   "close-old"=>{drop(old.take());println!("{{\"old_stream_closed\":true}}");},
   "new-socket"=>{let ok=connect(port).is_ok_and(|mut stream|echo(&mut stream));println!("{{\"new_stream\":{ok}}}");},
   "bad-sockaddr"=>println!("{{\"native_errors\":{}}}",bad_sockaddrs(cached,2)),
   "bad-sockaddr-v6"=>println!("{{\"native_errors\":{}}}",bad_sockaddrs(cached,23)),
   "cache-dns-hints"|"dns-invalid-numeric"=>{let flags=if line=="dns-invalid-numeric"{4}else{1026};let(status,error,address)=native_lookup(port,flags);if line=="cache-dns-hints"{cached=address;}println!("{{\"native_status\":{status},\"last_error\":{error},\"cached\":{},\"cached_address\":\"{}\"}}",address.is_some(),address.map(|address|address.ip().to_string()).unwrap_or_default());},
   "cache-dns"=>{cached=("localhost",port).to_socket_addrs().ok().and_then(|mut list|list.find(|a|a.is_ipv4()));println!("{{\"cached\":{},\"cached_address\":\"{}\"}}",cached.is_some(),cached.map(|address|address.ip().to_string()).unwrap_or_default());},
   "cache-sdk-dns"=>{let(status,address)=sdk_lookup(port);cached=address;println!("{{\"sdk_status\":{status},\"cached\":{},\"cached_address\":\"{}\"}}",cached.is_some(),cached.map(|address|address.ip().to_string()).unwrap_or_default());},
   "cached-socket"=>println!("{}",cached_connection(cached,false,true)),
   "cached-mapped-blocking"=>println!("{}",cached_connection(cached,true,false)),
   "cached-mapped-nonblocking"=>println!("{}",cached_connection(cached,true,true)),
   "snapshot"=>snapshot(),
   "quiesce"=>{load_pause.store(true,Ordering::Release);while !load_paused.load(Ordering::Acquire){std::thread::yield_now();}println!("{{\"quiescent\":true}}");let _=io::stdout().flush();std::thread::sleep(Duration::from_secs(5));load_pause.store(false,Ordering::Release);},
   "block"=>{
    if blocked.is_some(){return 7;}
    let(mut read,mut write)=(std::ptr::null_mut(),std::ptr::null_mut());
    if unsafe{CreatePipe(&mut read,&mut write,std::ptr::null(),0)}==0{return 8;}
    let mut read=unsafe{std::fs::File::from_raw_handle(read)};let write=unsafe{std::fs::File::from_raw_handle(write)};
    let ready=Arc::new(AtomicBool::new(false));let mark=ready.clone();
    let thread=std::thread::spawn(move||{mark.store(true,Ordering::Release);let mut byte=[0];read.read_exact(&mut byte).is_ok() && byte==*b"B"});
    while !ready.load(Ordering::Acquire){std::thread::yield_now();}
    std::thread::sleep(Duration::from_millis(40));blocked=Some((write,thread));println!("{{\"blocked\":true}}");
   },
   "unblock"=>{let Some((mut write,thread))=blocked.take()else{return 9;};if write.write_all(b"B").is_err(){return 10;}drop(write);println!("{{\"blocked_original_preserved\":{}}}",thread.join().unwrap_or(false));},
   "stress-start"=>{
    if stress.is_some(){return 24;}
    let active=Arc::new(AtomicBool::new(true));let work=active.clone();let epoch=stress_epoch.clone();let allowed=stress_allowed.clone();let denied=stress_denied.clone();let other=stress_other.clone();let path=path.clone();let trace=format!("{path}.spawn-events");if std::fs::create_dir_all(&trace).is_err(){return 28;}
    let thread=std::thread::spawn(move||while work.load(Ordering::Acquire){
     let started=epoch.load(Ordering::Acquire);
     let code=std::env::current_exe().ok().and_then(|exe|std::process::Command::new(exe).args([&path,&port.to_string(),"--read-trace",&trace]).stdin(std::process::Stdio::null()).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null()).status().ok()).and_then(|status|status.code()).unwrap_or(255);
     if started==epoch.load(Ordering::Acquire){match code{0=>{allowed.fetch_add(1,Ordering::Relaxed);},13=>{denied.fetch_add(1,Ordering::Relaxed);},_=>{other.fetch_add(1,Ordering::Relaxed);}}}
     std::thread::sleep(Duration::from_millis(5));
    });stress=Some((active,thread));println!("{{\"spawn_stress\":true}}");
   },
   "stress-reset"=>{stress_allowed.store(0,Ordering::Release);stress_denied.store(0,Ordering::Release);stress_other.store(0,Ordering::Release);stress_epoch.fetch_add(1,Ordering::AcqRel);println!("{{\"stress_reset\":true}}");},
   "stress-check"=>println!("{{\"allowed\":{},\"denied\":{},\"other\":{}}}",stress_allowed.load(Ordering::Acquire),stress_denied.load(Ordering::Acquire),stress_other.load(Ordering::Acquire)),
   "stress-stop"=>{if let Some((active,thread))=stress.take(){active.store(false,Ordering::Release);let _=thread.join();}println!("{{\"stress_stopped\":true}}");},
   "spawn-survivor"=>{let child=std::env::current_exe().ok().and_then(|exe|std::process::Command::new(exe).args([path,&port.to_string(),"--survivor-controlled"]).stdin(std::process::Stdio::null()).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null()).spawn().ok());match child{Some(child)=>println!("{{\"child_pid\":{}}}",child.id()),None=>return 23}},
   "exec-last-error"|"exec-last-error-fail"=>{
    let Some(executable)=std::env::current_exe().ok()else{return 25;};let failing=line=="exec-last-error-fail";
    let executable=if failing{executable.with_file_name("missing-disposable-fixture.exe")}else{executable};
    let executable:Vec<u16>=executable.to_string_lossy().encode_utf16().chain(Some(0)).collect();
    let mut command:Vec<u16>=format!("\"fixture\" \"{path}\" {port} --read-once").encode_utf16().chain(Some(0)).collect();
    let mut startup:Startup=unsafe{std::mem::zeroed()};startup.size=std::mem::size_of::<Startup>() as u32;let mut information:ProcessInfo=unsafe{std::mem::zeroed()};
    unsafe{SetLastError(0x5a31);}
    let success=unsafe{CreateProcessW(executable.as_ptr(),command.as_mut_ptr(),std::ptr::null(),std::ptr::null(),0,0,std::ptr::null(),std::ptr::null(),&startup,&mut information)};
    let error=unsafe{GetLastError()};let mut code=255;
    if success!=0{unsafe{let _=WaitForSingleObject(information.process,30000);let _=GetExitCodeProcess(information.process,&mut code);CloseHandle(information.thread);CloseHandle(information.process);}}
    println!("{{\"native_success\":{},\"last_error\":{error},\"child_result\":{code}}}",success!=0);
   },
   "exec-read"=>{let result=std::env::current_exe().ok().and_then(|exe|std::process::Command::new(exe).args([path,&port.to_string(),"--read-once"]).status().ok()).and_then(|status|status.code()).unwrap_or(255);println!("{{\"child_result\":{result}}}");},
   "exit"=>break,
   _=>return 11,
  }
  if io::stdout().flush().is_err(){return 12;}
 }
 if let Some((mut write,thread))=blocked.take(){let _=write.write_all(b"B");drop(write);let _=thread.join();}
 for handle in &mut credentials{if let Some(mut handle)=handle.take(){let _=unsafe{FreeCredentialsHandle(&mut handle)};}}
 if let Some((active,thread))=stress.take(){active.store(false,Ordering::Release);let _=thread.join();}
 running.store(false,Ordering::Release);let _=worker.join();37
}
