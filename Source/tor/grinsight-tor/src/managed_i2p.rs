//! Managed Java I2P router prototype for Windows, local SAM only.
//! The returned guard owns the child and Windows job object.
#[cfg(windows)]
pub mod windows {
    use std::ffi::c_void;
    use std::fs::{self, File, OpenOptions};
    use std::io::{Read, Write};
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpListener, TcpStream, Shutdown};
    use std::sync::{Arc, atomic::{AtomicBool, AtomicUsize, Ordering}};
    use std::thread::{self, JoinHandle};
    use std::os::windows::io::AsRawHandle;
    use std::os::windows::process::CommandExt;
    use std::path::Path;
    use std::process::{Child, Command, Stdio};
    use std::time::{Duration, Instant};

    type Handle = *mut c_void;
    const JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE: u32 = 0x2000;
    const CREATE_NO_WINDOW: u32 = 0x08000000;
    const CREATE_SUSPENDED: u32 = 0x00000004;
    const TH32CS_SNAPTHREAD: u32 = 0x00000004;
    const THREAD_SUSPEND_RESUME: u32 = 0x0002;
    const LOCKFILE_EXCLUSIVE_LOCK: u32 = 2;
    const LOCKFILE_FAIL_IMMEDIATELY: u32 = 1;
    #[repr(C)] #[derive(Default)] struct BasicLimits {
        per_process_user_time: i64, per_job_user_time: i64, flags: u32,
        min_working_set: usize, max_working_set: usize, active_process_limit: u32,
        affinity: usize, priority_class: u32, scheduling_class: u32,
    }
    #[repr(C)] #[derive(Default)] struct IoCounters { read_ops:u64, write_ops:u64, other_ops:u64, read_bytes:u64, write_bytes:u64, other_bytes:u64 }
    #[repr(C)] #[derive(Default)] struct ExtendedLimits {
        basic: BasicLimits, io: IoCounters, process_memory: usize, job_memory: usize,
        peak_process: usize, peak_job: usize,
    }
    #[repr(C)] #[derive(Default)] struct Overlapped { internal:usize, internal_high:usize, offset:u32, offset_high:u32, event:Handle }
    #[repr(C)] #[derive(Default)] struct ThreadEntry {size:u32, usage:u32, thread_id:u32, owner_pid:u32, base_priority:i32, delta_priority:i32, flags:u32}
    #[link(name="kernel32")] extern "system" {
        fn CreateJobObjectW(attributes: *mut c_void, name:*const u16) -> Handle;
        fn SetInformationJobObject(job: Handle, class:u32, info:*const c_void, size:u32) -> i32;
        fn AssignProcessToJobObject(job: Handle, process:Handle) -> i32;
        fn CloseHandle(handle:Handle) -> i32;
        fn LockFileEx(file:Handle, flags:u32, reserved:u32, low:u32, high:u32, overlapped:*mut Overlapped) -> i32;
        fn CreateToolhelp32Snapshot(flags:u32, process_id:u32)->Handle;
        fn Thread32First(snapshot:Handle, entry:*mut ThreadEntry)->i32;
        fn Thread32Next(snapshot:Handle, entry:*mut ThreadEntry)->i32;
        fn OpenThread(access:u32, inherit:i32, thread_id:u32)->Handle;
        fn ResumeThread(thread:Handle)->u32;
    }
    #[repr(C)] #[derive(Clone, Copy)] struct TcpRow { state:u32, local_addr:u32, local_port:u32, remote_addr:u32, remote_port:u32, pid:u32 }
    #[link(name="iphlpapi")] extern "system" {
        fn GetExtendedTcpTable(table:*mut c_void, size:*mut u32, sorted:i32, family:u32, class:u32, reserved:u32)->u32;
    }
    fn err(prefix:&str) -> String { format!("{prefix}: {}", std::io::Error::last_os_error()) }
    struct Job(Handle);
    impl Job {
        fn new() -> Result<Self,String> {
            let h=unsafe { CreateJobObjectW(std::ptr::null_mut(),std::ptr::null()) };
            if h.is_null() {return Err(err("cannot create I2P job"));}
            let job=Self(h); let mut limits=ExtendedLimits::default();
            limits.basic.flags=JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            if unsafe { SetInformationJobObject(job.0,9,&limits as *const _ as *const c_void,std::mem::size_of::<ExtendedLimits>() as u32) }==0 {return Err(err("cannot restrict I2P job"));}
            Ok(job)
        }
        fn assign(&self, child:&Child)->Result<(),String> {
            if unsafe { AssignProcessToJobObject(self.0,child.as_raw_handle() as Handle) }==0 {return Err(err("cannot own I2P process"));}
            Ok(())
        }
    }
    impl Drop for Job { fn drop(&mut self) {unsafe {CloseHandle(self.0);}} }
    fn resume_initial_thread(pid:u32)->Result<(),String> {
        let snapshot=unsafe {CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD,0)};
        if snapshot as isize == -1 {return Err(err("cannot inspect I2P launch thread"));}
        let mut entry=ThreadEntry {size:std::mem::size_of::<ThreadEntry>() as u32,..ThreadEntry::default()};
        let mut found=false; let mut ok=unsafe {Thread32First(snapshot,&mut entry)};
        while ok!=0 {
            if entry.owner_pid==pid {
                let thread=unsafe {OpenThread(THREAD_SUSPEND_RESUME,0,entry.thread_id)};
                if thread.is_null() {unsafe {CloseHandle(snapshot);};return Err(err("cannot open I2P launch thread"));}
                let result=unsafe {ResumeThread(thread)}; unsafe {CloseHandle(thread);}
                if result==u32::MAX {unsafe {CloseHandle(snapshot);};return Err(err("cannot resume I2P launch thread"));}
                if result!=1 {unsafe {CloseHandle(snapshot);};return Err("unexpected I2P launch thread state".into());}
                found=true; break;
            }
            ok=unsafe {Thread32Next(snapshot,&mut entry)};
        }
        unsafe {CloseHandle(snapshot);}
        if found {Ok(())} else {Err("I2P launch thread not found".into())}
    }
    fn lock_state(dir:&Path)->Result<File,String> {
        let file=OpenOptions::new().read(true).write(true).create(true).open(dir.join("grinsight-router.lock")).map_err(|e|e.to_string())?;
        let mut ov=Overlapped::default();
        if unsafe {LockFileEx(file.as_raw_handle() as Handle,LOCKFILE_EXCLUSIVE_LOCK|LOCKFILE_FAIL_IMMEDIATELY,0,1,0,&mut ov)}==0 {return Err("I2P router state is already in use".into());}
        Ok(file)
    }
    fn tcp_rows(class:u32)->Result<Vec<TcpRow>,String> {
        let mut size=0u32;
        let r=unsafe {GetExtendedTcpTable(std::ptr::null_mut(),&mut size,0,2,class,0)};
        if r!=122 || size<4 {return Err(format!("cannot query TCP ownership ({r})"));}
        let mut buf=vec![0u64;(size as usize+7)/8];
        let r=unsafe {GetExtendedTcpTable(buf.as_mut_ptr().cast(),&mut size,0,2,class,0)};
        if r!=0 {return Err(format!("cannot query TCP ownership ({r})"));}
        let count=unsafe {*(buf.as_ptr().cast::<u32>())} as usize;
        let head=4usize; let row_size=std::mem::size_of::<TcpRow>();
        if count > (size as usize).saturating_sub(head)/row_size {return Err("invalid TCP table".into());}
        let mut rows=Vec::with_capacity(count);
        for i in 0..count { rows.push(unsafe {std::ptr::read_unaligned((buf.as_ptr() as *const u8).add(head+i*row_size).cast::<TcpRow>())}); }
        Ok(rows)
    }
    fn listener_port_owned(pid:u32, port:u16)->Result<bool,String> {
        let ip=u32::from_ne_bytes([127,0,0,1]);
        Ok(tcp_rows(3)?.iter().any(|r|r.state==2 && r.pid==pid && r.local_addr==ip && u16::from_be(r.local_port as u16)==port))
    }
    /// Verify the server-side established socket, not just a listener PID before connect.
    fn connected_owned(pid:u32, stream:&TcpStream)->Result<bool,String> {
        let local=match stream.local_addr().map_err(|e|e.to_string())? {SocketAddr::V4(v)=>v,_=>return Ok(false)};
        let peer=match stream.peer_addr().map_err(|e|e.to_string())? {SocketAddr::V4(v)=>v,_=>return Ok(false)};
        let local_ip=u32::from_ne_bytes(local.ip().octets());let peer_ip=u32::from_ne_bytes(peer.ip().octets());
        Ok(tcp_rows(5)?.iter().any(|r|r.state==5 && r.pid==pid && r.local_addr==peer_ip && r.remote_addr==local_ip && u16::from_be(r.local_port as u16)==peer.port() && u16::from_be(r.remote_port as u16)==local.port()))
    }
    fn forward_owned(mut front:TcpStream,target:SocketAddr,pid:u32) {
        let Ok(mut back)=TcpStream::connect_timeout(&target,Duration::from_secs(2)) else{return};
        // No byte is read from the front socket until the exact server-side connection
        // is confirmed to belong to our router process. No direct-network fallback.
        if !matches!(connected_owned(pid,&back),Ok(true)) {let _=back.shutdown(Shutdown::Both);return;}
        let Ok(mut front_read)=front.try_clone() else{return};let Ok(mut back_write)=back.try_clone() else{return};
        let up=thread::spawn(move || {let _=std::io::copy(&mut front_read,&mut back_write);let _=back_write.shutdown(Shutdown::Write);});
        let _=std::io::copy(&mut back,&mut front);let _=front.shutdown(Shutdown::Both);let _=back.shutdown(Shutdown::Both);let _=up.join();
    }
    fn spawn_proxy(listener:TcpListener,target:SocketAddr,pid:u32,stop:Arc<AtomicBool>,active:Arc<AtomicUsize>)->Result<JoinHandle<()>,String> {
        listener.set_nonblocking(true).map_err(|e|e.to_string())?;
        Ok(thread::spawn(move || while !stop.load(Ordering::Acquire) {
            match listener.accept() {
                Ok((stream,peer)) if peer.ip().is_loopback() => {
                    if stream.set_nonblocking(false).is_err() { continue; }
                    if active.fetch_add(1,Ordering::AcqRel)>=32 {active.fetch_sub(1,Ordering::AcqRel);continue;}
                    let count=active.clone();thread::spawn(move || {forward_owned(stream,target,pid);count.fetch_sub(1,Ordering::AcqRel);});
                }
                Ok(_) => {},
                Err(e) if e.kind()==std::io::ErrorKind::WouldBlock => thread::sleep(Duration::from_millis(30)),
                Err(_) => break,
            }
        }))
    }
    fn write_config(path:&Path, data:&str)->Result<(),String> {
        let tmp=path.with_extension(format!("new-{}",std::process::id()));
        let mut f=OpenOptions::new().write(true).create_new(true).open(&tmp).map_err(|e|e.to_string())?;
        f.write_all(data.as_bytes()).and_then(|_|f.sync_all()).map_err(|e|e.to_string())?;drop(f);
        // Windows rename over an existing target is supported by std::fs::rename.
        fs::rename(&tmp,path).map_err(|e|e.to_string())
    }
    fn prepare_state(state:&Path,sam:u16,i2cp:u16,socks:u16)->Result<(),String> {
        fs::create_dir_all(state.join("clients.config.d")).map_err(|e|e.to_string())?;
        let path=state.join("router.config");
        let existing=match fs::read_to_string(&path) {Ok(x)=>x,Err(e) if e.kind()==std::io::ErrorKind::NotFound=>String::new(),Err(e)=>return Err(e.to_string())};
        let keys=["i2cp.port", "i2cp.tcp.bindAllInterfaces", "i2np.upnp.enable", "routerconsole.browserStart"];
        let mut config=String::new();
        for l in existing.lines() { if !keys.iter().any(|k| l.trim_start().strip_prefix(k).is_some_and(|v| v.trim_start().starts_with('='))) {config.push_str(l);config.push('\n');} }
        config.push_str(&format!("i2cp.port={i2cp}\ni2cp.tcp.bindAllInterfaces=false\ni2np.upnp.enable=false\nrouterconsole.browserStart=false\n"));
        write_config(&path,&config)?;
        let sam_conf=format!("clientApp.0.main=net.i2p.sam.SAMBridge\nclientApp.0.name=GrinSight SAM\nclientApp.0.args=sam.keys 127.0.0.1 {sam} i2cp.tcp.host=127.0.0.1 i2cp.tcp.port={i2cp}\nclientApp.0.startOnLoad=true\nclientApp.0.delay=0\n");
        write_config(&state.join("clients.config.d/00-grinsight-sam-clients.config"),&sam_conf)?;
        let app_conf="clientApp.0.main=net.i2p.i2ptunnel.TunnelControllerGroup\nclientApp.0.name=GrinSight I2P tunnels\nclientApp.0.startOnLoad=true\nclientApp.0.delay=0\n";
        write_config(&state.join("clients.config.d/01-grinsight-tunnels-clients.config"),app_conf)?;
        fs::create_dir_all(state.join("i2ptunnel.config.d")).map_err(|e|e.to_string())?;
        let tunnel=format!("type=sockstunnel\nname=GrinSight SOCKS\ninterface=127.0.0.1\nlistenPort={socks}\ni2cpHost=127.0.0.1\ni2cpPort={i2cp}\nstartOnLoad=true\nsharedClient=false\noption.i2cp.delayOpen=true\noption.inbound.length=3\noption.outbound.length=3\n");
        write_config(&state.join("i2ptunnel.config.d/00-grinsight-socks-i2ptunnel.config"),&tunnel)
    }
    pub struct RouterGuard { child:Child, _job:Job, _lock:File, sam:SocketAddr, socks:SocketAddr, stop:Arc<AtomicBool>, proxies:Vec<JoinHandle<()>> }
    impl RouterGuard {
        pub fn sam(&self)->SocketAddr {self.sam}
        pub fn socks(&self)->SocketAddr {self.socks}
        pub fn pid(&self)->u32 {self.child.id()}
        pub fn running(&mut self)->bool {matches!(self.child.try_wait(), Ok(None))}
    }
    impl Drop for RouterGuard {fn drop(&mut self) {self.stop.store(true,Ordering::Release);let _=self.child.kill();let _=self.child.wait();for t in self.proxies.drain(..){let _=t.join();}}}
    /// The package contains `runtime/bin/java.exe` and `router/{lib,certificates,hosts.txt}`.
    /// `state` must be a private app-owned profile directory; no deletion occurs.
    pub fn start(package:&Path, state:&Path, timeout:Duration)->Result<RouterGuard,String> {
        let java=package.join("runtime/bin/java.exe");let base=package.join("router");
        if !java.is_file() || !base.join("hosts.txt").is_file() || !base.join("lib/router.jar").is_file() || !base.join("lib/sam.jar").is_file() {return Err("bundled I2P components missing".into());}
        fs::create_dir_all(state).map_err(|e|e.to_string())?;let lock=lock_state(state)?;
        let a=TcpListener::bind((Ipv4Addr::LOCALHOST,0)).map_err(|e|e.to_string())?;
        let b=TcpListener::bind((Ipv4Addr::LOCALHOST,0)).map_err(|e|e.to_string())?;
        let c=TcpListener::bind((Ipv4Addr::LOCALHOST,0)).map_err(|e|e.to_string())?;
        let front_sam=TcpListener::bind((Ipv4Addr::LOCALHOST,0)).map_err(|e|e.to_string())?;
        let front_socks=TcpListener::bind((Ipv4Addr::LOCALHOST,0)).map_err(|e|e.to_string())?;
        let sam=a.local_addr().map_err(|e|e.to_string())?.port();let i2cp=b.local_addr().map_err(|e|e.to_string())?.port();let socks=c.local_addr().map_err(|e|e.to_string())?.port();
        prepare_state(state,sam,i2cp,socks)?;let job=Job::new()?;
        let mut cmd=Command::new(&java);
        cmd.args(["-Xmx160m","-Djava.awt.headless=true"]).arg(format!("-Di2p.dir.base={}",base.display())).arg(format!("-Di2p.dir.config={}",state.display()))
           .arg("-cp").arg(base.join("lib/*")).arg("net.i2p.router.RouterLaunch").current_dir(state).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).creation_flags(CREATE_NO_WINDOW|CREATE_SUSPENDED);
        drop(a);drop(b);drop(c);
        let mut child=cmd.spawn().map_err(|e|format!("cannot start bundled I2P: {e}"))?;
        if let Err(e)=job.assign(&child){let _=child.kill();let _=child.wait();return Err(e);}
        if let Err(e)=resume_initial_thread(child.id()){let _=child.kill();let _=child.wait();return Err(e);}
        let pid=child.id();let address=SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST,sam));let socks_address=SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST,socks));let deadline=Instant::now()+timeout;
        loop {
            if let Some(exit)=child.try_wait().map_err(|e|e.to_string())? {return Err(format!("bundled I2P stopped ({exit})"));}
            if Instant::now()>=deadline {let _=child.kill();let _=child.wait();return Err("bundled I2P SAM startup timed out".into());}
            match listener_port_owned(pid,sam) {
                Ok(true)=> {
                    if let Ok(mut stream)=TcpStream::connect_timeout(&address,Duration::from_secs(1)) {
                        let _=stream.set_read_timeout(Some(Duration::from_secs(2)));
                        if stream.write_all(b"HELLO VERSION MIN=3.0 MAX=3.3\n").is_ok() {
                            let mut buf=[0u8;256]; if let Ok(n)=stream.read(&mut buf) {
                                let text=String::from_utf8_lossy(&buf[..n]);
                                if text.starts_with("HELLO REPLY ") && text.contains("RESULT=OK") && connected_owned(pid,&stream)? && listener_port_owned(pid,socks)? {
                                    if let Ok(mut proxy)=TcpStream::connect_timeout(&socks_address,Duration::from_secs(1)) {
                                        let _=proxy.set_read_timeout(Some(Duration::from_secs(2)));
                                        let mut reply=[0u8;2];
                                        if connected_owned(pid,&proxy)? && proxy.write_all(&[5,1,0]).is_ok() && proxy.read_exact(&mut reply).is_ok() && reply==[5,0] {
                                            let sam_front=front_sam.local_addr().map_err(|e|e.to_string())?;
                                            let socks_front=front_socks.local_addr().map_err(|e|e.to_string())?;
                                            let stop=Arc::new(AtomicBool::new(false));let active=Arc::new(AtomicUsize::new(0));
                                            let first=spawn_proxy(front_sam,address,pid,stop.clone(),active.clone())?;
                                            let second=match spawn_proxy(front_socks,socks_address,pid,stop.clone(),active) {
                                                Ok(t)=>t,Err(e)=>{stop.store(true,Ordering::Release);let _=first.join();return Err(e)}
                                            };
                                            return Ok(RouterGuard {child,_job:job,_lock:lock,sam:sam_front,socks:socks_front,stop,proxies:vec![first,second]});
                                        }
                                    }
                                }
                            }
                        }
                    }
                }, Ok(false)=>{}, Err(e)=> {let _=child.kill();let _=child.wait();return Err(e);}
            }
            std::thread::sleep(Duration::from_millis(500));
        }
    }
    // SAM startup is not network readiness. Do not mark I2P reachable on this signal alone.
    #[cfg(test)] mod tests {
        use super::*;
        #[test] fn established_connection_owner_checks_both_sides_and_pid() {
            let listener=TcpListener::bind((Ipv4Addr::LOCALHOST,0)).unwrap();
            let client=TcpStream::connect(listener.local_addr().unwrap()).unwrap();
            let (server,_)=listener.accept().unwrap();
            assert!(connected_owned(std::process::id(),&client).unwrap());
            assert!(!connected_owned(u32::MAX,&client).unwrap());
            drop(server);drop(client);
        }
        #[test] fn nonblocking_listener_keeps_both_proxy_directions_open() {
            let backend=TcpListener::bind((Ipv4Addr::LOCALHOST,0)).unwrap();
            let target=backend.local_addr().unwrap();
            let frontend=TcpListener::bind((Ipv4Addr::LOCALHOST,0)).unwrap();
            let address=frontend.local_addr().unwrap();
            let stop=Arc::new(AtomicBool::new(false));
            let proxy=spawn_proxy(frontend,target,std::process::id(),stop.clone(),Arc::new(AtomicUsize::new(0))).unwrap();
            let peer=thread::spawn(move || {
                let (mut sock,_)=backend.accept().unwrap();
                sock.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
                let mut first=[0;1];sock.read_exact(&mut first).unwrap();assert_eq!(first,[1]);sock.write_all(&[2]).unwrap();
                let mut next=[0;1];sock.read_exact(&mut next).unwrap();assert_eq!(next,[3]);sock.write_all(&[4]).unwrap();
            });
            let mut client=TcpStream::connect(address).unwrap();client.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            client.write_all(&[1]).unwrap();let mut response=[0;1];client.read_exact(&mut response).unwrap();assert_eq!(response,[2]);
            thread::sleep(Duration::from_millis(100));
            client.write_all(&[3]).unwrap();client.read_exact(&mut response).unwrap();assert_eq!(response,[4]);
            drop(client);peer.join().unwrap();stop.store(true,Ordering::Release);proxy.join().unwrap();
        }
        #[test] fn proxy_rejects_unowned_backend_before_forwarding_data() {
            let backend=TcpListener::bind((Ipv4Addr::LOCALHOST,0)).unwrap();
            let frontend=TcpListener::bind((Ipv4Addr::LOCALHOST,0)).unwrap();
            let target=backend.local_addr().unwrap();
            let mut client=TcpStream::connect(frontend.local_addr().unwrap()).unwrap();
            let (front,_)=frontend.accept().unwrap();
            let t=thread::spawn(move || forward_owned(front,target,u32::MAX));
            client.write_all(b"secret-must-not-leak").unwrap();
            let (mut fake,_)=backend.accept().unwrap();fake.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            let mut buf=[0u8;32];
            let n=fake.read(&mut buf).unwrap_or(0);assert_eq!(n,0);
            t.join().unwrap();
        }
    }
}
