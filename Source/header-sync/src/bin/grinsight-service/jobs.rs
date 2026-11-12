//! Long operations (sync, wallet scan, send, confirm, broadcast) run as jobs:
//! the RPC call returns a job id at once, the app polls `job.status`.
//! A job runs its child processes through [`run_exe`]; `job.cancel` kills the
//! running child (the core writes every file atomically, so a killed run
//! leaves the previous state).

use serde_json::{json, Value};
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(Default)]
pub struct Job {
    pub id: String,
    pub kind: String,
    pub state: Mutex<String>,
    pub phase: Mutex<String>,
    pub lines: Mutex<Vec<String>>,
    pub result: Mutex<Value>,
    pub error: Mutex<String>,
    pub cancel: AtomicBool,
    pub child: Mutex<Option<u32>>,
    pub started: u64,
    pub finished: AtomicU64,
}

impl Job {
    pub fn phase(&self, p: &str) {
        *self.phase.lock().unwrap() = p.to_string();
        self.line(&format!("== {p}"));
    }

    pub fn line(&self, l: &str) {
        let mut v = self.lines.lock().unwrap();
        v.push(l.chars().take(400).collect());
        let n = v.len();
        if n > 200 {
            v.drain(..n - 200);
        }
    }

    pub fn cancelled(&self) -> bool {
        self.cancel.load(Ordering::SeqCst)
    }

    pub fn json(&self, all_lines: bool) -> Value {
        let lines = self.lines.lock().unwrap();
        let shown: Vec<&String> = if all_lines { lines.iter().collect() } else { lines.iter().rev().take(12).rev().collect() };
        json!({
            "id": self.id, "kind": self.kind,
            "state": *self.state.lock().unwrap(),
            "phase": *self.phase.lock().unwrap(),
            "lines": shown,
            "result": *self.result.lock().unwrap(),
            "error": *self.error.lock().unwrap(),
            "started": self.started,
            "finished": self.finished.load(Ordering::SeqCst),
        })
    }
}

#[derive(Default)]
pub struct Jobs {
    map: Mutex<HashMap<String, Arc<Job>>>,
    next: AtomicU64,
    /// One job that changes the wallet at a time (two scans would race on
    /// the state and wallet files; the core also locks the pending journal).
    busy: Mutex<Option<String>>,
}

impl Jobs {
    /// Starts `f` in a thread. `exclusive` jobs refuse to start while another
    /// exclusive job runs.
    pub fn start<F>(self: &Arc<Self>, kind: &str, exclusive: bool, f: F) -> Result<String, String>
    where
        F: FnOnce(&Job) -> Result<Value, String> + Send + 'static,
    {
        if exclusive {
            let mut b = self.busy.lock().unwrap();
            if let Some(other) = b.as_ref() {
                return Err(format!("another wallet operation is running (job {other}); wait or cancel it"));
            }
            *b = Some(String::new());
        }
        let id = format!("{}-{}", kind, self.next.fetch_add(1, Ordering::SeqCst) + 1);
        if exclusive {
            *self.busy.lock().unwrap() = Some(id.clone());
        }
        let job = Arc::new(Job {
            id: id.clone(),
            kind: kind.into(),
            state: Mutex::new("running".into()),
            started: grinsight_state::session::now_unix() as u64,
            ..Default::default()
        });
        self.map.lock().unwrap().insert(id.clone(), job.clone());
        let me = self.clone();
        std::thread::spawn(move || {
            let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| f(&job)));
            let (state, res, err) = match r {
                Ok(Ok(v)) => ("done", v, String::new()),
                Ok(Err(e)) if job.cancelled() => ("cancelled", Value::Null, e),
                Ok(Err(e)) => ("failed", Value::Null, e),
                Err(_) => ("failed", Value::Null, "internal error (panic)".into()),
            };
            *job.result.lock().unwrap() = res;
            *job.error.lock().unwrap() = err;
            *job.state.lock().unwrap() = state.into();
            job.finished.store(grinsight_state::session::now_unix() as u64, Ordering::SeqCst);
            if exclusive {
                *me.busy.lock().unwrap() = None;
            }
        });
        Ok(id)
    }

    pub fn get(&self, id: &str) -> Option<Arc<Job>> {
        self.map.lock().unwrap().get(id).cloned()
    }

    pub fn list(&self) -> Vec<Value> {
        let mut v: Vec<Arc<Job>> = self.map.lock().unwrap().values().cloned().collect();
        v.sort_by_key(|j| j.started);
        v.iter().map(|j| j.json(false)).collect()
    }

    pub fn busy(&self) -> Option<String> {
        self.busy.lock().unwrap().clone()
    }

    pub fn cancel(&self, id: &str) -> Result<(), String> {
        let j = self.get(id).ok_or("no such job")?;
        j.cancel.store(true, Ordering::SeqCst);
        if let Some(pid) = *j.child.lock().unwrap() {
            kill(pid);
        }
        Ok(())
    }
}

fn kill(pid: u32) {
    #[cfg(windows)]
    let _ = Command::new("taskkill").args(["/PID", &pid.to_string(), "/T", "/F"]).stdout(Stdio::null()).stderr(Stdio::null()).status();
    #[cfg(not(windows))]
    let _ = Command::new("kill").args(["-9", &pid.to_string()]).status();
}

#[derive(Debug)]
pub struct Done {
    pub code: i32,
    pub stdout: String,
}

impl Done {
    pub fn value(&self, key: &str) -> Option<&str> {
        self.stdout.lines().rev().find_map(|l| l.strip_prefix(key).and_then(|r| r.strip_prefix('=')))
    }
    pub fn values(&self, key: &str) -> Vec<&str> {
        self.stdout.lines().filter_map(|l| l.strip_prefix(key).and_then(|r| r.strip_prefix('='))).collect()
    }
}

/// Runs a core program. `seeds`: written to its stdin (`--seeds -`).
/// stdout+stderr go to `log`; stdout lines also to the job (progress).
pub fn run_exe(
    program: &Path,
    args: &[String],
    seeds: Option<&str>,
    log: &Path,
    job: Option<&Job>,
    timeout: Duration,
) -> Result<Done, String> {
    if let Some(j) = job {
        if j.cancelled() {
            return Err("cancelled".into());
        }
    }
    let mut cmd = Command::new(program);
    cmd.args(args).stdout(Stdio::piped()).stderr(Stdio::piped());
    cmd.stdin(if seeds.is_some() { Stdio::piped() } else { Stdio::null() });
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
    }
    let mut child: Child = cmd.spawn().map_err(|e| format!("{}: {e}", program.display()))?;
    if let Some(j) = job {
        *j.child.lock().unwrap() = Some(child.id());
    }
    if let (Some(s), Some(mut stdin)) = (seeds, child.stdin.take()) {
        let _ = stdin.write_all(s.as_bytes());
        let _ = stdin.write_all(b"\n");
    }
    let mut err_pipe = child.stderr.take().unwrap();
    let err_t = std::thread::spawn(move || {
        let mut e = Vec::new();
        let _ = err_pipe.read_to_end(&mut e);
        String::from_utf8_lossy(&e).into_owned()
    });
    let out_pipe = child.stdout.take().unwrap();
    let (tx, rx) = std::sync::mpsc::channel::<String>();
    let out_t = std::thread::spawn(move || {
        for l in BufReader::new(out_pipe).lines().map_while(Result::ok) {
            if tx.send(l).is_err() {
                break;
            }
        }
    });
    let mut stdout = String::new();
    let start = Instant::now();
    let mut timed_out = false;
    loop {
        match rx.recv_timeout(Duration::from_millis(200)) {
            Ok(l) => {
                if let Some(j) = job {
                    if progress_line(&l) {
                        j.line(&l);
                    }
                }
                stdout.push_str(&l);
                stdout.push('\n');
            }
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
            Err(_) => {}
        }
        if start.elapsed() > timeout {
            timed_out = true;
        }
        if timed_out || job.is_some_and(|j| j.cancelled()) {
            // Do not wait for the pipe: a grandchild may still hold it open.
            let _ = child.kill();
            break;
        }
    }
    if !timed_out && !job.is_some_and(|j| j.cancelled()) {
        let _ = out_t.join();
    }
    let status = child.wait().map_err(|e| e.to_string())?;
    if let Some(j) = job {
        *j.child.lock().unwrap() = None;
    }
    let killed = timed_out || job.is_some_and(|j| j.cancelled());
    let stderr = if killed { String::new() } else { err_t.join().unwrap_or_default() };
    let _ = std::fs::write(log, format!("$ {} {}\n{stdout}\n--- stderr ---\n{stderr}", program.display(), args.join(" ")));
    if job.is_some_and(|j| j.cancelled()) {
        return Err("cancelled".into());
    }
    if timed_out {
        return Err(format!("timed out after {}s", timeout.as_secs()));
    }
    Ok(Done { code: status.code().unwrap_or(-1), stdout })
}

/// Lines worth showing as progress (no per-output detail, no keys).
fn progress_line(l: &str) -> bool {
    const KEYS: &[&str] = &[
        "HEADER_SYNC=", "HEADER_SYNC_LAST_HEIGHT=", "HEADER_SYNC_PROGRESS=", "HEADER_SYNC_SAVED_PROGRESS", "HEADER_SYNC_PEERS_OK=", "HEADER_SYNC_PEER_RESULT=", "HEADER_SYNC_BLOCK_BATCH=",
        "GAP_INSTALL_MODE=", "GAP_ARCHIVE_HEIGHT=", "GAP_TIP_HEIGHT=", "GAP_PROVE_SEGMENTS=", "GAP_SCAN_RPROOF_PROGRESS=",
        "GAP_PEER_BLOCKS=", "GAP_BLOCKS_SECONDS=", "GAP_WALLET=", "GAP_STATE_SAVED=", "GAP_PROVE_VERDICT=", "GAP=FAIL",
        "PROBE_PEER=", "BROADCAST_TX=", "FINALIZE=", "RECEIVE=", "INVOICE=", "SEND=", "PAY_INVOICE=", "GAP_KERNEL=",
        "GAP_BLOCK_CHECK=", "GAP_WALLET_STALE=", "GAP_RECONNECT=",
    ];
    KEYS.iter().any(|k| l.starts_with(k))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn runner_stdin_progress_cancel_timeout() {
        let d = std::env::temp_dir().join(format!("gs-jobs-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        let log = d.join("x.log");
        let r = run_exe(
            Path::new("/bin/sh"),
            &["-c".into(), "read s; echo HEADER_SYNC=PASS; echo secret-free; echo \"GOT=$s\"; exit 3".into()],
            Some("one two"),
            &log,
            None,
            Duration::from_secs(5),
        )
        .unwrap();
        assert_eq!((r.code, r.value("GOT")), (3, Some("one two")));
        assert!(std::fs::read_to_string(&log).unwrap().contains("HEADER_SYNC=PASS"));
        let e = run_exe(Path::new("/bin/sleep"), &["5".into()], None, &log, None, Duration::from_millis(300));
        assert!(e.unwrap_err().contains("timed out"));
        // A job: progress lines only; cancel kills the child.
        let jobs = Arc::new(Jobs::default());
        let log2 = log.clone();
        let id = jobs
            .start("t", true, move |j| {
                run_exe(Path::new("/bin/sh"), &["-c".into(), "echo GAP_TIP_HEIGHT=5; echo noise; sleep 30".into()], None, &log2, Some(j), Duration::from_secs(60))
                    .map(|_| json!(1))
            })
            .unwrap();
        assert!(jobs.start("t2", true, |_| Ok(json!(0))).is_err(), "exclusive");
        let j = jobs.get(&id).unwrap();
        // Wait for the child's first line (not a fixed time: slow under load).
        for _ in 0..200 {
            if !j.lines.lock().unwrap().is_empty() {
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        jobs.cancel(&id).unwrap();
        for _ in 0..50 {
            if *j.state.lock().unwrap() != "running" {
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        let v = j.json(true);
        assert_eq!(v["state"], "cancelled");
        assert_eq!(v["lines"], json!(["GAP_TIP_HEIGHT=5"]));
        assert!(jobs.busy().is_none());
        let _ = std::fs::remove_dir_all(&d);
    }
}
