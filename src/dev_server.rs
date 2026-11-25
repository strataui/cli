//! Development server with real state-preserving Hot Module Replacement (HMR).
//!
//! Coordinates:
//! - Recursive debounced filesystem watching (`strata_hot_reload::DirectoryWatcher`)
//! - Incremental `cargo build --lib --message-format=json` cdylib compilation
//! - Cross-platform JSON-Lines HMR IPC delivery (`strata_hot_reload::HmrIpcClient`)
//! - Child application launching with `STRATA_HMR_SOCKET` wired automatically

use std::io::{BufRead, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use strata_hot_reload::{
    default_hmr_socket_path, DirectoryWatcher, HmrIpcClient, HmrRequest, HmrResponse,
    STRATA_HMR_SOCKET_ENV,
};

use crate::args::BuildTarget;

/// Real metrics returned after an incremental cdylib compile and live IPC hot-patch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HmrPatchReport {
    pub dylib_path: PathBuf,
    pub epoch: u64,
    pub compile_ms: u64,
    pub swap_us: u64,
    pub signals_restored: usize,
}

/// Active Hot Module Replacement session coordinating state preservation and dynamic reloads.
#[derive(Debug, Clone)]
pub struct HmrSession {
    pub session_id: String,
    pub signal_snapshot_bytes: Option<Vec<u8>>,
    pub reload_count: usize,
    pub is_active: bool,
    pub last_reload_unix_ms: u64,
    pub last_compile_ms: Option<u64>,
    pub last_swap_us: Option<u64>,
    pub last_signals_restored: usize,
}

impl Default for HmrSession {
    fn default() -> Self {
        Self::new()
    }
}

impl HmrSession {
    /// Creates a new HMR coordination session.
    pub fn new() -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        Self {
            session_id: format!("hmr-{}", now),
            signal_snapshot_bytes: None,
            reload_count: 0,
            is_active: true,
            last_reload_unix_ms: now,
            last_compile_ms: None,
            last_swap_us: None,
            last_signals_restored: 0,
        }
    }

    /// Serializes active reactive state into the session snapshot buffer.
    pub fn snapshot_state(&mut self, bytes: Vec<u8>) {
        self.signal_snapshot_bytes = Some(bytes);
    }

    /// Retrieves the serialized state buffer to restore signal values after module re-compilation.
    pub fn restore_state(&self) -> Option<&[u8]> {
        self.signal_snapshot_bytes.as_deref()
    }

    /// Increments reload count, updates timestamp, and records a hot-reload cycle.
    pub fn trigger_reload(&mut self) -> usize {
        self.reload_count += 1;
        self.last_reload_unix_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        self.reload_count
    }

    /// Records verified metrics from a completed [`HmrPatchReport`].
    pub fn record_patch_report(&mut self, report: &HmrPatchReport) {
        self.reload_count = report.epoch as usize;
        self.last_compile_ms = Some(report.compile_ms);
        self.last_swap_us = Some(report.swap_us);
        self.last_signals_restored = report.signals_restored;
        self.last_reload_unix_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
    }
}

/// Orchestrates real Cargo incremental `cdylib` compilation and IPC delivery to a live Strata app.
#[derive(Debug, Clone)]
pub struct CargoHmrOrchestrator {
    project_dir: PathBuf,
    socket_path: PathBuf,
    epoch: u64,
}

impl CargoHmrOrchestrator {
    /// Creates an orchestrator targeting `project_dir` and a specific HMR IPC `socket_path`.
    pub fn new(project_dir: impl Into<PathBuf>, socket_path: impl Into<PathBuf>) -> Self {
        Self {
            project_dir: project_dir.into(),
            socket_path: socket_path.into(),
            epoch: 0,
        }
    }

    /// Creates an orchestrator using the deterministic per-project HMR socket path.
    pub fn for_project(project_dir: impl Into<PathBuf>) -> Self {
        let dir = project_dir.into();
        let sock = default_hmr_socket_path(&dir);
        Self::new(dir, sock)
    }

    /// Returns the root project directory being compiled.
    pub fn project_dir(&self) -> &Path {
        &self.project_dir
    }

    /// Returns the HMR IPC socket path shared with the running Strata application.
    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    /// Returns the current HMR epoch counter.
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Extracts the compiled dynamic library path (`.so`, `.dylib`, or `.dll`) from
    /// `cargo build --lib --message-format=json` stdout output.
    pub fn parse_cdylib_from_cargo_json(stdout: &str) -> Option<PathBuf> {
        let mut found = None;
        for line in stdout.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || !trimmed.starts_with('{') {
                continue;
            }
            let Ok(val) = serde_json::from_str::<serde_json::Value>(trimmed) else {
                continue;
            };
            if val.get("reason").and_then(|r| r.as_str()) != Some("compiler-artifact") {
                continue;
            }
            let is_cdylib = val
                .get("target")
                .and_then(|t| t.get("crate_types"))
                .and_then(|ct| ct.as_array())
                .map(|arr| {
                    arr.iter()
                        .any(|v| matches!(v.as_str(), Some("cdylib") | Some("dylib")))
                })
                .unwrap_or(true);
            if !is_cdylib {
                continue;
            }
            if let Some(filenames) = val.get("filenames").and_then(|f| f.as_array()) {
                for name in filenames {
                    if let Some(path_str) = name.as_str() {
                        let p = PathBuf::from(path_str);
                        if matches!(
                            p.extension().and_then(|e| e.to_str()),
                            Some("so") | Some("dylib") | Some("dll")
                        ) {
                            found = Some(p);
                        }
                    }
                }
            }
        }
        found
    }

    /// Runs `cargo build --lib --message-format=json` in `project_dir` and returns
    /// `(compiled_dylib_path, compile_ms)`.
    pub fn compile_cdylib(&self) -> Result<(PathBuf, u64), String> {
        if !self.project_dir.join("Cargo.toml").exists() {
            return Err(format!(
                "No Cargo.toml found in '{}'",
                self.project_dir.display()
            ));
        }

        let start = Instant::now();
        let output = Command::new("cargo")
            .args(["build", "--lib", "--message-format=json"])
            .current_dir(&self.project_dir)
            .output()
            .map_err(|e| format!("Failed to invoke `cargo build --lib`: {e}"))?;
        let compile_ms = start.elapsed().as_millis() as u64;

        let stdout = String::from_utf8_lossy(&output.stdout);
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let mut diag = String::new();
            for line in stdout.lines() {
                if let Ok(val) = serde_json::from_str::<serde_json::Value>(line) {
                    if val.get("reason").and_then(|r| r.as_str()) == Some("compiler-message") {
                        if let Some(rendered) = val
                            .get("message")
                            .and_then(|m| m.get("rendered"))
                            .and_then(|r| r.as_str())
                        {
                            diag.push_str(rendered);
                        }
                    }
                }
            }
            if diag.trim().is_empty() {
                diag = stderr.into_owned();
            }
            return Err(format!(
                "Incremental HMR compilation failed ({compile_ms}ms):\n{}",
                diag.trim()
            ));
        }

        let dylib_path = Self::parse_cdylib_from_cargo_json(&stdout).ok_or_else(|| {
            "Cargo build succeeded, but no cdylib artifact (.so/.dylib/.dll) was emitted. \
             Ensure Cargo.toml contains `[lib] crate-type = [\"rlib\", \"cdylib\"]`."
                .to_string()
        })?;

        Ok((dylib_path, compile_ms))
    }

    /// Compiles a fresh `cdylib` and pushes it over IPC to the live Strata application.
    pub fn trigger_hot_patch(&mut self) -> Result<HmrPatchReport, String> {
        let (dylib_path, compile_ms) = self.compile_cdylib()?;
        let next_epoch = self.epoch + 1;
        let client = HmrIpcClient::new(&self.socket_path);
        match client.apply_patch(&dylib_path, next_epoch, compile_ms)? {
            HmrResponse::PatchAck {
                ok: true,
                epoch,
                swap_us,
                signals_restored,
                ..
            } => {
                self.epoch = epoch;
                Ok(HmrPatchReport {
                    dylib_path,
                    epoch,
                    compile_ms,
                    swap_us,
                    signals_restored,
                })
            }
            HmrResponse::PatchAck {
                ok: false, error, ..
            } => Err(error.unwrap_or_else(|| "Application rejected HMR patch".to_string())),
            other => Err(format!("Unexpected HMR response from app: {other:?}")),
        }
    }

    /// Spawns the Strata application binary with `STRATA_HMR_SOCKET` exported in its environment.
    pub fn spawn_app_process(&self) -> Result<Child, String> {
        if !self.project_dir.join("Cargo.toml").exists() {
            return Err(format!(
                "No Cargo.toml found in '{}'",
                self.project_dir.display()
            ));
        }
        Command::new("cargo")
            .arg("run")
            .current_dir(&self.project_dir)
            .env(STRATA_HMR_SOCKET_ENV, &self.socket_path)
            .stdin(Stdio::null())
            .spawn()
            .map_err(|e| format!("Failed to spawn Strata app via `cargo run`: {e}"))
    }

    /// Requests a graceful shutdown of the running application over the HMR IPC socket.
    pub fn send_shutdown(&self) {
        let client = HmrIpcClient::new(&self.socket_path);
        let _ = client.send(&HmrRequest::Shutdown);
    }
}

/// Configuration options for the local development server.
#[derive(Debug, Clone)]
pub struct DevServerConfig {
    pub target: BuildTarget,
    pub port: u16,
    pub watch: bool,
    pub headless: bool,
}

impl Default for DevServerConfig {
    fn default() -> Self {
        Self {
            target: BuildTarget::Desktop,
            port: 3000,
            watch: true,
            headless: false,
        }
    }
}

/// Local development server instance.
pub struct DevServer {
    pub config: DevServerConfig,
    pub session: HmrSession,
    project_dir: PathBuf,
    socket_path: PathBuf,
    is_running: Arc<AtomicBool>,
    reload_counter: Arc<AtomicUsize>,
}

impl DevServer {
    pub fn new(config: DevServerConfig) -> Self {
        let project_dir = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
        let socket_path = default_hmr_socket_path(&project_dir);
        Self {
            config,
            session: HmrSession::new(),
            project_dir,
            socket_path,
            is_running: Arc::new(AtomicBool::new(false)),
            reload_counter: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// Overrides the project root watched and compiled by this dev server.
    pub fn with_project_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.project_dir = dir.into();
        self.socket_path = default_hmr_socket_path(&self.project_dir);
        self
    }

    /// Overrides the HMR IPC socket path used to communicate with the running app.
    pub fn with_hmr_socket(mut self, socket_path: impl Into<PathBuf>) -> Self {
        self.socket_path = socket_path.into();
        self
    }

    /// Returns the HMR IPC socket path configured for this dev server.
    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    /// Returns a shared atomic flag handle allowing external threads to inspect or stop the server.
    pub fn running_handle(&self) -> Arc<AtomicBool> {
        self.is_running.clone()
    }

    /// Handles a detected file change by invoking real incremental compilation and live HMR IPC
    /// when a Cargo project is present, reporting actual measured latencies.
    pub fn on_file_changed(&mut self, file_path: &str) -> usize {
        println!(
            "  \x1b[36m›\x1b[0m \x1b[90m[HMR]\x1b[0m Change detected: \x1b[37m{}\x1b[0m",
            file_path
        );
        if self.project_dir.join("Cargo.toml").exists() {
            let mut orch = CargoHmrOrchestrator::new(&self.project_dir, &self.socket_path);
            orch.epoch = self.session.reload_count as u64;
            match orch.trigger_hot_patch() {
                Ok(report) => {
                    self.session.record_patch_report(&report);
                    self.reload_counter
                        .store(self.session.reload_count, Ordering::SeqCst);
                    println!(
                        "  \x1b[32m√\x1b[0m Hot-patch epoch #{} applied \x1b[90m(compile: {}ms, swap: {}us, signals restored: {})\x1b[0m",
                        report.epoch, report.compile_ms, report.swap_us, report.signals_restored
                    );
                    return self.session.reload_count;
                }
                Err(err) => {
                    eprintln!("  \x1b[33m!\x1b[0m \x1b[90m[HMR]\x1b[0m {}", err);
                }
            }
        }
        let reload_num = self.session.trigger_reload();
        self.reload_counter.store(reload_num, Ordering::SeqCst);
        reload_num
    }

    /// Starts the persistent development server, filesystem watcher, and interactive runner.
    pub fn run(&mut self) -> Result<(), String> {
        let start_time = Instant::now();
        self.is_running.store(true, Ordering::SeqCst);
        let port = self.config.port;
        let is_running_clone = self.is_running.clone();
        let reload_counter_http = self.reload_counter.clone();
        let socket_display = self.socket_path.display().to_string();

        // Spawn background HTTP status listener thread
        let listener_handle = thread::spawn(move || {
            let addr = format!("127.0.0.1:{}", port);
            if let Ok(listener) = TcpListener::bind(&addr) {
                let _ = listener.set_nonblocking(true);
                while is_running_clone.load(Ordering::SeqCst) {
                    match listener.accept() {
                        Ok((mut stream, _)) => {
                            let reloads = reload_counter_http.load(Ordering::SeqCst);
                            Self::handle_http_connection(
                                &mut stream,
                                port,
                                reloads,
                                &socket_display,
                            );
                        }
                        Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(50));
                        }
                        Err(_) => break,
                    }
                }
            }
        });

        // Launch the target Strata application automatically when running interactively in a Cargo project
        let mut child_app: Option<Child> = None;
        if !self.config.headless && self.project_dir.join("Cargo.toml").exists() {
            let orch = CargoHmrOrchestrator::new(&self.project_dir, &self.socket_path);
            match orch.spawn_app_process() {
                Ok(child) => {
                    child_app = Some(child);
                }
                Err(err) => {
                    eprintln!("  \x1b[33m!\x1b[0m \x1b[90m[HMR]\x1b[0m {}", err);
                }
            }
        }

        // Spawn debounced recursive filesystem watcher thread backed by strata-hot-reload
        let is_running_watch = self.is_running.clone();
        let watch_enabled = self.config.watch;
        let watch_project_dir = self.project_dir.clone();
        let watch_socket_path = self.socket_path.clone();
        let reload_counter_watch = self.reload_counter.clone();
        let watch_handle = thread::spawn(move || {
            if !watch_enabled {
                return;
            }
            let watch_root = if watch_project_dir.join("src").exists() {
                watch_project_dir.join("src")
            } else {
                watch_project_dir.clone()
            };
            let mut watcher =
                DirectoryWatcher::new(&watch_root).with_debounce(Duration::from_millis(120));
            let mut orch = CargoHmrOrchestrator::new(&watch_project_dir, &watch_socket_path);

            while is_running_watch.load(Ordering::SeqCst) {
                thread::sleep(Duration::from_millis(120));
                let changed = watcher.poll_changes();
                if changed.is_empty() {
                    continue;
                }
                let display_list: Vec<String> = changed
                    .iter()
                    .take(3)
                    .map(|p| {
                        p.strip_prefix(&watch_project_dir)
                            .unwrap_or(p)
                            .display()
                            .to_string()
                    })
                    .collect();
                println!(
                    "  \x1b[36m›\x1b[0m \x1b[90m[HMR]\x1b[0m Change detected: \x1b[37m{}\x1b[0m",
                    display_list.join(", ")
                );

                if !watch_project_dir.join("Cargo.toml").exists() {
                    continue;
                }

                match orch.compile_cdylib() {
                    Ok((dylib_path, compile_ms)) => {
                        let next_epoch = orch.epoch() + 1;
                        let client = HmrIpcClient::new(orch.socket_path());
                        match client.apply_patch(&dylib_path, next_epoch, compile_ms) {
                            Ok(HmrResponse::PatchAck {
                                ok: true,
                                epoch,
                                swap_us,
                                signals_restored,
                                ..
                            }) => {
                                orch.epoch = epoch;
                                reload_counter_watch.store(epoch as usize, Ordering::SeqCst);
                                println!(
                                    "  \x1b[32m√\x1b[0m Hot-patch epoch #{} applied \x1b[90m(compile: {}ms, swap: {}us, signals restored: {})\x1b[0m",
                                    epoch, compile_ms, swap_us, signals_restored
                                );
                            }
                            Ok(HmrResponse::PatchAck {
                                ok: false, error, ..
                            }) => {
                                eprintln!(
                                    "  \x1b[31mx\x1b[0m \x1b[90m[HMR]\x1b[0m Patch rejected after {}ms compile: {}",
                                    compile_ms,
                                    error.unwrap_or_else(|| "unknown error".to_string())
                                );
                            }
                            Ok(other) => {
                                eprintln!(
                                    "  \x1b[33m!\x1b[0m \x1b[90m[HMR]\x1b[0m Unexpected app response: {:?}",
                                    other
                                );
                            }
                            Err(ipc_err) => {
                                eprintln!(
                                    "  \x1b[33m!\x1b[0m \x1b[90m[HMR]\x1b[0m Compiled in {}ms, awaiting live app HMR socket: {}",
                                    compile_ms, ipc_err
                                );
                            }
                        }
                    }
                    Err(compile_err) => {
                        eprintln!("  \x1b[31mx\x1b[0m \x1b[90m[HMR]\x1b[0m {}", compile_err);
                    }
                }
            }
        });

        let ready_ms = start_time.elapsed().as_millis();
        println!(
            "\x1b[1;36m▲ Strata\x1b[0m \x1b[90mv{}\x1b[0m \x1b[90m(Native State-Preserving HMR Dev Server)\x1b[0m",
            env!("CARGO_PKG_VERSION")
        );
        println!(
            "  \x1b[90m- Program target:\x1b[0m \x1b[37m{}\x1b[0m",
            self.config.target.as_str()
        );
        println!(
            "  \x1b[90m- Health status:\x1b[0m  \x1b[36mhttp://127.0.0.1:{}\x1b[0m",
            self.config.port
        );
        println!(
            "  \x1b[90m- HMR IPC socket:\x1b[0m \x1b[36m{}\x1b[0m",
            self.socket_path.display()
        );
        println!(
            "  \x1b[90m- File watch:\x1b[0m     \x1b[32m{}\x1b[0m \x1b[90m(strata-hot-reload cdylib orchestrator)\x1b[0m\n",
            if self.config.watch { "active" } else { "disabled" }
        );
        println!(
            "  \x1b[32m√ Dev server ready in {}ms\x1b[0m\n",
            ready_ms
        );
        println!("  \x1b[90m› Interactive controls:\x1b[0m");
        println!(
            "    \x1b[36m[r]\x1b[0m reload   \x1b[36m[c]\x1b[0m clear   \x1b[36m[h]\x1b[0m help   \x1b[36m[q]\x1b[0m quit\n"
        );

        if self.config.headless {
            while self.is_running.load(Ordering::SeqCst) {
                thread::sleep(Duration::from_millis(20));
            }
            let _ = listener_handle.join();
            let _ = watch_handle.join();
            return Ok(());
        }

        // Interactive terminal loop listening on stdin
        let stdin = std::io::stdin();
        let mut reader = stdin.lock();
        let mut line = String::new();

        while self.is_running.load(Ordering::SeqCst) {
            line.clear();
            match reader.read_line(&mut line) {
                Ok(0) => break, // EOF
                Ok(_) => {
                    let cmd = line.trim();
                    match cmd {
                        "r" | "reload" => {
                            self.on_file_changed("manual-trigger");
                        }
                        "c" | "clear" => {
                            print!("\x1b[2J\x1b[H");
                            let _ = std::io::stdout().flush();
                            println!(
                                "\x1b[1;36m▲ Strata\x1b[0m \x1b[90mv{}\x1b[0m \x1b[90m(Native State-Preserving HMR Dev Server)\x1b[0m",
                                env!("CARGO_PKG_VERSION")
                            );
                            println!(
                                "  \x1b[90m- Health status:\x1b[0m \x1b[36mhttp://127.0.0.1:{}\x1b[0m\n",
                                self.config.port
                            );
                        }
                        "h" | "help" => {
                            println!("  \x1b[90m› Available commands:\x1b[0m");
                            println!("    \x1b[36m[r]\x1b[0m reload: recompile cdylib and push state-preserving HMR patch");
                            println!("    \x1b[36m[c]\x1b[0m clear:  clear terminal screen");
                            println!("    \x1b[36m[h]\x1b[0m help:   show this help menu");
                            println!("    \x1b[36m[q]\x1b[0m quit:   stop dev server and running app");
                        }
                        "q" | "quit" | "exit" => {
                            println!("\n  \x1b[90m› Shutting down dev server...\x1b[0m");
                            self.stop();
                            break;
                        }
                        _ => {}
                    }
                }
                Err(_) => break,
            }
        }

        self.stop();
        if let Some(mut child) = child_app {
            let orch = CargoHmrOrchestrator::new(&self.project_dir, &self.socket_path);
            orch.send_shutdown();
            thread::sleep(Duration::from_millis(50));
            let _ = child.kill();
            let _ = child.wait();
        }
        let _ = listener_handle.join();
        let _ = watch_handle.join();
        println!("  \x1b[32m√\x1b[0m Dev server stopped cleanly.");
        Ok(())
    }

    /// Stops the server.
    pub fn stop(&self) {
        self.is_running.store(false, Ordering::SeqCst);
    }

    fn handle_http_connection(
        stream: &mut TcpStream,
        port: u16,
        reloads: usize,
        socket_path: &str,
    ) {
        let mut buffer = [0u8; 1024];
        let _ = stream.read(&mut buffer);

        let body = format!(
            "<!DOCTYPE html><html><head><title>Strata Dev Server</title></head>\
             <body style=\"font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0a0a0a; color: #f0f0f0; padding: 40px;\">\
             <h1>▲ Strata Universal Frontend Engine</h1>\
             <p>Status: <strong style=\"color: #10b981;\">Ready (Direct Hardware Swapchain &amp; Native HMR Active)</strong></p>\
             <p>Local Port: <code>{}</code></p>\
             <p>HMR IPC Endpoint: <code>{}</code></p>\
             <p>Applied Hot-Reload Epochs: <strong>{}</strong></p>\
             </body></html>",
            port, socket_path, reloads
        );

        let response = format!(
            "HTTP/1.1 200 OK\r\n\
             Content-Type: text/html; charset=utf-8\r\n\
             Content-Length: {}\r\n\
             Connection: close\r\n\r\n\
             {}",
            body.len(),
            body
        );

        let _ = stream.write_all(response.as_bytes());
        let _ = stream.flush();
    }
}
