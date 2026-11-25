use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::atomic::Ordering;
use std::thread;
use std::time::Duration;
use strata_cli::prelude::*;

#[test]
fn test_dev_server_session_hmr() {
    let mut session = HmrSession::new();
    assert_eq!(session.reload_count, 0);
    assert!(session.restore_state().is_none());

    let state_snapshot = vec![1, 2, 3, 4, 5, 99];
    session.snapshot_state(state_snapshot.clone());
    assert_eq!(session.restore_state(), Some(state_snapshot.as_slice()));

    let count = session.trigger_reload();
    assert_eq!(count, 1);
    assert_eq!(session.reload_count, 1);
    assert_eq!(session.restore_state(), Some(state_snapshot.as_slice()));
}

#[test]
fn test_dev_server_headless_mode() {
    let config = DevServerConfig {
        target: BuildTarget::Desktop,
        port: 39876,
        watch: true,
        headless: true,
    };

    let mut server = DevServer::new(config);
    let stopper = server.running_handle();
    let server_handle = thread::spawn(move || {
        server.run()
    });

    thread::sleep(Duration::from_millis(50));
    stopper.store(false, Ordering::SeqCst);
    let res = server_handle.join().unwrap();
    assert!(res.is_ok(), "Headless dev server must shut down cleanly");
}

#[test]
fn test_dev_server_http_status_listener() {
    let test_port = 39877;
    let config = DevServerConfig {
        target: BuildTarget::Desktop,
        port: test_port,
        watch: true,
        headless: true,
    };

    let mut server = DevServer::new(config);
    let stopper = server.running_handle();
    let server_handle = thread::spawn(move || {
        server.run()
    });

    // Allow TCP listener thread to bind
    thread::sleep(Duration::from_millis(100));

    // Send HTTP GET request
    let mut stream = TcpStream::connect(format!("127.0.0.1:{}", test_port)).expect("Failed to connect to dev server");
    let request = "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
    stream.write_all(request.as_bytes()).unwrap();
    stream.flush().unwrap();

    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();

    assert!(response.contains("HTTP/1.1 200 OK"));
    assert!(response.contains("Strata Universal Frontend Engine"));
    assert!(response.contains(&format!("{}", test_port)));
    assert!(!response.contains('\u{26A1}'));

    // Cleanly signal server stop and join thread
    stopper.store(false, Ordering::SeqCst);
    let _ = server_handle.join();
}

#[test]
fn test_cargo_hmr_orchestrator_parses_cdylib_artifacts() {
    let sample_linux = r#"
{"reason":"compiler-artifact","target":{"crate_types":["rlib"]},"filenames":["/tmp/target/debug/libdemo.rlib"]}
{"reason":"compiler-artifact","target":{"crate_types":["rlib","cdylib"]},"filenames":["/tmp/target/debug/libdemo.rlib","/tmp/target/debug/libdemo.so"]}
{"reason":"build-finished","success":true}
"#;
    assert_eq!(
        CargoHmrOrchestrator::parse_cdylib_from_cargo_json(sample_linux),
        Some(std::path::PathBuf::from("/tmp/target/debug/libdemo.so"))
    );

    let sample_macos = r#"{"reason":"compiler-artifact","target":{"crate_types":["cdylib"]},"filenames":["/tmp/libdemo.dylib"]}"#;
    assert_eq!(
        CargoHmrOrchestrator::parse_cdylib_from_cargo_json(sample_macos),
        Some(std::path::PathBuf::from("/tmp/libdemo.dylib"))
    );

    let sample_win = r#"{"reason":"compiler-artifact","target":{"crate_types":["cdylib"]},"filenames":["C:\\app\\target\\debug\\demo.dll"]}"#;
    assert_eq!(
        CargoHmrOrchestrator::parse_cdylib_from_cargo_json(sample_win),
        Some(std::path::PathBuf::from("C:\\app\\target\\debug\\demo.dll"))
    );
}

#[test]
fn test_scaffold_generates_hmr_lib_rs_and_cdylib_manifest() {
    let tmp = std::env::temp_dir().join(format!(
        "strata_cli_hmr_scaffold_{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).unwrap();

    let report = ProjectScaffolder::scaffold("hmr_demo", TemplateKind::Blank, &tmp).unwrap();
    let lib_rs = std::fs::read_to_string(report.root_path.join("src/lib.rs")).unwrap();
    let cargo_toml = std::fs::read_to_string(report.root_path.join("Cargo.toml")).unwrap();
    assert!(lib_rs.contains("export_hot_view!(app::App)"));
    assert!(cargo_toml.contains("crate-type = [\"rlib\", \"cdylib\"]"));
    assert!(cargo_toml.contains("features = [\"hot-reload\"]"));

    let _ = std::fs::remove_dir_all(&tmp);
}

