#[cfg(not(windows))]
#[test]
fn non_windows_entry_exits_without_starting_service_or_networking() {
    let binary = std::env::var("CARGO_BIN_EXE_varmlen-service").unwrap();
    let output = std::process::Command::new(binary).output().unwrap();

    assert!(!output.status.success());
    assert_eq!(
        String::from_utf8(output.stderr).unwrap(),
        "VarmlenService is only supported on Windows\n"
    );
}
