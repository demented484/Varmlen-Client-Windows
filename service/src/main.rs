#[cfg(windows)]
fn main() {
    if std::env::args_os().nth(1).as_deref() == Some(std::ffi::OsStr::new("--cleanup")) {
        let result = (|| -> std::io::Result<()> {
            varmlen_service::windows_wfp::cleanup_persistent_policy()?;
            let layout = varmlen_service::windows_state::runtime_layout()?;
            varmlen_service::windows_state::clear_desired_state(&layout)
        })();
        if let Err(error) = result {
            eprintln!("Varmlen cleanup failed: {error}");
            std::process::exit(1);
        }
        return;
    }
    if let Err(error) = varmlen_service::windows_service::run_dispatcher() {
        eprintln!("VarmlenService failed: {error}");
        std::process::exit(1);
    }
}

#[cfg(not(windows))]
fn main() {
    eprintln!("VarmlenService is only supported on Windows");
    std::process::exit(1);
}
