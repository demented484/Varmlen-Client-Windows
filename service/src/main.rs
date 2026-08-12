#[cfg(windows)]
fn main() {
    let command = std::env::args_os().nth(1);
    if command.as_deref() == Some(std::ffi::OsStr::new("--cleanup")) {
        let result = (|| -> std::io::Result<()> {
            let layout = varmlen_service::windows_state::runtime_layout()?;
            varmlen_service::windows_routes::remove_killswitch_routes(&layout)?;
            varmlen_service::windows_state::clear_desired_state(&layout)
        })();
        if let Err(error) = result {
            eprintln!("Varmlen cleanup failed: {error}");
            std::process::exit(1);
        }
        return;
    }
    if command.as_deref() == Some(std::ffi::OsStr::new("--health")) {
        let result = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .and_then(|runtime| runtime.block_on(varmlen_service::pipe::service_health_check()));
        match result {
            Ok(state) => {
                println!(
                    "VarmlenService v{} ready ({:?})",
                    varmlen_protocol::PROTOCOL_VERSION,
                    state.phase
                );
            }
            Err(error) => {
                eprintln!("Varmlen service health check failed: {error}");
                std::process::exit(1);
            }
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
