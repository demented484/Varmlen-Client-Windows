#[cfg(windows)]
fn main() {
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
