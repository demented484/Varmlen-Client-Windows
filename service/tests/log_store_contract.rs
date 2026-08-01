use std::{fs, path::PathBuf};

use varmlen_service::log_store::{clear_logs, rotate_if_needed, tail_log, MAX_LOG_BYTES};

fn scratch(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "varmlen-{name}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ))
}

#[test]
fn log_rotation_and_tail_keep_memory_and_disk_bounded() {
    let directory = scratch("logs");
    fs::create_dir_all(&directory).unwrap();
    let log = directory.join("xray.log");
    fs::write(&log, vec![b'a'; MAX_LOG_BYTES + 1]).unwrap();

    rotate_if_needed(&log).unwrap();
    assert!(!log.exists());
    assert_eq!(
        fs::metadata(directory.join("xray.log.1")).unwrap().len(),
        (MAX_LOG_BYTES + 1) as u64
    );

    fs::write(&log, b"old line\nnew line\n").unwrap();
    assert_eq!(tail_log(&log, 9).unwrap(), "new line\n");

    clear_logs(&log).unwrap();
    assert_eq!(fs::read(&log).unwrap(), b"");
    assert!(!directory.join("xray.log.1").exists());
    let _ = fs::remove_dir_all(directory);
}
