use std::{
    fs::{self, File},
    io::{self, Read, Seek, SeekFrom},
    path::{Path, PathBuf},
};

pub const MAX_LOG_BYTES: usize = 10 * 1024 * 1024;
const MAX_ROTATED_LOGS: usize = 3;

pub fn rotate_if_needed(path: &Path) -> io::Result<()> {
    let size = match fs::metadata(path) {
        Ok(metadata) => metadata.len(),
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    if size <= MAX_LOG_BYTES as u64 {
        return Ok(());
    }

    remove_if_exists(&rotated(path, MAX_ROTATED_LOGS))?;
    for index in (1..MAX_ROTATED_LOGS).rev() {
        rename_if_exists(&rotated(path, index), &rotated(path, index + 1))?;
    }
    fs::rename(path, rotated(path, 1))
}

pub fn tail_log(path: &Path, max_bytes: usize) -> io::Result<String> {
    if max_bytes == 0 {
        return Ok(String::new());
    }
    let mut file = match File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(String::new()),
        Err(error) => return Err(error),
    };
    let length = file.metadata()?.len();
    let read_bytes = length.min(max_bytes as u64);
    file.seek(SeekFrom::Start(length - read_bytes))?;
    let mut bytes = Vec::with_capacity(read_bytes as usize);
    file.take(read_bytes).read_to_end(&mut bytes)?;
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

pub fn clear_logs(path: &Path) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, [])?;
    for index in 1..=MAX_ROTATED_LOGS {
        remove_if_exists(&rotated(path, index))?;
    }
    Ok(())
}

fn rotated(path: &Path, index: usize) -> PathBuf {
    PathBuf::from(format!("{}.{}", path.to_string_lossy(), index))
}

fn remove_if_exists(path: &Path) -> io::Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

fn rename_if_exists(from: &Path, to: &Path) -> io::Result<()> {
    match fs::rename(from, to) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}
