use std::{cmp::Ordering, path::PathBuf, time::Duration};

use serde::Deserialize;
use varmlen_protocol::{CoreInfo, CoreInstalledVersion, CoreRelease};
use varmlen_service_core::runtime::RuntimeLayout;

pub const BUNDLED_XRAY_VERSION: &str = "26.3.27";
const API_ROOT: &str = "https://api.github.com/repos/XTLS/Xray-core/releases";
const OFFICIAL_DOWNLOAD_ROOT: &str = "https://github.com/XTLS/Xray-core/releases/download/";
const MAX_RELEASE_BODY: usize = 4 * 1024 * 1024;
const MAX_CORE_BYTES: u64 = 256 * 1024 * 1024;

#[derive(Debug, Clone, Deserialize)]
struct GithubRelease {
    tag_name: String,
    name: Option<String>,
    published_at: Option<String>,
    #[serde(default)]
    prerelease: bool,
    #[serde(default)]
    assets: Vec<GithubAsset>,
}

#[derive(Debug, Clone, Deserialize)]
struct GithubAsset {
    name: String,
    browser_download_url: String,
    size: u64,
    digest: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoreDownloadAsset {
    pub name: String,
    pub url: String,
    pub size: u64,
    pub sha256: String,
}

pub fn xray_asset_name(arch: &str) -> Result<&'static str, String> {
    match arch {
        "x86_64" => Ok("Xray-windows-64.zip"),
        "aarch64" => Ok("Xray-windows-arm64-v8a.zip"),
        other => Err(format!("unsupported Windows architecture: {other}")),
    }
}

pub fn version_cmp(left: &str, right: &str) -> Ordering {
    version_parts(left).cmp(&version_parts(right))
}

fn version_parts(value: &str) -> Vec<u32> {
    normalize_tag(value)
        .split(|character: char| !character.is_ascii_digit())
        .filter(|part| !part.is_empty())
        .filter_map(|part| part.parse().ok())
        .collect()
}

pub fn parse_releases(body: &str) -> Result<Vec<CoreRelease>, String> {
    let releases = decode_releases(body)?;
    Ok(releases
        .into_iter()
        .filter_map(|release| {
            let tag = normalize_tag(&release.tag_name);
            valid_tag(&tag).then(|| CoreRelease {
                name: release.name.unwrap_or_else(|| release.tag_name.clone()),
                tag,
                date: release.published_at,
                prerelease: release.prerelease,
            })
        })
        .collect())
}

pub fn select_release_asset(
    body: &str,
    requested_tag: &str,
    arch: &str,
) -> Result<CoreDownloadAsset, String> {
    let requested_tag = normalize_tag(requested_tag);
    let release = decode_releases(body)?
        .into_iter()
        .find(|release| normalize_tag(&release.tag_name) == requested_tag)
        .ok_or_else(|| format!("Xray release {requested_tag} was not found"))?;
    let expected_name = xray_asset_name(arch)?;
    let asset = release
        .assets
        .into_iter()
        .find(|asset| asset.name == expected_name)
        .ok_or_else(|| format!("release has no {expected_name} asset"))?;
    if asset.size == 0 || asset.size > MAX_CORE_BYTES {
        return Err(format!("invalid core asset size: {} bytes", asset.size));
    }
    if !asset
        .browser_download_url
        .starts_with(OFFICIAL_DOWNLOAD_ROOT)
    {
        return Err("refusing a non-official Xray download URL".into());
    }
    let sha256 = asset
        .digest
        .as_deref()
        .and_then(|digest| digest.strip_prefix("sha256:"))
        .filter(|digest| digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .ok_or_else(|| "official release asset has no valid SHA-256 digest".to_string())?
        .to_ascii_lowercase();
    Ok(CoreDownloadAsset {
        name: asset.name,
        url: asset.browser_download_url,
        size: asset.size,
        sha256,
    })
}

fn decode_releases(body: &str) -> Result<Vec<GithubRelease>, String> {
    if body.len() > MAX_RELEASE_BODY {
        return Err("GitHub release response exceeds the size limit".into());
    }
    let value: serde_json::Value =
        serde_json::from_str(body).map_err(|error| format!("invalid release JSON: {error}"))?;
    if value.is_array() {
        serde_json::from_value(value).map_err(|error| format!("invalid releases: {error}"))
    } else {
        serde_json::from_value(value)
            .map(|release| vec![release])
            .map_err(|error| format!("invalid release: {error}"))
    }
}

fn normalize_tag(tag: &str) -> String {
    tag.trim().trim_start_matches('v').to_string()
}

fn valid_tag(tag: &str) -> bool {
    !tag.is_empty()
        && tag.len() <= 64
        && tag
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
}

pub struct CoreManager {
    layout: RuntimeLayout,
}

impl CoreManager {
    pub fn new(layout: RuntimeLayout) -> Self {
        Self { layout }
    }

    pub fn active_tag(&self) -> String {
        std::fs::read_to_string(self.active_file())
            .ok()
            .map(|value| normalize_tag(&value))
            .filter(|tag| valid_tag(tag) && self.binary_for(tag).is_file())
            .unwrap_or_else(|| BUNDLED_XRAY_VERSION.into())
    }

    pub fn binary_for(&self, tag: &str) -> PathBuf {
        let tag = normalize_tag(tag);
        if tag == BUNDLED_XRAY_VERSION {
            self.layout.xray_executable.clone()
        } else {
            self.versions_dir().join(tag).join("xray.exe")
        }
    }

    pub fn resolve_binary(&self, tag: &str) -> Result<PathBuf, String> {
        let tag = normalize_tag(tag);
        if !valid_tag(&tag) {
            return Err(format!("invalid Xray version: {tag}"));
        }
        let binary = self.binary_for(&tag);
        if !binary.is_file() {
            return Err(format!("Xray {tag} is not installed"));
        }
        Ok(binary)
    }

    pub fn local_info(&self, latest: Option<String>) -> CoreInfo {
        let active = self.active_tag();
        let mut tags = vec![BUNDLED_XRAY_VERSION.to_string()];
        if let Ok(entries) = std::fs::read_dir(self.versions_dir()) {
            for entry in entries.flatten() {
                let tag = entry.file_name().to_string_lossy().to_string();
                if valid_tag(&tag)
                    && entry.path().join("xray.exe").is_file()
                    && !tags.contains(&tag)
                {
                    tags.push(tag);
                }
            }
        }
        tags.sort_by(|left, right| version_cmp(right, left));
        let installed = tags
            .into_iter()
            .map(|tag| CoreInstalledVersion {
                active: tag == active,
                bundled: tag == BUNDLED_XRAY_VERSION,
                tag,
            })
            .collect();
        let has_update = latest
            .as_deref()
            .is_some_and(|latest| version_cmp(latest, &active).is_gt());
        CoreInfo {
            installed,
            active: Some(active),
            latest,
            has_update,
        }
    }

    pub async fn list_releases(&self) -> Result<Vec<CoreRelease>, String> {
        let body = fetch_text(&format!("{API_ROOT}?per_page=30")).await?;
        parse_releases(&body)
    }

    #[cfg(windows)]
    pub async fn install(&self, requested: Option<String>) -> Result<String, String> {
        use futures_util::StreamExt;
        use sha2::{Digest, Sha256};
        use tokio::io::AsyncWriteExt;

        let (body, tag) = match requested {
            Some(tag) => {
                let tag = normalize_tag(&tag);
                if !valid_tag(&tag) {
                    return Err(format!("invalid Xray version: {tag}"));
                }
                let body = fetch_text(&format!("{API_ROOT}/tags/v{tag}")).await?;
                (body, tag)
            }
            None => {
                let body = fetch_text(&format!("{API_ROOT}?per_page=30")).await?;
                let tag = parse_releases(&body)?
                    .into_iter()
                    .next()
                    .map(|release| release.tag)
                    .ok_or_else(|| "GitHub returned no Xray releases".to_string())?;
                (body, tag)
            }
        };
        if self.resolve_binary(&tag).is_ok() {
            return Ok(tag);
        }
        let asset = select_release_asset(&body, &tag, std::env::consts::ARCH)?;
        std::fs::create_dir_all(&self.layout.state_dir)
            .map_err(|error| format!("create core state directory: {error}"))?;
        let archive_path = self.layout.state_dir.join(format!(".xray-{tag}.download"));
        let executable_path = self.layout.state_dir.join(format!(".xray-{tag}.exe"));
        let _cleanup = TemporaryFiles(vec![archive_path.clone(), executable_path.clone()]);

        let response = http_client()?
            .get(&asset.url)
            .send()
            .await
            .map_err(|error| format!("download Xray: {error}"))?;
        if !response.status().is_success() {
            return Err(format!("Xray download returned HTTP {}", response.status()));
        }
        let mut output = tokio::fs::File::create(&archive_path)
            .await
            .map_err(|error| format!("create Xray archive: {error}"))?;
        let mut hasher = Sha256::new();
        let mut downloaded = 0_u64;
        let mut stream = response.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|error| format!("download Xray chunk: {error}"))?;
            downloaded = downloaded.saturating_add(chunk.len() as u64);
            if downloaded > MAX_CORE_BYTES || downloaded > asset.size.saturating_add(1024) {
                return Err("Xray download exceeded its declared size".into());
            }
            hasher.update(&chunk);
            output
                .write_all(&chunk)
                .await
                .map_err(|error| format!("write Xray archive: {error}"))?;
        }
        output
            .sync_all()
            .await
            .map_err(|error| format!("flush Xray archive: {error}"))?;
        drop(output);
        let actual = format!("{:x}", hasher.finalize());
        if actual != asset.sha256 {
            return Err(format!(
                "Xray SHA-256 mismatch (expected {}, got {actual})",
                asset.sha256
            ));
        }
        let archive = archive_path.clone();
        let executable = executable_path.clone();
        tokio::task::spawn_blocking(move || extract_xray(&archive, &executable))
            .await
            .map_err(|error| format!("Xray extraction task failed: {error}"))??;
        verify_xray_version(&executable_path, &tag).await?;

        let destination = self.binary_for(&tag);
        let directory = destination
            .parent()
            .ok_or_else(|| "Xray destination has no directory".to_string())?;
        std::fs::create_dir_all(directory)
            .map_err(|error| format!("create Xray version directory: {error}"))?;
        std::fs::rename(&executable_path, &destination)
            .map_err(|error| format!("install Xray {tag}: {error}"))?;
        Ok(tag)
    }

    #[cfg(windows)]
    pub async fn activate(&self, tag: &str) -> Result<(), String> {
        let tag = normalize_tag(tag);
        let binary = self.resolve_binary(&tag)?;
        verify_xray_version(&binary, &tag).await?;
        crate::windows_state::atomic_write(&self.active_file(), tag.as_bytes())
            .map_err(|error| format!("activate Xray {tag}: {error}"))
    }

    pub fn uninstall(&self, tag: &str) -> Result<(), String> {
        let tag = normalize_tag(tag);
        if !valid_tag(&tag) {
            return Err(format!("invalid Xray version: {tag}"));
        }
        if tag == BUNDLED_XRAY_VERSION {
            return Err("the Xray version bundled with Varmlen cannot be removed".into());
        }
        if tag == self.active_tag() {
            return Err("activate another Xray version before removing this one".into());
        }
        let directory = self.versions_dir().join(tag);
        match std::fs::remove_dir_all(directory) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(format!("remove Xray version: {error}")),
        }
    }

    fn versions_dir(&self) -> PathBuf {
        self.layout.state_dir.join("cores").join("xray")
    }

    fn active_file(&self) -> PathBuf {
        self.layout.state_dir.join("active-xray.txt")
    }
}

fn http_client() -> Result<reqwest::Client, String> {
    let redirects = reqwest::redirect::Policy::custom(|attempt| {
        if allowed_http_url(attempt.url()) {
            attempt.follow()
        } else {
            attempt.stop()
        }
    });
    reqwest::Client::builder()
        .user_agent("Varmlen-Windows-Core-Updater")
        .redirect(redirects)
        .timeout(Duration::from_secs(45))
        .build()
        .map_err(|error| format!("create HTTP client: {error}"))
}

fn allowed_http_url(url: &reqwest::Url) -> bool {
    url.scheme() == "https"
        && matches!(
            url.host_str(),
            Some(
                "api.github.com"
                    | "github.com"
                    | "objects.githubusercontent.com"
                    | "release-assets.githubusercontent.com"
            )
        )
}

async fn fetch_text(url: &str) -> Result<String, String> {
    let parsed =
        reqwest::Url::parse(url).map_err(|error| format!("invalid GitHub URL: {error}"))?;
    if !allowed_http_url(&parsed) {
        return Err("refusing a non-GitHub release URL".into());
    }
    let response = http_client()?
        .get(parsed)
        .send()
        .await
        .map_err(|error| format!("GitHub release request: {error}"))?;
    if !response.status().is_success() {
        return Err(format!(
            "GitHub release request returned HTTP {}",
            response.status()
        ));
    }
    if response
        .content_length()
        .is_some_and(|length| length as usize > MAX_RELEASE_BODY)
    {
        return Err("GitHub release response exceeds the size limit".into());
    }
    let bytes = response
        .bytes()
        .await
        .map_err(|error| format!("read GitHub release response: {error}"))?;
    if bytes.len() > MAX_RELEASE_BODY {
        return Err("GitHub release response exceeds the size limit".into());
    }
    String::from_utf8(bytes.to_vec())
        .map_err(|error| format!("GitHub response is not UTF-8: {error}"))
}

#[cfg(windows)]
fn extract_xray(
    archive_path: &std::path::Path,
    destination: &std::path::Path,
) -> Result<(), String> {
    use std::io::{Read, Write};
    let archive_file =
        std::fs::File::open(archive_path).map_err(|error| format!("open Xray archive: {error}"))?;
    let mut archive =
        zip::ZipArchive::new(archive_file).map_err(|error| format!("open Xray ZIP: {error}"))?;
    let mut found = None;
    for index in 0..archive.len() {
        let file = archive
            .by_index(index)
            .map_err(|error| format!("read Xray ZIP: {error}"))?;
        if file.name().rsplit('/').next() == Some("xray.exe") {
            if found.is_some() {
                return Err("Xray ZIP contains multiple xray.exe entries".into());
            }
            found = Some(index);
        }
    }
    let index = found.ok_or_else(|| "Xray ZIP has no xray.exe".to_string())?;
    let input = archive
        .by_index(index)
        .map_err(|error| format!("read xray.exe: {error}"))?;
    if input.size() == 0 || input.size() > 128 * 1024 * 1024 {
        return Err("xray.exe has an invalid extracted size".into());
    }
    let mut output = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(destination)
        .map_err(|error| format!("create extracted xray.exe: {error}"))?;
    let mut limited = input.take(128 * 1024 * 1024 + 1);
    let copied = std::io::copy(&mut limited, &mut output)
        .map_err(|error| format!("extract xray.exe: {error}"))?;
    if copied > 128 * 1024 * 1024 {
        return Err("xray.exe exceeded the extraction size limit".into());
    }
    output
        .flush()
        .map_err(|error| format!("flush xray.exe: {error}"))?;
    output
        .sync_all()
        .map_err(|error| format!("sync xray.exe: {error}"))
}

#[cfg(windows)]
async fn verify_xray_version(binary: &std::path::Path, expected: &str) -> Result<(), String> {
    let output = tokio::time::timeout(
        Duration::from_secs(10),
        tokio::process::Command::new(binary).arg("version").output(),
    )
    .await
    .map_err(|_| "Xray version check timed out".to_string())?
    .map_err(|error| format!("run downloaded Xray: {error}"))?;
    if !output.status.success() {
        return Err("downloaded xray.exe failed its version check".into());
    }
    let version = String::from_utf8_lossy(&output.stdout)
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .map(normalize_tag)
        .ok_or_else(|| "downloaded Xray returned no version".to_string())?;
    if version != normalize_tag(expected) {
        return Err(format!(
            "downloaded Xray reports {version}, expected {expected}"
        ));
    }
    Ok(())
}

#[cfg(windows)]
struct TemporaryFiles(Vec<PathBuf>);

#[cfg(windows)]
impl Drop for TemporaryFiles {
    fn drop(&mut self) {
        for path in &self.0 {
            let _ = std::fs::remove_file(path);
        }
    }
}
