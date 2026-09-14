pub mod integrity;

use flate2::read::GzDecoder;
use sha2::{Digest, Sha256};
use std::fmt;
use std::io::{Cursor, Read};
use std::path::Path;

pub const CHECKPOINT_BASE_URL: &str = "https://checkpoints.spacesprotocol.org";

/// The three spaced database files included in a checkpoint.
pub const CHECKPOINT_FILES: &[&str] = &["root.sdb", "nums_v2.sdb", "index.sqlite"];

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Checkpoint {
    pub height: u32,
    pub block_hash: String,
    /// SHA-256 hex digest of the checkpoint archive
    pub digest: String,
}

impl Checkpoint {
    /// Returns "blockhash:height" identifier.
    pub fn block_id(&self) -> String {
        format!("{}:{}", self.block_hash, self.height)
    }

    /// Parse the hex digest into bytes.
    pub fn digest_bytes(&self) -> Result<[u8; 32], CheckpointError> {
        let bytes = hex::decode(&self.digest)
            .map_err(|e| CheckpointError::Unavailable(format!("invalid digest hex: {}", e)))?;
        if bytes.len() != 32 {
            return Err(CheckpointError::Unavailable(format!(
                "invalid digest length: {}",
                bytes.len()
            )));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(arr)
    }

    /// Build the download URL for this checkpoint.
    pub fn url(&self, base_url: &str) -> String {
        format!(
            "{}/checkpoint-{}.tar.gz",
            base_url.trim_end_matches('/'),
            self.height
        )
    }
}

/// Fetch the latest checkpoint metadata from `<base_url>/latest.json`.
/// Returns `None` if the server is unreachable.
pub fn fetch_latest(base_url: &str) -> Result<Option<Checkpoint>, CheckpointError> {
    let url = format!("{}/latest.json", base_url.trim_end_matches('/'));
    let response = match ureq::get(&url).call() {
        Ok(r) => r,
        Err(_) => return Ok(None),
    };
    let body: String = response
        .into_body()
        .read_to_string()
        .map_err(|e| CheckpointError::Unavailable(e.to_string()))?;
    let latest: Checkpoint = serde_json::from_str(&body)
        .map_err(|e| CheckpointError::Unavailable(format!("invalid latest.json: {}", e)))?;
    Ok(Some(latest))
}

/// Progress callback: (downloaded_bytes, total_bytes).
/// `total_bytes` is 0 if the server didn't send Content-Length.
pub type ProgressFn = dyn Fn(u64, u64) + Send + Sync;

#[derive(Debug)]
pub enum CheckpointError {
    /// Checkpoint server unreachable or download failed after retries
    Unavailable(String),
    /// SHA-256 digest mismatch
    DigestMismatch { expected: String, got: String },
    /// Failed to extract the archive
    Extract(std::io::Error),
    /// Local filesystem error
    Io(std::io::Error),
}

impl fmt::Display for CheckpointError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CheckpointError::Unavailable(msg) => write!(f, "checkpoint unavailable: {}", msg),
            CheckpointError::DigestMismatch { expected, got } => write!(
                f,
                "checkpoint hash mismatch: expected {}, got {}",
                expected, got
            ),
            CheckpointError::Extract(e) => write!(f, "failed to extract checkpoint: {}", e),
            CheckpointError::Io(e) => write!(f, "io error: {}", e),
        }
    }
}

impl std::error::Error for CheckpointError {}

impl From<std::io::Error> for CheckpointError {
    fn from(e: std::io::Error) -> Self {
        CheckpointError::Io(e)
    }
}

const MAX_RETRIES: u32 = 5;

/// Returns true if no spaced data exists and a checkpoint should be applied.
pub fn needs_checkpoint(data_dir: &Path) -> bool {
    !data_dir.join("root.sdb").exists()
}

/// Downloads and extracts a checkpoint.
/// Retries with exponential backoff on transient errors.
/// Returns `Ok(false)` if the checkpoint server is unreachable after retries,
/// allowing the caller to fall back to syncing from scratch.
/// Returns `Ok(true)` if checkpoint was applied.
pub fn ensure_checkpoint(
    target_dir: &Path,
    url: &str,
    expected_digest: &[u8; 32],
    progress: Option<&ProgressFn>,
) -> Result<bool, CheckpointError> {
    std::fs::create_dir_all(target_dir)?;

    for attempt in 0..=MAX_RETRIES {
        if attempt > 0 {
            let delay = std::time::Duration::from_secs(1 << attempt);
            tracing::warn!(
                "checkpoint download attempt {}/{} failed, retrying in {:?}...",
                attempt,
                MAX_RETRIES,
                delay
            );
            std::thread::sleep(delay);
        }

        match download_and_verify(url, expected_digest, progress) {
            Ok(data) => {
                return extract(target_dir, &data).map(|()| true);
            }
            Err(e) => {
                if attempt == MAX_RETRIES {
                    tracing::warn!(
                        "checkpoint unavailable after {} attempts: {} — falling back to full sync",
                        MAX_RETRIES + 1,
                        e
                    );
                    return Ok(false);
                }
                tracing::warn!("checkpoint download error: {}", e);
            }
        }
    }

    Ok(false)
}

fn download_and_verify(
    url: &str,
    expected_digest: &[u8; 32],
    progress: Option<&ProgressFn>,
) -> Result<Vec<u8>, CheckpointError> {
    tracing::info!("downloading checkpoint from {}", url);

    let response = ureq::get(url)
        .call()
        .map_err(|e| CheckpointError::Unavailable(e.to_string()))?;

    let total = response
        .headers()
        .get("content-length")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(0);

    let mut reader = response.into_body().into_reader();
    let mut data = Vec::with_capacity(total as usize);
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = reader
            .read(&mut buf)
            .map_err(|e| CheckpointError::Unavailable(e.to_string()))?;
        if n == 0 {
            break;
        }
        data.extend_from_slice(&buf[..n]);
        if let Some(cb) = &progress {
            cb(data.len() as u64, total);
        }
    }

    tracing::info!("downloaded {} bytes, verifying...", data.len());

    let computed = Sha256::digest(&data);
    if computed.as_slice() != expected_digest {
        return Err(CheckpointError::DigestMismatch {
            expected: hex::encode(expected_digest),
            got: hex::encode(computed),
        });
    }

    tracing::info!("checkpoint hash verified");
    Ok(data)
}

fn extract(target_dir: &Path, data: &[u8]) -> Result<(), CheckpointError> {
    tracing::info!("extracting checkpoint...");
    let decoder = GzDecoder::new(Cursor::new(data));
    let mut archive = tar::Archive::new(decoder);
    archive
        .unpack(target_dir)
        .map_err(CheckpointError::Extract)?;
    tracing::info!("checkpoint extracted to {:?}", target_dir);
    Ok(())
}

/// Read the tip (block hash + height) from a spaced data directory
/// by inspecting the latest snapshot metadata in root.sdb.
#[cfg(feature = "cli")]
pub fn read_tip(data_dir: &Path) -> anyhow::Result<(String, u32)> {
    use spacedb::Sha256Hasher;
    use spacedb::db::Database;
    use spaces_protocol::constants::ChainAnchor;

    let db_path = data_dir.join("root.sdb");
    if !db_path.exists() {
        anyhow::bail!("root.sdb not found in {:?}", data_dir);
    }

    let config = spacedb::Configuration::standard();
    let db: Database<Sha256Hasher> = Database::open_with_config(
        db_path
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("invalid path"))?,
        config,
    )?;

    let snapshot = db
        .iter()
        .next()
        .ok_or_else(|| anyhow::anyhow!("no snapshots in root.sdb"))?;
    let snapshot = snapshot?;
    let anchor: ChainAnchor = snapshot
        .metadata()
        .try_into()
        .map_err(|_| anyhow::anyhow!("could not read snapshot metadata"))?;

    Ok((anchor.hash.to_string(), anchor.height))
}

/// Build a checkpoint archive from a spaced data directory.
/// Returns the SHA-256 digest of the produced archive.
#[cfg(feature = "cli")]
pub fn build_checkpoint(data_dir: &Path, output: &Path) -> anyhow::Result<[u8; 32]> {
    use flate2::Compression;
    use flate2::write::GzEncoder;
    use std::fs::File;

    for name in CHECKPOINT_FILES {
        let path = data_dir.join(name);
        if !path.exists() {
            anyhow::bail!("{} not found in {:?}", name, data_dir);
        }
    }

    let out_file = File::create(output)?;
    let encoder = GzEncoder::new(out_file, Compression::best());
    let mut archive = tar::Builder::new(encoder);

    for name in CHECKPOINT_FILES {
        let path = data_dir.join(name);
        archive.append_path_with_name(&path, name)?;
    }

    archive.into_inner()?.finish()?;

    let archive_data = std::fs::read(output)?;
    let hash = Sha256::digest(&archive_data);
    let mut digest = [0u8; 32];
    digest.copy_from_slice(&hash);
    Ok(digest)
}

/// Format the integrity.rs file content with the checkpoint function.
pub fn format_integrity_file(height: u32, block_hash: &str, digest: &[u8; 32]) -> String {
    format!(
        r#"// AUTO GENERATED by checkpoint-builder. Do not edit manually.
pub fn checkpoint() -> super::Checkpoint {{
    super::Checkpoint {{
        height: {},
        block_hash: "{}".to_string(),
        digest: "{}".to_string(),
    }}
}}
"#,
        height,
        block_hash,
        hex::encode(digest),
    )
}

/// Write the checkpoint constant to `checkpoint/src/integrity.rs` relative to
/// the current working directory. Must be run from the workspace root.
#[cfg(feature = "cli")]
pub fn write_integrity(height: u32, block_hash: &str, digest: &[u8; 32]) -> anyhow::Result<()> {
    write_integrity_to(
        Path::new("checkpoint/src/integrity.rs"),
        height,
        block_hash,
        digest,
    )
}

/// Write the checkpoint constant to a Rust source file at `path`.
#[cfg(feature = "cli")]
pub fn write_integrity_to(
    path: &Path,
    height: u32,
    block_hash: &str,
    digest: &[u8; 32],
) -> anyhow::Result<()> {
    std::fs::write(path, format_integrity_file(height, block_hash, digest))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};

    // Network integration test: downloads the checkpoint named in
    // `integrity::checkpoint()` from the live server. Ignored by default —
    // it requires that specific archive to already be uploaded (freshly
    // generated checkpoints aren't, until published), makes a multi-MB
    // production request, and would otherwise couple CI to server state.
    // Run manually after upload: `cargo test -p spaces_checkpoint -- --ignored`.
    #[test]
    #[ignore = "requires the current checkpoint to be uploaded to the server"]
    fn download_reports_progress() {
        let cp = integrity::checkpoint();
        let url = cp.url(CHECKPOINT_BASE_URL);
        let digest = cp.digest_bytes().unwrap();

        let last_downloaded = Arc::new(AtomicU64::new(0));
        let last_total = Arc::new(AtomicU64::new(0));
        let call_count = Arc::new(AtomicU64::new(0));

        let ld = last_downloaded.clone();
        let lt = last_total.clone();
        let cc = call_count.clone();
        let progress: Box<ProgressFn> = Box::new(move |downloaded, total| {
            ld.store(downloaded, Ordering::SeqCst);
            lt.store(total, Ordering::SeqCst);
            cc.fetch_add(1, Ordering::SeqCst);
        });

        let dir = tempfile::tempdir().unwrap();
        let applied = ensure_checkpoint(dir.path(), &url, &digest, Some(&*progress)).unwrap();

        assert!(applied, "checkpoint should be applied");
        assert!(
            call_count.load(Ordering::SeqCst) > 1,
            "progress should be called multiple times"
        );

        let total = last_total.load(Ordering::SeqCst);
        assert!(
            total > 0,
            "total bytes should be reported from content-length"
        );

        let downloaded = last_downloaded.load(Ordering::SeqCst);
        assert_eq!(downloaded, total, "final downloaded should equal total");

        // Verify the files were extracted
        for name in CHECKPOINT_FILES {
            assert!(dir.path().join(name).exists(), "{} should exist", name);
        }
    }
}
