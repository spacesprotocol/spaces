# spaces-checkpoint

Fast-sync for spaced nodes by downloading a verified snapshot of the database state.

## Generating a checkpoint

Run from the workspace root with a fully synced spaced data directory:

```bash
cargo run -p spaces-checkpoint --bin checkpoint-builder -- --data-dir /path/to/spaced/mainnet
```

This will:
1. Read the current tip (block hash + height) from `root.sdb`
2. Create `checkpoint-<height>.tar.gz` containing `root.sdb`, `nums.sdb`, and `index.sqlite`
3. Update `checkpoint/src/integrity.rs` with the SHA-256 digest
4. If `--upload` is specified, upload the archive and `latest.json` to S3

### Uploading

Upload to an S3-compatible bucket with `--upload`:

```bash
# AWS S3
checkpoint-builder --data-dir ./mainnet --upload s3://my-bucket/

# Cloudflare R2
checkpoint-builder --data-dir ./mainnet --upload s3://my-bucket/ \
  --endpoint-url https://ACCOUNT_ID.r2.cloudflarestorage.com
```

Requires the [AWS CLI](https://aws.amazon.com/cli/) to be installed and configured.

This uploads both `checkpoint-<height>.tar.gz` and `latest.json` to the bucket. `latest.json` contains the height, block hash, and digest so consumers can check for newer checkpoints without downloading the full archive.

## Usage

Three functions, you control the flow:

```rust
use spaces_checkpoint::{
    needs_checkpoint, fetch_latest, ensure_checkpoint,
    integrity, CHECKPOINT_BASE_URL,
};

// 1. Check if a checkpoint is needed
if needs_checkpoint(&data_dir) {

    // 2. Optionally check for a newer checkpoint than the hardcoded one
    let (url, digest) = if let Ok(Some(latest)) = fetch_latest(CHECKPOINT_BASE_URL) {
        if latest.height > integrity::CHECKPOINT.height {
            // A newer checkpoint is available — let the user decide
            (latest.url(CHECKPOINT_BASE_URL), latest.digest_bytes().unwrap())
        } else {
            // Use hardcoded
            let url = format!("{}/checkpoint-{}.tar.gz",
                CHECKPOINT_BASE_URL, integrity::CHECKPOINT.height);
            (url, integrity::CHECKPOINT.digest)
        }
    } else {
        // Server unreachable, use hardcoded
        let url = format!("{}/checkpoint-{}.tar.gz",
            CHECKPOINT_BASE_URL, integrity::CHECKPOINT.height);
        (url, integrity::CHECKPOINT.digest)
    };

    // 3. Download and apply
    let applied = ensure_checkpoint(&data_dir, &url, &digest, None)?;
    if !applied {
        // Server unreachable after retries, sync from scratch
    }
}
```

### Return values

`ensure_checkpoint` returns:
- `Ok(true)` — checkpoint applied
- `Ok(false)` — server unreachable after retries, fall back to full sync
- `Err(CheckpointError)` — local filesystem error

`fetch_latest` returns:
- `Ok(Some(LatestCheckpoint))` — latest checkpoint metadata from server
- `Ok(None)` — server unreachable
- `Err(CheckpointError)` — invalid response