use clap::Parser;
use std::path::{Path, PathBuf};
use std::process::Command;

fn s3_cp(
    local: &Path,
    dest: &str,
    endpoint_url: Option<&str>,
    profile: Option<&str>,
) -> anyhow::Result<()> {
    eprintln!("Uploading to {}...", dest);
    let mut cmd = Command::new("aws");
    cmd.args(["s3", "cp"]);
    cmd.arg(local.to_str().unwrap());
    cmd.arg(dest);
    if let Some(endpoint) = endpoint_url {
        cmd.args(["--endpoint-url", endpoint]);
    }
    if let Some(profile) = profile {
        cmd.args(["--profile", profile]);
    }
    let status = cmd.status().map_err(|e| {
        anyhow::anyhow!(
            "failed to run `aws` CLI: {} — install from https://aws.amazon.com/cli/",
            e
        )
    })?;
    if !status.success() {
        anyhow::bail!("aws s3 cp failed with exit code {}", status);
    }
    Ok(())
}

#[derive(Parser)]
#[command(about = "Build a checkpoint archive from a synced spaced data directory")]
struct Args {
    /// Path to a fully synced spaced network dir (e.g. .../spaced/mainnet)
    #[arg(long)]
    data_dir: PathBuf,

    /// Output directory for the archive
    #[arg(long, default_value = ".")]
    output_dir: PathBuf,

    /// Upload to S3-compatible bucket (e.g. s3://bucket-name/path/)
    #[arg(long)]
    upload: Option<String>,

    /// S3 endpoint URL for non-AWS providers like Cloudflare R2
    #[arg(long, requires = "upload")]
    endpoint_url: Option<String>,

    /// AWS CLI profile name
    #[arg(long, requires = "upload")]
    profile: Option<String>,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    let (block_hash, height) = spaces_checkpoint::read_tip(&args.data_dir)?;
    eprintln!("Tip: height={} hash={}", height, block_hash);

    let filename = format!("checkpoint-{}.tar.gz", height);
    let output = args.output_dir.join(&filename);

    eprintln!("Creating {}...", output.display());
    for name in spaces_checkpoint::CHECKPOINT_FILES {
        eprintln!("  {}", name);
    }

    let digest = spaces_checkpoint::build_checkpoint(&args.data_dir, &output)?;

    eprintln!(
        "\nArchive: {} ({} bytes)",
        output.display(),
        std::fs::metadata(&output)?.len()
    );
    eprintln!("SHA-256: {}", hex::encode(digest));

    spaces_checkpoint::write_integrity(height, &block_hash, &digest)?;
    eprintln!("Updated checkpoint/src/integrity.rs");

    if let Some(bucket) = &args.upload {
        let bucket = bucket.trim_end_matches('/');

        // Upload the archive
        s3_cp(
            &output,
            &format!("{}/{}", bucket, filename),
            args.endpoint_url.as_deref(),
            args.profile.as_deref(),
        )?;

        // Write and upload latest.json
        let latest = spaces_checkpoint::Checkpoint {
            height,
            block_hash: block_hash.clone(),
            digest: hex::encode(digest),
        };
        let latest_path = args.output_dir.join("latest.json");
        std::fs::write(&latest_path, serde_json::to_string_pretty(&latest)?)?;
        s3_cp(
            &latest_path,
            &format!("{}/latest.json", bucket),
            args.endpoint_url.as_deref(),
            args.profile.as_deref(),
        )?;

        eprintln!("Upload complete.");
    }

    Ok(())
}
