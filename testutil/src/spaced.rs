use std::{
    net::Ipv4Addr,
    path::PathBuf,
    process::{Child, Stdio},
    time::Duration,
};

use anyhow::Result;
use assert_cmd::cargo::CommandCargoExt;
use bitcoind::{anyhow, anyhow::anyhow, get_available_port, tempfile::{tempdir, TempDir}};
use spaces_client::{
    auth::{auth_token_from_creds, http_client_with_auth},
    jsonrpsee::{http_client::HttpClient, tokio},
    log::{debug, error},
    rpc::RpcClient,
};

const LOCAL_IP: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 1);

/// Conf a similar structure to bitcoind crate configuration
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct Conf<'a> {
    /// Spaced command line arguments e.g. `vec!["--chain", "regtest"]`
    /// note that `--rpc-port`, `--data-dir` are automatically initialized.
    pub args: Vec<&'a str>,
    pub view_stdout: bool,
    /// Optional fixed data directory. If None, a temp directory is used.
    pub data_dir: Option<PathBuf>,
}

#[derive(Debug)]
pub struct SpaceD {
    process: Child,
    pub client: HttpClient,
    rpc_port: u16,
    /// Temp directory handle - keeps it alive until SpaceD is dropped
    _data_dir_tempdir: Option<TempDir>,
}

impl SpaceD {
    pub async fn new(conf: Conf<'_>) -> Result<Self> {
        let rpc_port = get_available_port()?;

        let stdout = if conf.view_stdout {
            Stdio::inherit()
        } else {
            Stdio::null()
        };

        let args: Vec<_> = conf.args.into_iter().map(String::from).collect();
        let data_dir = conf.data_dir.clone();
        let (process, tempdir_handle) = tokio::task::spawn_blocking(move || -> Result<(Child, Option<TempDir>)> {
            let (data_dir_path, tempdir_handle) = match data_dir {
                Some(path) => (path, None),
                None => {
                    let td = tempdir()?;
                    let path = td.path().to_path_buf();
                    (path, Some(td))
                }
            };

            #[allow(deprecated)]
            let child = std::process::Command::cargo_bin("spaced")?
                .args(args)
                .arg("--rpc-port")
                .arg(rpc_port.to_string())
                .arg("--data-dir")
                .arg(&data_dir_path)
                .arg("--rpc-user")
                .arg("user")
                .arg("--rpc-password")
                .arg("pass")
                .stdout(stdout)
                .spawn()?;

            Ok((child, tempdir_handle))
        })
        .await
        .expect("spawn blocking task")?;

        let client =
            http_client_with_auth(&rpc_url(rpc_port), &auth_token_from_creds("user", "pass"))?;

        let mut spaced = Self {
            process,
            rpc_port,
            client,
            _data_dir_tempdir: tempdir_handle,
        };

        let mut i = 0;
        loop {
            if let Some(status) = spaced.process.try_wait()? {
                error!("early exit with: {:?}", status);
                return Err(anyhow!("Spaced exited with status {} ", status));
            }

            tokio::time::sleep(Duration::from_millis(100)).await;
            assert!(spaced.process.stderr.is_none());

            if spaced.client.get_server_info().await.is_ok() {
                break;
            }

            debug!(
                "spaces client for process {} not ready ({})",
                spaced.process.id(),
                i
            );
            i += 1;
        }

        Ok(spaced)
    }

    pub fn rpc_url(&self) -> String {
        rpc_url(self.rpc_port)
    }
}

fn rpc_url(port: u16) -> String {
    format!("http://{}:{}", LOCAL_IP, port)
}

impl Drop for SpaceD {
    fn drop(&mut self) {
        debug!("killing spaced process");
        let _ = self.process.kill();
    }
}
