use std::{net::Ipv4Addr};

use chrono::Utc;

use super::*;

/// Troubleshoot a FTP server connection
#[derive(clap::Parser, serde::Serialize, serde::Deserialize, Debug, Clone)]
#[serde(default)]
pub struct FtpTroubleshooter {
    /// The host to connect to and attempt signing in
    #[arg(long, short = 'H', default_value = "127.0.0.1")]
    pub host: Ipv4Addr,

    /// The port of the FTP server
    #[arg(long, short, default_value_t = 21)]
    pub port: u16,

    /// The user to sign in as
    #[arg(long, short, default_value = "Anonymous")]
    pub user: String,

    /// [`CheckValue`] The password to authenticate with
    #[arg(long, short = 'P', default_value_t = Default::default())]
    pub password: CheckValue,

    /// If the remote host is specified, indicate that the traffic sent to the remote host will be sent
    /// back to this server via NAT reflection (e.g., debug firewall on another machine, network firewall
    /// WAN IP for this machine)
    #[arg(long, short)]
    pub local: bool,

    /// Listen for an external connection attempt, and diagnose what appears to
    /// be going wrong with such a check. All other steps attempt to initiate connections
    #[arg(long, short)]
    pub external: bool,

    /// Disable the download shell used to test the FTP and TCP connections
    #[arg(long, short)]
    pub disable_download_shell: bool,

    /// Specify an IP address to use the download container with
    #[arg(long, short = 'I')]
    pub sneaky_ip: Option<Ipv4Addr>,

    /// Compare a local hashfile with the remote file's hash
    #[arg(short = 'X', long)]
    pub compare_hash: Option<String>, // path to local hashfile

    /// Test write permissions by uploading and deleting a temporary file
    #[arg(short = 'w', long)]
    pub write_test: bool,


}

impl Default for FtpTroubleshooter {
    fn default() -> Self {
        FtpTroubleshooter {
            host: Ipv4Addr::from(0x7F_00_00_01),
            port: 21,
            user: "Anonymous".to_string(),
            password: CheckValue::stdin(),
            local: false,
            external: false,
            disable_download_shell: false,
            sneaky_ip: None,
            compare_hash: None,
            write_test: false,
        }
    }
}

impl Troubleshooter for FtpTroubleshooter {
    fn display_name(&self) -> &'static str {
        "FTP"
    }

    fn checks<'a>(&'a self) -> eyre::Result<Vec<Box<dyn super::CheckStep<'a> + 'a>>> {
        Ok(vec![
            #[cfg(unix)]
            filter_check(
                systemd_services_check(["vsftpd", "ftpd", "proftpd"]),
                self.host.is_loopback() || self.local,
                "Cannot check systemd service on remote host",
            ),
            #[cfg(unix)]
            filter_check(
                openrc_services_check(["vsftpd"]),
                self.host.is_loopback() || self.local,
                "Cannot check openrc service on remote host",
            ),
            #[cfg(unix)]
            binary_ports_check(
                #[cfg(unix)]
                Some(["ftp"]),
                #[cfg(windows)]
                Some(["ftp.exe"]),
                self.port,
                CheckIpProtocol::Tcp,
                self.host.is_loopback() || self.local,
            ),
            tcp_connect_check(
                self.host,
                self.port,
                self.disable_download_shell,
                self.sneaky_ip,
            ),
            #[cfg(unix)]
            immediate_tcpdump_check(
                self.port,
                CheckIpProtocol::Tcp,
                b"openssh".to_vec(),
                self.host.is_loopback() || self.local,
            ),
            check_fn("Try remote login", |tr| self.try_remote_login(tr)),
            #[cfg(unix)]
            pam_check(
                Some("vsftpd"),
                &self.user,
                self.password.clone(),
                self.host.is_loopback() || self.local,
            ),
            #[cfg(unix)]
            passive_tcpdump_check(
                self.port,
                self.external,
                !self.host.is_loopback() && !self.local,
                get_system_logs,
            ),
        ])
    }
}

impl FtpTroubleshooter {
    fn try_remote_login(&self, tr: &mut dyn TroubleshooterRunner) -> eyre::Result<CheckResult> {
        let host = self.host;
        let port = self.port;
        let user = self.user.clone();
        let pass = self
            .password
            .clone()
            .resolve_prompt(tr, "Enter a password to sign into the FTP server with: ")?;

        let (check_result, start) = crate::utils::checks::optionally_run_in_container(
            host.is_loopback() || self.local,
            self.disable_download_shell,
            self.sneaky_ip,
            || {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|e| format!("{e}"))
                    .and_then(|rt| {
                        rt.block_on(self.try_connection(host, port, &user, &pass))
                            .map_err(|e| format!("{e}"))
                    })
            },
        );

        let end = Utc::now();

        let logs = (self.local || host.is_loopback()).then(|| get_system_logs(start, end));

        Ok(check_result
            .into_check_result("Could not contact remote server")
            .merge_overwrite_details(serde_json::json!({
                "system_logs": logs,
            })))
    }

    async fn try_connection(
    &self,
    host: Ipv4Addr,
    port: u16,
    user: &str,
    password: &str,
) -> eyre::Result<CheckResult> {
    use ::ftp::FtpStream;
    use tokio::time::{self, Duration};
    use sha2::{Sha256, Digest};
    //use std::fs;

    let user = user.to_string();
    let password = password.to_string();
    let compare_hash_file = self.compare_hash.clone();
    let write_test_enabled = self.write_test;


let operation = time::timeout(
    Duration::from_secs(15),
    tokio::task::spawn_blocking(move || {
        let mut ftp = FtpStream::connect((host, port))?;
        ftp.login(&user, &password)?;

        let mut result_json = serde_json::json!({});



// Compare hashes (-X)
if let Some(raw_manifest_path) = compare_hash_file {
    use std::path::PathBuf;

    // Expand ~ to home directory if present
    let expanded_path = if raw_manifest_path.starts_with("~/") {
        if let Some(home) = dirs::home_dir() {
            home.join(raw_manifest_path.trim_start_matches("~/"))
        } else {
            PathBuf::from(&raw_manifest_path)
        }
    } else {
        PathBuf::from(&raw_manifest_path)
    };

    // Resolve relative paths against current working directory
    let manifest_path = if expanded_path.is_absolute() {
        expanded_path
    } else {
        std::env::current_dir()?.join(expanded_path)
    };

    println!("\nUsing hash manifest: {}", manifest_path.display());

    let manifest_contents = std::fs::read_to_string(&manifest_path)?;

    let mut comparisons = Vec::new();

    for (line_number, line) in manifest_contents.lines().enumerate() {
        let line = line.trim();

        // Skip empty lines and comments
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let mut parts = line.split_whitespace();

        let remote_path = parts.next().ok_or_else(|| {
            eyre::eyre!(
                "Invalid format in {} at line {}: missing file path",
                manifest_path.display(),
                line_number + 1
            )
        })?;

        let expected_hash = parts.next().ok_or_else(|| {
            eyre::eyre!(
                "Invalid format in {} at line {}: missing hash",
                manifest_path.display(),
                line_number + 1
            )
        })?;

        // Retrieve remote file
        let data = ftp.simple_retr(remote_path)?;
        let bytes = data.into_inner();

        // Compute SHA256
        let mut hasher = Sha256::new();
        hasher.update(&bytes);
        let remote_hash = format!("{:x}", hasher.finalize());

        let matches = remote_hash.eq_ignore_ascii_case(expected_hash);

        println!(
            "File: {} | Match: {}",
            remote_path,
            if matches { "YES" } else { "NO" }
        );

        comparisons.push(serde_json::json!({
            "file": remote_path,
            "expected_hash": expected_hash,
            "remote_hash": remote_hash,
            "match": matches,
        }));
    }

    result_json["compare_hash"] = serde_json::json!({
        "manifest_file": manifest_path.display().to_string(),
        "results": comparisons,
    });
}
    //write test (-w)
    if write_test_enabled {
        use chrono::Utc;
        use std::io::Cursor;

        let test_filename = format!(
            "jj_write_test_{}.tmp",
            Utc::now().timestamp_nanos_opt().unwrap_or_default()
        );

        let test_contents = format!(
            "jj-rs FTP write test\nTimestamp: {}\n",
            Utc::now().to_rfc3339()
        );

        println!("\nAttempting write test with temporary file: {}", test_filename);

        let write_result = (|| -> eyre::Result<serde_json::Value> {
            // Upload file
            ftp.put(
                &test_filename,
                &mut Cursor::new(test_contents.as_bytes()),
            )?;

            println!("Upload successful.");

            // Verify file exists
            let files = ftp.list(None)?;
            let exists = files.iter().any(|f| f.contains(&test_filename));

            if !exists {
                eyre::bail!("Uploaded file not found in directory listing");
            }

            println!("File verified in listing.");

            // Delete file
            ftp.rm(&test_filename)?;
            println!("Temporary file deleted successfully.");

            Ok(serde_json::json!({
                "temporary_file": test_filename,
                "upload_success": true,
                "verified_in_listing": true,
                "deleted_successfully": true
            }))
        })();

        match write_result {
            Ok(details) => {
                result_json["write_test"] = details;
            }
            Err(e) => {
                // Attempt cleanup if something failed
                let _ = ftp.rm(&test_filename);

                result_json["write_test"] = serde_json::json!({
                    "temporary_file": test_filename,
                    "error": format!("{e:?}"),
                    "upload_success": false
                });
            }
        }
    }

        ftp.quit().ok();
        Ok::<_, eyre::Report>(result_json)
    }),
)

    .await;

    match operation {
        Ok(Ok(Ok(details))) => Ok(CheckResult::succeed(
            "FTP operation succeeded",
            details,
        )),
        Ok(Ok(Err(e))) => Ok(CheckResult::fail(
            "FTP operation failed",
            serde_json::json!({
                "ftp_error": format!("{e:?}")
            }),
        )),
        Ok(Err(e)) => Ok(CheckResult::fail(
            "Internal blocking task failure",
            serde_json::json!({
                "task_error": format!("{e:?}")
            }),
        )),
        Err(_) => Ok(CheckResult::fail(
            "FTP operation timeout",
            serde_json::json!({}),
        )),
    }
}
}