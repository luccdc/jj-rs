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

    /// If the remote host is specified, indicate NAT reflection
    #[arg(long, short)]
    pub local: bool,

    /// Listen for an external connection attempt
    #[arg(long, short)]
    pub external: bool,

    /// Disable the download shell used to test the FTP and TCP connections
    #[arg(long, short)]
    pub disable_download_shell: bool,

    /// Specify an IP address to use the download container with
    #[arg(long, short = 'I')]
    pub sneaky_ip: Option<Ipv4Addr>,

    /// Additional service names to check
    #[arg(long, short = 's')]
    pub additional_services: Vec<String>,

    /// Compare a local hashfile with the remote file's hash
    #[arg(short = 'X', long)]
    pub compare_hash: Option<String>,

    /// Test write permissions by uploading and deleting a temporary file
    #[arg(short = 'w', long)]
    pub write_test: bool,

    /// Timeout in seconds for FTP operations
    #[arg(long, short = 't', default_value_t = 15)]
    pub timeout: u64,
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
            timeout: 15,
            additional_services: Vec::new(),
        }
    }
}

impl Troubleshooter for FtpTroubleshooter {
    fn display_name(&self) -> &'static str {
        "FTP"
    }

    fn checks<'a>(&'a self) -> eyre::Result<Vec<Box<dyn super::CheckStep<'a> + 'a>>> {
        #[cfg(unix)]
        let mut services = vec!["vsftpd", "ftpd", "proftpd"];
        #[cfg(windows)]
        let mut services = vec!["ftpsvc", "FileZilla Server"];

        // Add user-specified services
        services.extend(self.additional_services.iter().map(|s| s.as_str()));

        Ok(vec![
            filter_check(
                service_check(services.clone()),
                self.host.is_loopback() || self.local,
                "Cannot check service on remote host",
            ),

            // Binary / port check
            #[cfg(unix)]
            binary_ports_check(
                Some(services.clone()),
                self.port,
                CheckIpProtocol::Tcp,
                self.host.is_loopback() || self.local,
            ),

            // TCP connection check
            tcp_connect_check(
                self.host,
                self.port,
                self.disable_download_shell,
                self.sneaky_ip,
            ),

            // Optional Unix tcpdump
            #[cfg(unix)]
            immediate_tcpdump_check(
                self.port,
                CheckIpProtocol::Tcp,
                b"openssh".to_vec(),
                self.host.is_loopback() || self.local,
            ),

            // Remote login
            check_fn("Try remote login", |tr| self.try_remote_login(tr)),

            // PAM check for Unix
            #[cfg(unix)]
            pam_check(
                Some("vsftpd"),
                &self.user,
                self.password.clone(),
                self.host.is_loopback() || self.local,
            ),

            // Passive tcpdump for Unix
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
        let pass = if self.user.eq_ignore_ascii_case("anonymous") {
            String::new()
        } else {
            self.password
                .clone()
                .resolve_prompt(tr, "Enter a password to sign into the FTP server with: ")?
        };

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

        let system_logs = (self.local || host.is_loopback()).then(|| get_system_logs(start, end));

        let mut result = check_result.into_check_result("Could not contact remote server");

        if let Some(logs) = system_logs {
            result = result.merge_overwrite_details(serde_json::json!({
                "system_logs": logs,
            }));
        }

        Ok(result)
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

        let user = user.to_string();
        let password = password.to_string();
        let compare_hash_file = self.compare_hash.clone();
        let write_test_enabled = self.write_test;
        let timeout_seconds = self.timeout;

        let operation = time::timeout(
            Duration::from_secs(timeout_seconds),
            tokio::task::spawn_blocking(move || {
                let mut ftp = FtpStream::connect((host, port))?;

                let login_result = ftp.login(&user, &password);

                let mut result_json = serde_json::json!({
                    "login": {
                        "username": user,
                        "success": login_result.is_ok()
                    }
                });

                if login_result.is_err() {
                    return Ok::<_, eyre::Report>(serde_json::json!({
                        "login": {
                            "success": false,
                            "error": format!("{:?}", login_result.err())
                        }
                    }));
                }

                let mut overall_success = true;

                // HASH CHECK (-X)
                if let Some(manifest_path) = compare_hash_file {
                    let manifest_contents = std::fs::read_to_string(&manifest_path)?;
                    let mut comparisons = Vec::new();
                    let mut hash_failed = false;

                    for line in manifest_contents.lines() {
                        let line = line.trim();
                        if line.is_empty() || line.starts_with('#') {
                            continue;
                        }

                        let mut parts = line.split_whitespace();
                        let remote_path = match parts.next() {
                            Some(p) => p,
                            None => continue,
                        };
                        let expected_hash = match parts.next() {
                            Some(h) => h,
                            None => continue,
                        };

                        let retrieve_result = ftp.simple_retr(remote_path);

                        match retrieve_result {
                            Ok(data) => {
                                let bytes = data.into_inner();
                                let mut hasher = Sha256::new();
                                hasher.update(&bytes);
                                let remote_hash = format!("{:x}", hasher.finalize());
                                let matches = remote_hash.eq_ignore_ascii_case(expected_hash);

                                if matches {
                                    comparisons.push(serde_json::json!({
                                        "file": remote_path,
                                        "remote_hash": remote_hash,
                                        "match": true
                                    }));
                                } else {
                                    hash_failed = true;
                                    comparisons.push(serde_json::json!({
                                        "file": remote_path,
                                        "expected_hash": expected_hash,
                                        "remote_hash": remote_hash,
                                        "match": false
                                    }));
                                }
                            }
                            Err(e) => {
                                hash_failed = true;
                                comparisons.push(serde_json::json!({
                                    "file": remote_path,
                                    "match": false,
                                    "error": format!("{e:}")
                                }));
                            }
                        }
                    }

                    result_json["compare_hash"] = serde_json::json!({
                        "results": comparisons,
                        "all_match": !hash_failed
                    });

                    if hash_failed {
                        overall_success = false;
                    }
                }

                // write test
                if write_test_enabled {
                    use std::io::Cursor;

                    let test_filename = format!(
                        "jj_write_test_{}.tmp",
                        Utc::now().timestamp_nanos_opt().unwrap_or_default()
                    );
                    let test_contents = b"jj-rs FTP write test";

                    let write_result = (|| -> eyre::Result<()> {
                        ftp.put(&test_filename, &mut Cursor::new(test_contents))?;
                        let files = ftp.list(None)?;
                        let exists = files.iter().any(|f| f.contains(&test_filename));
                        if !exists {
                            eyre::bail!("File not found after upload");
                        }
                        ftp.rm(&test_filename)?;
                        Ok(())
                    })();

                    match write_result {
                        Ok(_) => {
                            result_json["write_test"] = serde_json::json!({
                                "success": true,
                                "temporary_file": test_filename
                            });
                        }
                        Err(e) => {
                            overall_success = false;
                            let _ = ftp.rm(&test_filename);
                            result_json["write_test"] = serde_json::json!({
                                "success": false,
                                "temporary_file": test_filename,
                                "error": format!("{e:}")
                            });
                        }
                    }
                }

                ftp.quit().ok();
                result_json["overall_success"] = serde_json::json!(overall_success);

                Ok::<_, eyre::Report>(result_json)
            }),
        )
        .await;

        match operation {
            Ok(Ok(Ok(mut details))) => {
                let success = details["overall_success"].as_bool().unwrap_or(false);
                details["status"] = serde_json::json!(if success { "success" } else { "failure" });
                details["timeout_seconds"] = serde_json::json!(timeout_seconds);

                if success {
                    Ok(CheckResult::succeed("", details))
                } else {
                    Ok(CheckResult::fail("", details))
                }
            }

            Ok(Ok(Err(e))) => {
                let json = serde_json::json!({
                    "status": "failure",
                    "stage": "ftp_operation",
                    "error": format!("{e:}"),
                    "timeout_seconds": timeout_seconds
                });
                
                Ok(CheckResult::fail("", json))
            }

            Ok(Err(e)) => {
                let json = serde_json::json!({
                    "status": "failure",
                    "stage": "internal_task",
                    "error": format!("{e:}"),
                    "timeout_seconds": timeout_seconds
                });
                Ok(CheckResult::fail("Failed to perform FTP operation", json))
            }

            Err(_) => {
                let json = serde_json::json!({
                    "status": "failure",
                    "stage": "timeout",
                    "timeout_seconds": timeout_seconds
                });
                Ok(CheckResult::fail("Failed to perform FTP operation", json))
            }
        }
    }
}