use super::*;
use chrono::Utc;
use std::net::Ipv4Addr;

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

    /// Test write permissions by uploading and deleting a temporary file in the
    /// specified directory
    #[arg(short = 'w', long)]
    pub write_path: Option<String>,

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
            write_path: None,
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
            check_fn("Compare remote hashes", |tr| self.try_compare_hashes(tr)),
            check_fn("Perform remote write test", |tr| self.try_remote_write(tr)),
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
    fn try_compare_hashes(&self, tr: &mut dyn TroubleshooterRunner) -> eyre::Result<CheckResult> {
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
        let Some(hashes_path) = self.compare_hash.clone() else {
            return Ok(CheckResult::not_run(
                "Hash file not provided to perform hash checking",
                serde_json::json!({}),
            ));
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
                        rt.block_on(self.try_compare_hashes_internal(
                            host,
                            port,
                            &user,
                            &pass,
                            hashes_path,
                        ))
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

    fn try_remote_write(&self, tr: &mut dyn TroubleshooterRunner) -> eyre::Result<CheckResult> {
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

        let Some(write_path) = self.write_path.clone() else {
            return Ok(CheckResult::not_run(
                "Write path not provided to perform write check",
                serde_json::json!({}),
            ));
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
                        rt.block_on(self.try_write_internal(host, port, &user, &pass, write_path))
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

    async fn try_compare_hashes_internal(
        &self,
        host: Ipv4Addr,
        port: u16,
        user: &str,
        password: &str,
        manifest_path: String,
    ) -> eyre::Result<CheckResult> {
        use ::ftp::FtpStream;
        use sha2::Digest;
        use tokio::time::{self, Duration};

        let user = user.to_string();
        let password = password.to_string();
        let timeout_seconds = self.timeout;

        let task = move || -> eyre::Result<CheckResult> {
            let mut ftp = match FtpStream::connect((host, port)) {
                Ok(ftp) => ftp,
                Err(e) => {
                    return Ok(CheckResult::fail(
                        "Could not establish connection to FTP server",
                        serde_json::json!({
                            "error": format!("{e}")
                        }),
                    ));
                }
            };

            if let Err(e) = ftp.login(&user, &password) {
                return Ok(CheckResult::fail(
                    "Could not login to the FTP server",
                    serde_json::json!({
                        "error": format!("{e}")
                    }),
                ));
            };

            struct HashCheckResult {
                file: String,
                remote_hash: eyre::Result<String>,
                expected_hash: String,
                failed: bool,
            }

            fn serialize_hcr(hcr: &HashCheckResult) -> serde_json::Value {
                match &hcr.remote_hash {
                    Ok(rh) if hcr.failed => serde_json::json!({
                        "file": hcr.file.clone(),
                        "remote_hash": rh.clone(),
                        "expected_hash": hcr.expected_hash.clone(),
                        "failed": true
                    }),
                    Ok(_) => serde_json::json!({
                        "file": hcr.file.clone(),
                        "hash": hcr.expected_hash.clone(),
                        "failed": false,
                    }),
                    Err(e) => serde_json::json!({
                        "file": hcr.file.clone(),
                        "expected_hash": hcr.expected_hash.to_string(),
                        "error": format!("{e}"),
                        "failed": true,
                    }),
                }
            }

            let manifest_contents = std::fs::read_to_string(&manifest_path)?;

            let hash_comparison_results = manifest_contents
                .lines()
                .filter_map(|line| {
                    let line = line.trim();
                    if line.is_empty() || line.starts_with('#') {
                        return None;
                    }

                    let mut parts = line.split_whitespace();
                    let remote_path = parts.next()?;
                    let expected_hash = parts.next()?;

                    Some((remote_path, expected_hash))
                })
                .map(|(remote_path, expected_hash)| {
                    let retrieve_result = ftp.retr(&remote_path, |reader| {
                        let mut hasher = sha2::Sha256::new();
                        let mut buffer = [0u8; 8192];
                        loop {
                            let n = reader
                                .read(&mut buffer)
                                .map_err(::ftp::FtpError::ConnectionError)?;
                            if n == 0 {
                                break;
                            }
                            hasher.update(&buffer[..n]);
                        }
                        Ok(format!("{:x}", hasher.finalize()))
                    });

                    match retrieve_result {
                        Ok(remote_hash) if remote_hash.eq_ignore_ascii_case(expected_hash) => {
                            HashCheckResult {
                                file: remote_path.to_string(),
                                remote_hash: Ok(remote_hash),
                                expected_hash: expected_hash.to_string(),
                                failed: false,
                            }
                        }
                        Ok(remote_hash) => HashCheckResult {
                            file: remote_path.to_string(),
                            remote_hash: Ok(remote_hash),
                            expected_hash: expected_hash.to_string(),
                            failed: true,
                        },
                        Err(e) => HashCheckResult {
                            file: remote_path.to_string(),
                            remote_hash: Err(e.into()),
                            expected_hash: expected_hash.to_string(),
                            failed: true,
                        },
                    }
                })
                .collect::<Vec<_>>();

            let _ = ftp.quit();

            if hash_comparison_results.iter().any(|r| r.failed) {
                Ok(CheckResult::fail(
                    "One of the hashes provided did not match what was on the remote server",
                    serde_json::json!({
                        "hash_comparisons": hash_comparison_results.iter().map(serialize_hcr).collect::<serde_json::Value>(),
                    }),
                ))
            } else {
                Ok(CheckResult::succeed(
                    "FTP hash check succeeded",
                    serde_json::json!({
                        "hash_comparisons": hash_comparison_results.iter().map(serialize_hcr).collect::<serde_json::Value>(),
                    }),
                ))
            }
        };

        time::timeout(
            Duration::from_secs(timeout_seconds),
            tokio::task::spawn_blocking(task),
        )
        .await
        .unwrap_or_else(|e| {
            Ok(Ok(CheckResult::fail(
                format!("Failed to complete FTP check in allotted time"),
                serde_json::json!({
                    "timeout": self.timeout,
                    "elapsed_time": format!("{e}")
                }),
            )))
        })
        .unwrap_or_else(|e| {
            Ok(CheckResult::fail(
                format!("Internal error waiting for FTP check to complete"),
                serde_json::json!({
                    "error": format!("{e}")
                }),
            ))
        })
    }

    async fn try_write_internal(
        &self,
        host: Ipv4Addr,
        port: u16,
        user: &str,
        password: &str,
        write_path: String,
    ) -> eyre::Result<CheckResult> {
        use ::ftp::FtpStream;
        use tokio::time::{self, Duration};

        let user = user.to_string();
        let password = password.to_string();
        let timeout_seconds = self.timeout;

        let task = move || -> eyre::Result<CheckResult> {
            let mut ftp = match FtpStream::connect((host, port)) {
                Ok(ftp) => ftp,
                Err(e) => {
                    return Ok(CheckResult::fail(
                        "Could not establish connection to FTP server",
                        serde_json::json!({
                            "error": format!("{e}")
                        }),
                    ));
                }
            };

            if let Err(e) = ftp.login(&user, &password) {
                let _ = ftp.quit();
                return Ok(CheckResult::fail(
                    "Could not login to the FTP server",
                    serde_json::json!({
                        "error": format!("{e}")
                    }),
                ));
            };

            use std::io::Cursor;

            let test_filename = format!(
                "jj_write_test_{}.tmp",
                Utc::now().timestamp_nanos_opt().unwrap_or_default()
            );
            let test_contents = format!("jj FTP write test {}", Utc::now());

            if let Err(e) = ftp.put(
                &format!("{write_path}/{test_filename}"),
                &mut Cursor::new(test_contents.as_bytes()),
            ) {
                let _ = ftp.quit();
                return Ok(CheckResult::fail(
                    "Could not write file to server",
                    serde_json::json!({
                        "error": format!("{e}")
                    }),
                ));
            }

            let files = match ftp.nlst(Some(&write_path)) {
                Err(e) => {
                    let _ = ftp.quit();
                    return Ok(CheckResult::fail(
                        "Could not list files to verify file was written to server",
                        serde_json::json!({
                            "error": format!("{e}")
                        }),
                    ));
                }
                Ok(f) => f,
            };

            if !files.iter().any(|f| *f == test_filename) {
                let _ = ftp.quit();

                return Ok(CheckResult::fail(
                    "Could not find file on remote server",
                    serde_json::json!({
                        "file_listing": files.into_iter().map(serde_json::Value::String).collect::<serde_json::Value>()
                    }),
                ));
            }

            let file_content = match ftp.simple_retr(&format!("{write_path}/{test_filename}")) {
                Err(e) => {
                    let _ = ftp.quit();
                    return Ok(CheckResult::fail(
                        "Could not download uploaded file to verify file was accurately written to server",
                        serde_json::json!({
                            "error": format!("{e}")
                        }),
                    ));
                }
                Ok(f) => f,
            };

            let _ = ftp.rm(&format!("{write_path}/{test_filename}"));
            let _ = ftp.quit();

            if *file_content.get_ref() == test_contents.as_bytes() {
                Ok(CheckResult::succeed(
                    "Successfully verified FTP file can be uploaded and downloaded",
                    serde_json::json!({}),
                ))
            } else {
                Ok(CheckResult::fail(
                    "FTP write test failed",
                    serde_json::json!({
                        "expected": test_contents,
                        "found": String::from_utf8_lossy(&*file_content.get_ref())
                    }),
                ))
            }
        };

        time::timeout(
            Duration::from_secs(timeout_seconds),
            tokio::task::spawn_blocking(task),
        )
        .await
        .unwrap_or_else(|e| {
            Ok(Ok(CheckResult::fail(
                format!("Failed to complete FTP check in allotted time"),
                serde_json::json!({
                    "timeout": self.timeout,
                    "elapsed_time": format!("{e}")
                }),
            )))
        })
        .unwrap_or_else(|e| {
            Ok(CheckResult::fail(
                format!("Internal error waiting for FTP check to complete"),
                serde_json::json!({
                    "error": format!("{e}")
                }),
            ))
        })
    }
}
