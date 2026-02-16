use std::{net::Ipv4Addr, path::PathBuf};

use chrono::{DateTime, NaiveDateTime, Utc};
use sha2::{Digest, Sha256};

use super::*;

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct CliHeader {
    name: String,
    value: String,
}

impl std::str::FromStr for CliHeader {
    type Err = eyre::Report;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let Some((first, last)) = s.split_once('=') else {
            eyre::bail!("Could not split key value pair on `=`");
        };

        Ok(CliHeader {
            name: first.to_string(),
            value: last.to_string(),
        })
    }
}

#[derive(clap::Parser, serde::Serialize, serde::Deserialize, Debug, Clone)]
#[serde(default)]
pub struct HttpTroubleshooter {
    /// The address of the web server in question
    #[arg(long, short = 'H', default_value = "127.0.0.1")]
    pub host: Ipv4Addr,

    /// The port of the HTTP server
    #[arg(long, short, default_value_t = 80)]
    pub port: u16,

    /// A reference file that shows what is "good". If not provided, this check will check the status code
    #[arg(long, group = "content-check")]
    pub reference_file: Option<PathBuf>,

    /// How many differences are allowed between the reference file and the response from the HTTP server. Defaults to 0, or an exact match
    #[arg(long)]
    pub reference_difference_count: Option<u32>,

    /// Content to check against the HTTP response, an alternative to reference-file. If not provided, this check will check the status code
    #[arg(long, group = "content-check")]
    pub reference_content: Option<String>,

    /// Content to search for *in* the HTTP response, not in totality. If not provided, this check will check the status code
    #[arg(long, group = "content-check")]
    pub content: Option<String>,

    /// A SHA256 hash of the HTTP response. If not provided, this check will check the status code
    #[arg(long, group = "content-check")]
    pub content_hash: Option<String>,

    /// Error text that indicates the server is not appropriately responding (e.g., "error"). Ignored if checking for a SHA256 hash
    #[arg(long)]
    pub negative_content_checks: Vec<String>,

    /// Use case insensitive search for negative content checks
    #[arg(long, requires = "negative_content_checks")]
    pub ignore_case_negative_checks: bool,

    /// Extra headers, in the form of `key=value`
    #[arg(long, short = 'E')]
    pub headers: Vec<CliHeader>,

    /// Status code to check for
    #[arg(long, short = 's', default_value_t = 200)]
    pub valid_status: u16,

    /// URI on the web server to check
    #[arg(long, short = 'u', default_value = "/")]
    pub uri: String,

    /// If the remote host is specified, indicate that the traffic sent to the remote host will be sent
    /// back to this server via NAT reflection (e.g., debug firewall on another machine, network firewall
    /// WAN IP for this machine)
    #[arg(long, short)]
    pub local: bool,

    /// Listen for an external connection attempt, and diagnose what appears to
    /// be going wrong with such a check. All other steps attempt to initiate connections
    #[arg(long, short)]
    pub external: bool,

    /// Specify systemd/openrc/sc services to query
    #[cfg_attr(unix, arg(long, short, default_values_t = crate::strvec!["nginx", "php-fpm", "apache2", "httpd"]))]
    #[cfg_attr(windows, arg(long, short, default_values_t = crate::strvec!["IIS"]))]
    pub services: Vec<String>,

    /// Disable the download shell used to test the HTTP and TCP connections
    #[arg(long, short)]
    pub disable_download_shell: bool,

    /// Specify an IP address to use the download container with
    #[arg(long, short = 'I')]
    pub sneaky_ip: Option<Ipv4Addr>,
}

impl Default for HttpTroubleshooter {
    fn default() -> Self {
        HttpTroubleshooter {
            host: Ipv4Addr::from(0x7F_00_00_01),
            port: 80,
            reference_file: None,
            reference_difference_count: None,
            reference_content: None,
            content: None,
            content_hash: None,
            negative_content_checks: vec![],
            ignore_case_negative_checks: false,
            headers: vec![],
            valid_status: 200,
            uri: "/".to_string(),
            local: false,
            external: false,
            services: if cfg!(unix) {
                crate::strvec!["nginx", "php-fpm", "apache2", "httpd"]
            } else {
                crate::strvec!["IIS"]
            },
            disable_download_shell: false,
            sneaky_ip: None,
        }
    }
}

impl Troubleshooter for HttpTroubleshooter {
    fn display_name(&self) -> &'static str {
        "HTTP"
    }

    fn checks<'a>(&'a self) -> eyre::Result<Vec<Box<dyn super::CheckStep<'a> + 'a>>> {
        Ok(vec![
            #[cfg(unix)]
            filter_check(
                systemd_services_check(self.services.clone()),
                self.host.is_loopback() || self.local,
                "Cannot check systemd service on remote host",
            ),
            #[cfg(unix)]
            filter_check(
                openrc_services_check(self.services.clone()),
                self.host.is_loopback() || self.local,
                "Cannot check openrc service on remote host",
            ),
            tcp_connect_check(
                self.host,
                self.port,
                self.disable_download_shell,
                self.sneaky_ip,
            ),
            binary_ports_check(
                // None for Linux, because do we also want to check things like gitea and splunk?
                // None for Windows because Windows binds using its kernel, with PID 4... it doesn't show up normally
                None::<&[&str]>,
                self.port,
                CheckIpProtocol::Tcp,
                self.host.is_loopback() || self.local,
            ),
            #[cfg(unix)]
            immediate_tcpdump_check(
                self.port,
                CheckIpProtocol::Tcp,
                b"openssh".to_vec(),
                self.host.is_loopback() || self.local,
            ),
            check_fn("Try downloading web page", |tr| {
                Ok(self.download_webpage(tr))
            }),
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

impl HttpTroubleshooter {
    fn download_webpage(&self, _tr: &mut dyn TroubleshooterRunner) -> CheckResult {
        let (check_result, start) = crate::utils::checks::optionally_run_in_container(
            self.host.is_loopback() || self.local,
            self.disable_download_shell,
            self.sneaky_ip,
            || self.try_connection(),
        );

        let end = Utc::now();

        let system_logs =
            (self.local || self.host.is_loopback()).then(|| get_system_logs(start, end));
        let webserver_logs = (self.local || self.host.is_loopback()).then(|| {
            let mut logs = get_webserver_logs(start, end);
            logs.sort_by_key(|log| log.0);
            logs.into_iter()
                .map(|(time, log)| format!("{time} {log}"))
                .collect::<Vec<_>>()
        });

        check_result
            .into_check_result("Could not attempt connection to the server")
            .merge_overwrite_details(serde_json::json!({
                "system_logs": system_logs,
                "webserver_logs": webserver_logs
            }))
    }

    fn try_connection(&self) -> eyre::Result<CheckResult> {
        let reference_file = &self
            .reference_file
            .as_ref()
            .and_then(|path| std::fs::read(path).ok())
            .and_then(|bytes| String::from_utf8(bytes).ok());

        let client = reqwest::blocking::Client::new();
        let request = client.get(format!(
            "http://{}:{}{}{}",
            self.host,
            self.port,
            if self.uri.starts_with('/') { "" } else { "/" },
            self.uri
        ));

        let response = request.send()?;

        if response.status().as_u16() != self.valid_status {
            return Ok(CheckResult::fail(
                "Server responded with invalid status code",
                serde_json::json!({
                    "status_code": response.status().as_u16()
                }),
            ));
        }

        macro_rules! check_negative_content {
            ($self:ident, $status:ident, $response_text:ident) => {
                for negative_check in &$self.negative_content_checks {
                    let (rt, nc) = if $self.ignore_case_negative_checks {
                        ($response_text.to_lowercase(), negative_check.to_lowercase())
                    } else {
                        ($response_text.clone(), negative_check.clone())
                    };

                    if rt.contains(&*nc) {
                        return Ok(CheckResult::fail(
                            "Server responded with an error trigger word",
                            serde_json::json!({
                                "status_code": $status,
                                "error_trigger": negative_check
                            })
                        ));
                    }
                }
            }
        }

        if let Some(file_content) = reference_file.as_ref().or(self.reference_content.as_ref()) {
            use imara_diff::{Algorithm, Diff, InternedInput};

            let status = response.status().as_u16();
            let response_text = response.text()?;
            check_negative_content!(self, status, response_text);

            let input = InternedInput::new(&**file_content, &*response_text);
            let difference_count = self.reference_difference_count.unwrap_or(0);
            let mut diff = Diff::compute(Algorithm::Histogram, &input);
            diff.postprocess_lines(&input);

            let file_content_lines = file_content.split('\n').collect::<Vec<_>>();
            let response_text_lines = response_text.split('\n').collect::<Vec<_>>();

            let hunks = diff
                .hunks()
                .map(|hunk| {
                    serde_json::json!({
                        "response": serde_json::json!({
                            "line_range": [hunk.after.start, hunk.after.end],
                            "lines": response_text_lines[hunk.after.start as usize..hunk.after.end as usize].to_vec()
                        }),
                        "reference": serde_json::json!({
                            "line_range": [hunk.before.start, hunk.before.end],
                            "lines": file_content_lines[hunk.before.start as usize..hunk.before.end as usize].to_vec()
                        }),
                    })
                })
                .collect::<Vec<_>>();

            let lines_changed: u32 = diff
                .hunks()
                .map(|hunk| {
                    (hunk.before.end - hunk.before.start) + (hunk.after.end - hunk.after.start)
                })
                .sum();

            if lines_changed as usize <= difference_count as usize {
                Ok(CheckResult::succeed(
                    "Response text is similar enough to reference",
                    serde_json::json!({
                        "status_code": status,
                        "measured_difference_count": lines_changed,
                        "difference_count": difference_count,
                        "differences": hunks,
                    }),
                ))
            } else {
                Ok(CheckResult::fail(
                    "Response text has too many differences from reference",
                    serde_json::json!({
                        "status_code": status,
                        "differences": hunks,
                    }),
                ))
            }
        } else if let Some(text_content) = &self.content {
            let status = response.status().as_u16();
            let response_text = response.text()?;
            check_negative_content!(self, status, response_text);

            if response_text.contains(text_content) {
                Ok(CheckResult::succeed(
                    "Response text contains check text",
                    serde_json::json!({
                        "status_code": status
                    }),
                ))
            } else {
                Ok(CheckResult::fail(
                    "Response text does not contain text",
                    serde_json::json!({
                        "status_code": status
                    }),
                ))
            }
        } else if let Some(content_hash) = &self.content_hash {
            let status = response.status().as_u16();
            let response_bytes = response.bytes()?;
            let mut hasher = Sha256::new();
            hasher.update(response_bytes);
            let response_hash = format!("{:x}", hasher.finalize());

            if *content_hash == response_hash {
                Ok(CheckResult::succeed(
                    "Response hash matches expected hash",
                    serde_json::json!({
                        "status_code": status,
                        "hash": response_hash
                    }),
                ))
            } else {
                Ok(CheckResult::succeed(
                    "Response hash matches expected hash",
                    serde_json::json!({
                        "status_code": status,
                        "response_hash": response_hash,
                        "check_hash": content_hash
                    }),
                ))
            }
        } else {
            Ok(CheckResult::succeed(
                "Server responded with valid status code",
                serde_json::json!({
                    "status_code": response.status().as_u16()
                }),
            ))
        }
    }
}

#[cfg(windows)]
fn get_webserver_logs(start: DateTime<Utc>, end: DateTime<Utc>) -> Vec<(DateTime<Utc>, String)> {
    // IIS doesn't dump longs immediately, but batches them instead
    let _ = crate::utils::system("netsh http flush logbuffer");
    std::thread::sleep(std::time::Duration::from_secs(1));

    walkdir::WalkDir::new(r"C:\inetpub\logs")
        .into_iter()
        .filter_map(|entry| entry.ok())
        .filter_map(|entry| std::fs::read(entry.path()).ok())
        .filter_map(|entry| String::from_utf8(entry).ok())
        .flat_map(|logs| {
            ReverseIterator(logs.split('\n'))
                .filter(|line| !line.starts_with("#"))
                .filter_map(|line| {
                    let (datetime, line) =
                        NaiveDateTime::parse_and_remainder(line, "%Y-%m-%d %H:%M:%S").ok()?;

                    Some((datetime.and_utc(), line.to_string()))
                })
                .filter(|(t, _)| *t <= end)
                .take_while(|(t, _)| *t >= start)
                .collect::<Vec<_>>()
        })
        .collect()
}

#[cfg(unix)]
fn get_webserver_logs(start: DateTime<Utc>, end: DateTime<Utc>) -> Vec<(DateTime<Utc>, String)> {
    [
        get_php_fpm_logs(start, end),
        get_apache_error_logs(start, end),
        get_apache_access_logs(start, end),
        get_nginx_access_logs(start, end),
        get_nginx_error_logs(start, end),
    ]
    .concat()
}

#[cfg(unix)]
fn get_php_fpm_logs(start: DateTime<Utc>, end: DateTime<Utc>) -> Vec<(DateTime<Utc>, String)> {
    let Ok(log_files) = std::fs::read_dir("/var/log/php-fpm") else {
        return vec![];
    };

    log_files
        .into_iter()
        .filter_map(Result::ok)
        .map(|log_file| log_file.path())
        .filter(|p| p.extension() == Some(std::ffi::OsString::from("log")).as_deref())
        .filter_map(|log_file| {
            let mut path = PathBuf::from("/var/log/php-fpm");
            path.push(log_file);
            std::fs::read(path).ok()
        })
        .filter_map(|log_contents| String::from_utf8(log_contents).ok())
        .flat_map(|log_contents| {
            MultiLineReverseIterator::new(log_contents.split('\n'), |l: &str| !l.starts_with('['))
                .flat_map(|log_contents| {
                    use chrono::Local;

                    // php-fpm logs sometimes specify time zone, sometimes are just in local time
                    NaiveDateTime::parse_and_remainder(&log_contents, "[%d-%b-%Y %H:%M:%S UTC] ")
                        .ok()
                        .map(|(t, l)| (t.and_utc(), l))
                        .or_else(|| {
                            NaiveDateTime::parse_and_remainder(
                                &log_contents,
                                "[%d-%b-%Y %H:%M:%S] ",
                            )
                            .ok()
                            .and_then(|(t, l)| {
                                t.and_local_timezone(Local)
                                    .single()
                                    .map(|t| (t.to_utc(), l))
                            })
                        })
                        .map(|(t, l)| (t, format!("[php-fpm] {l}")))
                })
                .filter(|(t, _)| *t <= end)
                .take_while(|(t, _)| *t >= start)
                .collect::<Vec<_>>()
        })
        .collect()
}

#[cfg(unix)]
fn get_apache_error_logs(start: DateTime<Utc>, end: DateTime<Utc>) -> Vec<(DateTime<Utc>, String)> {
    let httpd_logs =
        std::fs::read_dir("/var/log/httpd").map(|p| (p, PathBuf::from("/var/log/httpd")));
    let apache_logs =
        std::fs::read_dir("/var/log/apache2").map(|p| (p, PathBuf::from("/var/log/apache2")));

    let Ok((log_files, log_files_location)) = httpd_logs.or(apache_logs) else {
        return vec![];
    };

    log_files
        .into_iter()
        .filter_map(Result::ok)
        .map(|log_file| log_file.path())
        .filter(|p| {
            p.extension() == Some(std::ffi::OsString::from("log")).as_deref()
                && p.to_string_lossy().contains("error")
        })
        .filter_map(|log_file| {
            let mut path = log_files_location.clone();
            path.push(log_file);
            std::fs::read(path).ok()
        })
        .filter_map(|log_contents| String::from_utf8(log_contents).ok())
        .flat_map(|log_contents| {
            MultiLineReverseIterator::new(log_contents.split('\n'), |l: &str| !l.starts_with('['))
                .flat_map(|log_contents| {
                    use chrono::Local;

                    NaiveDateTime::parse_and_remainder(&log_contents, "[%a %h %d %H:%M:%S.%6f %Y] ")
                        .ok()
                        .and_then(|(t, l)| t.and_local_timezone(Local).single().map(|t| (t, l)))
                        .map(|(t, l)| (t.to_utc(), format!("[apache:error] {l}")))
                })
                .filter(|(t, _)| *t <= end)
                .take_while(|(t, _)| *t >= start)
                .collect::<Vec<_>>()
        })
        .collect()
}

#[cfg(unix)]
fn get_apache_access_logs(
    start: DateTime<Utc>,
    end: DateTime<Utc>,
) -> Vec<(DateTime<Utc>, String)> {
    let httpd_logs =
        std::fs::read_dir("/var/log/httpd").map(|p| (p, PathBuf::from("/var/log/httpd")));
    let apache_logs =
        std::fs::read_dir("/var/log/apache2").map(|p| (p, PathBuf::from("/var/log/apache2")));

    let Ok((log_files, log_files_location)) = httpd_logs.or(apache_logs) else {
        return vec![];
    };

    log_files
        .into_iter()
        .filter_map(Result::ok)
        .map(|log_file| log_file.path())
        .filter(|p| {
            p.extension() == Some(std::ffi::OsString::from("log")).as_deref()
                && p.to_string_lossy().contains("access")
        })
        .filter_map(|log_file| {
            let mut path = log_files_location.clone();
            path.push(log_file);
            std::fs::read(path).ok()
        })
        .filter_map(|log_contents| String::from_utf8(log_contents).ok())
        .flat_map(|log_contents| {
            ReverseIterator(log_contents.split('\n'))
                .flat_map(|log_contents| {
                    let [ip, _, _, rest] = log_contents.splitn(4, ' ').collect::<Vec<_>>()[..]
                    else {
                        return None;
                    };
                    DateTime::parse_and_remainder(&rest, "[%d/%b/%Y:%H:%M:%S %z] ")
                        .ok()
                        .map(|(t, l)| (t.to_utc(), l))
                        .map(|(t, l)| (t, format!("[apache:access] {ip} {l}")))
                })
                .filter(|(t, _)| *t <= end)
                .take_while(|(t, _)| *t >= start)
                .collect::<Vec<_>>()
        })
        .collect()
}

#[cfg(unix)]
fn get_nginx_access_logs(start: DateTime<Utc>, end: DateTime<Utc>) -> Vec<(DateTime<Utc>, String)> {
    let Ok(log_files) = std::fs::read_dir("/var/log/nginx") else {
        return vec![];
    };

    log_files
        .into_iter()
        .filter_map(Result::ok)
        .map(|log_file| log_file.path())
        .filter(|p| {
            p.extension() == Some(std::ffi::OsString::from("log")).as_deref()
                && p.to_string_lossy().contains("access")
        })
        .filter_map(|log_file| {
            let mut path = PathBuf::from("/var/log/nginx");
            path.push(log_file);
            std::fs::read(path).ok()
        })
        .filter_map(|log_contents| String::from_utf8(log_contents).ok())
        .flat_map(|log_contents| {
            ReverseIterator(log_contents.split('\n'))
                .flat_map(|log_contents| {
                    let [ip, _, _, rest] = log_contents.splitn(4, ' ').collect::<Vec<_>>()[..]
                    else {
                        return None;
                    };
                    DateTime::parse_and_remainder(&rest, "[%d/%b/%Y:%H:%M:%S %z] ")
                        .ok()
                        .map(|(t, l)| (t.to_utc(), format!("[nginx:access] {ip} {l}")))
                })
                .filter(|(t, _)| *t <= end)
                .take_while(|(t, _)| *t >= start)
                .collect::<Vec<_>>()
        })
        .collect()
}

#[cfg(unix)]
fn get_nginx_error_logs(start: DateTime<Utc>, end: DateTime<Utc>) -> Vec<(DateTime<Utc>, String)> {
    let Ok(log_files) = std::fs::read_dir("/var/log/nginx") else {
        return vec![];
    };

    log_files
        .into_iter()
        .filter_map(Result::ok)
        .map(|log_file| log_file.path())
        .filter(|p| {
            p.extension() == Some(std::ffi::OsString::from("log")).as_deref()
                && p.to_string_lossy().contains("error")
        })
        .filter_map(|log_file| {
            let mut path = PathBuf::from("/var/log/nginx");
            path.push(log_file);
            std::fs::read(path).ok()
        })
        .filter_map(|log_contents| String::from_utf8(log_contents).ok())
        .flat_map(|log_contents| {
            use chrono::Local;

            ReverseIterator(log_contents.split('\n'))
                .flat_map(|log_contents| {
                    NaiveDateTime::parse_and_remainder(&log_contents, "%Y/%b/%d %H:%M:%S ")
                        .ok()
                        .and_then(|(t, l)| t.and_local_timezone(Local).single().map(|t| (t, l)))
                        .map(|(t, l)| (t.to_utc(), format!("[nginx:error] {l}")))
                })
                .filter(|(t, _)| *t <= end)
                .take_while(|(t, _)| *t >= start)
                .collect::<Vec<_>>()
        })
        .collect()
}

struct ReverseIterator<T>(T);

impl<I, T> Iterator for ReverseIterator<T>
where
    T: DoubleEndedIterator + Iterator<Item = I>,
{
    type Item = I;

    fn next(&mut self) -> Option<Self::Item> {
        self.0.next_back()
    }
}

struct MultiLineReverseIterator<T, F> {
    inner: T,
    group_func: F,
}

impl<T, F> MultiLineReverseIterator<T, F> {
    fn new(inner: T, group_func: F) -> Self {
        MultiLineReverseIterator { inner, group_func }
    }
}

impl<'a, T, F> Iterator for MultiLineReverseIterator<T, F>
where
    T: DoubleEndedIterator<Item = &'a str>,
    F: FnMut(&str) -> bool,
{
    type Item = String;

    fn next(&mut self) -> Option<Self::Item> {
        let mut state = None;

        // Some(line), Some(state), group_func -> true
        // None,       Some(state), group_func -> true
        // Some(line), None,        group_func -> true
        // None,       None,        group_func -> true
        // Some(line), Some(state), group_func -> false
        // None,       Some(state), group_func -> false
        // Some(line), None,        group_func -> false
        // None,       None,        group_func -> false

        // when group_func returns true, that indicates a grouping of logs has been found
        while let Some(line) = self.inner.next_back() {
            match (&mut state, !(self.group_func)(line)) {
                (Some(s), true) => {
                    *s = format!("{line}\n{s}");
                    break;
                }
                (Some(s), false) => {
                    *s = format!("{line}\n{s}");
                }
                (None, true) => {
                    state = Some(line.to_string());
                    break;
                }
                (None, false) => {
                    state = Some(line.to_string());
                }
            }
        }

        state
    }
}
