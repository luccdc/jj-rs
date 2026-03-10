use std::net::Ipv4Addr;

use chrono::Utc;

use crate::utils::clap::Host;

use super::*;

#[derive(clap::Parser, serde::Serialize, serde::Deserialize, Debug, Clone)]
#[serde(default)]
pub struct Pop3Troubleshooter {
    /// The host to connect to and attempt to signing in
    #[arg(long, short = 'H', default_value = "127.0.0.1")]
    pub host: Host,

    /// The port of the POP3 server
    #[arg(long, short, default_value_t = 110)]
    pub port: u16,

    /// The user to sign in as
    #[arg(long, short, default_value = "root")]
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

    /// Disable the download shell used to test the SMTP and TCP connections
    #[arg(long, short)]
    pub disable_download_shell: bool,

    /// Specify an IP address to use the download container with
    #[arg(long, short = 'I')]
    pub sneaky_ip: Option<Ipv4Addr>,
}

impl Default for Pop3Troubleshooter {
    fn default() -> Self {
        Pop3Troubleshooter {
            host: Host::from("127.0.0.1".to_string()),
            port: 110,
            user: "root".to_string(),
            password: CheckValue::stdin(),
            local: false,
            external: false,
            disable_download_shell: false,
            sneaky_ip: None,
        }
    }
}

impl Troubleshooter for Pop3Troubleshooter {
    fn display_name(&self) -> &'static str {
        "POP3"
    }

    fn checks<'a>(&'a self) -> eyre::Result<Vec<Box<dyn super::CheckStep<'a> + 'a>>> {
        Ok(vec![
            #[cfg(unix)]
            filter_check(
                systemd_services_check(["postfix", "sendmail"]),
                self.host.is_loopback() || self.local,
                "Cannot check systemd service on remote host",
            ),
            #[cfg(unix)]
            filter_check(
                openrc_services_check(["postfix"]),
                self.host.is_loopback() || self.local,
                "Cannot check openrc service on remote host",
            ),
            #[cfg(unix)]
            binary_ports_check(
                Some(["dovecot"]),
                self.port,
                CheckIpProtocol::Tcp,
                self.host.is_loopback() || self.local,
            ),
            tcp_connect_check_dns(
                self.host.clone(),
                self.port,
                self.disable_download_shell,
                self.sneaky_ip,
            )?,
            #[cfg(unix)]
            immediate_tcpdump_check(
                self.port,
                CheckIpProtocol::Tcp,
                b"".to_vec(), // Irrelevant for tcp.
                self.host.is_loopback() || self.local,
            ),
            check_fn("Try remote login", |tr| self.try_remote_login(tr)),
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

impl Pop3Troubleshooter {
    pub fn try_remote_login(&self, tr: &mut dyn TroubleshooterRunner) -> eyre::Result<CheckResult> {
        let host = &self.host;
        let port = self.port;
        let user = self.user.clone();
        let pass = self
            .password
            .clone()
            .resolve_prompt(tr, "POP3 Password: ")?;

        std::thread::sleep(std::time::Duration::from_secs(1));
        let start = Utc::now();

        let check_result = self
            .try_login_inner(&host.to_string(), port, &user, &pass)
            .into_check_result("Could not prepare arguments for CURL");

        let end = Utc::now();
        let logs = (self.local || host.is_loopback()).then(|| get_system_logs(start, end));

        Ok(check_result.merge_overwrite_details(serde_json::json!({
            "system_logs": logs,
        })))
    }

    fn try_login_inner(
        &self,
        host: &str,
        port: u16,
        user: &str,
        pass: &str,
    ) -> eyre::Result<CheckResult> {
        use std::ffi::{CStr, CString};

        use crate::utils::curl::ffi as curl_ffi;

        let res = unsafe {
            let curl = curl_ffi::curl_easy_init();

            if curl.is_null() {
                return Ok(CheckResult::fail(
                    "Failed to initialize CURL",
                    serde_json::json!({}),
                ));
            }

            let url = CString::new(format!("pop3://{host}:{port}/"))?;
            let username = CString::new(user)?;
            let password = CString::new(pass)?;

            curl_ffi::curl_easy_setopt(curl, curl_ffi::CURLoption_CURLOPT_URL, url.as_ptr());

            curl_ffi::curl_easy_setopt(
                curl,
                curl_ffi::CURLoption_CURLOPT_USERNAME,
                username.as_ptr(),
            );
            curl_ffi::curl_easy_setopt(
                curl,
                curl_ffi::CURLoption_CURLOPT_PASSWORD,
                password.as_ptr(),
            );

            let res = curl_ffi::curl_easy_perform(curl);
            curl_ffi::curl_easy_cleanup(curl);
            res
        };

        if res == curl_ffi::CURLcode_CURLE_OK {
            Ok(CheckResult::succeed(
                "Successfully authenticated to POP3 server",
                serde_json::json!({}),
            ))
        } else {
            let err: &'static _ = unsafe { CStr::from_ptr(curl_ffi::curl_easy_strerror(res)) };

            Ok(CheckResult::fail(
                "Failed to authenticate to POP3 server",
                serde_json::json!({
                    "error": err.to_string_lossy()
                }),
            ))
        }
    }
}
