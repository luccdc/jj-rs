use std::net::Ipv4Addr;
use eyre::Context;
use reqwest::blocking::Client;
use super::*;

#[derive(clap::Parser, serde::Serialize, serde::Deserialize, Debug, Clone)]
#[serde(default)]
pub struct WebTroubleshooter {
    #[arg(long, short = 'H', default_value = "127.0.0.1")]
    host: Ipv4Addr,

    #[arg(long, short, default_value_t = 80)]
    port: u16,

    #[arg(long, short = 'S')]
    secure: bool,

    #[arg(long, short, default_value = "nginx")]
    service: String,

    #[arg(long, short)]
    local: bool
}

impl Default for WebTroubleshooter {
    fn default() -> Self {
        Self {
            host: Ipv4Addr::new(127, 0, 0, 1),
            port: 80,
            secure: false,
            service: "nginx".to_string(),
            local: false
        }
    }
}

impl Troubleshooter for WebTroubleshooter {
    fn checks<'a>(&'a self) -> eyre::Result<Vec<Box<dyn super::CheckStep<'a> + 'a>>> {
        let is_local_target = self.host.is_loopback() || self.local;
        Ok(vec![
           filter_check(
               systemd_service_check(&self.service),
               is_local_target,
               "Skipping service check (not local)"
           ),
           filter_check(
               openrc_service_check(&self.service),
               is_local_target,
               "Skipping service check (not local)"
           ),
           filter_check(
               binary_ports_check(
                   [&self.service],
                   self.port,
                   CheckIpProtocol::Tcp,
                   true
               ),
               is_local_target,
               "Skipping local port ownership check"
           ),
           tcp_connect_check(self.host, self.port),
           check_fn("Verify HTTP Response", |tr| self.check_http_response(tr)),
        ])
    }
}

impl WebTroubleshooter {
    fn check_http_response(&self, _tr: &mut dyn TroubleshooterRunner) -> eyre::Result<CheckResult> {
        let protocol = if self.secure { "https" } else { "http" };
        let url = format!("{}://{}:{}/", protocol, self.host, self.port);

        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .context("Failed to build HTTP client")?;
        
        let response = client.get(&url).send();

        match response {
            Ok(resp) => {
                let status = resp.status();
                if status.is_success() {
                    Ok(CheckResult::succeed(
                            "Web server returned 2xx OK",
                            serde_json::json!({ "status_code": status.as_u16(), "url": url }),
                    ))
                } else{
                    Ok(CheckResult::fail(
                            format!("Web server returned error status: {}", status),
                            serde_json::json!({ "status_code": status.as_u16(), "url": url }),
                    ))
                }
            }
            Err(e) => {
                Ok(CheckResult::fail(
                        "Could not connect to web server",
                        serde_json::json!({ "error": e.to_string(), "url": url }),
                ))
            }
        }
    }
}
