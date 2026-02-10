use crate::utils::{
    checks::{CheckResult, CheckStep, TroubleshooterRunner},
    qx,
};

#[cfg(unix)]
use crate::utils::systemd::{get_service_info, is_service_active};

#[cfg(unix)]
struct SystemdServiceCheck {
    service_names: Vec<String>,
}

#[cfg(unix)]
impl CheckStep<'_> for SystemdServiceCheck {
    fn name(&self) -> &'static str {
        "Check systemd service"
    }

    fn run_check(&self, _tr: &mut dyn TroubleshooterRunner) -> eyre::Result<CheckResult> {
        if qx("which systemctl 2>/dev/null")?.1.trim().is_empty() {
            return Ok(CheckResult::not_run(
                "`systemctl` not found on host",
                serde_json::json!(null),
            ));
        }

        for name in &self.service_names {
            #[allow(clippy::collapsible_if)]
            if let Ok(service_info) = get_service_info(name) {
                if is_service_active(&service_info) {
                    return Ok(CheckResult::succeed(
                        format!("systemd service '{name}' is active"),
                        serde_json::json!({
                           "service": name,
                           "main_pid": service_info.get("MainPID"),
                           "running_since": service_info.get("ExecMainStartTimestamp")
                        }),
                    ));
                }

                if service_info
                    .get("ActiveState")
                    .is_some_and(|field| field == "failed")
                {
                    return Ok(CheckResult::succeed(
                        format!("systemd service '{name}' has died"),
                        serde_json::json!({
                           "service": name,
                           "main_pid": service_info.get("MainPID"),
                           "running_since": service_info.get("InactiveEnterTimestamp")
                        }),
                    ));
                }
            }
        }

        Ok(CheckResult::fail(
            format!(
                "Could not find any of the following services: {}",
                self.service_names.join(", ")
            ),
            serde_json::json!(null),
        ))
    }
}

/// A simple check that makes sure a systemd service is up. Provides
/// as context when the server went up or down as well as the PID if it
/// is running
///
/// ```
/// # use jj_rs::utils::checks::systemd_service_check;
/// systemd_service_check("ssh");
/// ```
#[cfg(unix)]
pub fn systemd_service_check<'a, I: Into<String>>(name: I) -> Box<dyn CheckStep<'a> + 'a> {
    Box::new(SystemdServiceCheck {
        service_names: vec![name.into()],
    })
}

#[cfg(unix)]
pub fn systemd_services_check<'a, S: Into<String>, I: IntoIterator<Item = S>>(
    names: I,
) -> Box<dyn CheckStep<'a> + 'a> {
    Box::new(SystemdServiceCheck {
        service_names: names.into_iter().map(std::convert::Into::into).collect(),
    })
}

#[cfg(unix)]
struct OpenrcServiceCheck {
    service_names: Vec<String>,
}

#[cfg(unix)]
impl CheckStep<'_> for OpenrcServiceCheck {
    fn name(&self) -> &'static str {
        "Check openrc service"
    }

    fn run_check(&self, _tr: &mut dyn TroubleshooterRunner) -> eyre::Result<CheckResult> {
        if qx("which rc-service 2>/dev/null")?.1.trim().is_empty() {
            return Ok(CheckResult::not_run(
                "`rc-service` not found on host",
                serde_json::json!(null),
            ));
        }

        for name in &self.service_names {
            // We ignore errors here because we want to check all services
            #[allow(clippy::collapsible_if)]
            if let Ok((_, res)) = qx(&format!("rc-service {name} status")) {
                if res.contains("status: started") {
                    return Ok(CheckResult::succeed(
                        format!("OpenRC service '{name}' is active"),
                        serde_json::json!({
                            "service": name,
                        }),
                    ));
                }
            }
        }

        Ok(CheckResult::fail(
            format!(
                "Could not find any of the following services: {}",
                self.service_names.join(", ")
            ),
            serde_json::json!(null),
        ))
    }
}

/// A simple check that makes sure an `OpenRC` service is up
///
/// ```
/// # use jj_rs::utils::checks::openrc_service_check;
/// openrc_service_check("ssh");
/// ```
#[cfg(unix)]
pub fn openrc_service_check<'a, I: Into<String>>(name: I) -> Box<dyn CheckStep<'a> + 'a> {
    Box::new(OpenrcServiceCheck {
        service_names: vec![name.into()],
    })
}

#[cfg(unix)]
pub fn openrc_services_check<'a, S: Into<String>, I: IntoIterator<Item = S>>(
    names: I,
) -> Box<dyn CheckStep<'a> + 'a> {
    Box::new(OpenrcServiceCheck {
        service_names: names.into_iter().map(std::convert::Into::into).collect(),
    })
}
