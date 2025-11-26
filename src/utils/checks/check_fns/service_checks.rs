use eyre::Context;

use crate::utils::{
    checks::{CheckResult, CheckStep, TroubleshooterRunner},
    qx,
    systemd::{get_service_info, is_service_active},
};

struct SystemdServiceCheck {
    service_name: String,
}

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

        let service_info = get_service_info(&self.service_name)
            .context("Could not pull systemd service information")?;

        if is_service_active(&service_info) {
            Ok(CheckResult::succeed(
                "systemd service is active",
                serde_json::json!({
                   "main_pid": service_info.get("MainPID"),
                   "running_since": service_info.get("ExecMainStartTimestamp")
                }),
            ))
        } else {
            Ok(CheckResult::fail(
                "systemd service is not active",
                serde_json::json!({
                   "stopped_since": service_info.get("InactiveEnterTimestamp")
                }),
            ))
        }
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
pub fn systemd_service_check<'a, I: Into<String>>(name: I) -> Box<dyn CheckStep<'a> + 'a> {
    Box::new(SystemdServiceCheck {
        service_name: name.into(),
    })
}

struct OpenrcServiceCheck {
    service_name: String,
}

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

        let res = qx(&format!("rc-service {} status", &self.service_name))
            .context("Could not pull openrc service information")?
            .1;

        if res.contains("status: started") {
            Ok(CheckResult::succeed(
                "OpenRC service is active",
                serde_json::json!(null),
            ))
        } else {
            Ok(CheckResult::fail(
                "OpenRC service is not active",
                serde_json::json!(null),
            ))
        }
    }
}

/// A simple check that makes sure an `OpenRC` service is up
///
/// ```
/// # use jj_rs::utils::checks::openrc_service_check;
/// openrc_service_check("ssh");
/// ```
pub fn openrc_service_check<'a, I: Into<String>>(name: I) -> Box<dyn CheckStep<'a> + 'a> {
    Box::new(OpenrcServiceCheck {
        service_name: name.into(),
    })
}
