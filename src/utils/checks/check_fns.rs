//! Not all checks have to be reimplemented from the ground up. This module
//! includes building blocks for applying simple checks or applying filters
//! to checks

use std::marker::PhantomData;

use crate::utils::{
    checks::{CheckResult, CheckStep, TroubleshooterRunner},
    distro::Distro,
    qx,
    systemd::{get_service_info, is_service_active},
};

#[doc(hidden)]
pub struct CheckFn<'a, F>
where
    F: Fn(&mut TroubleshooterRunner) -> anyhow::Result<CheckResult> + 'a,
{
    name: &'static str,
    check_fn: F,
    _lifetime: PhantomData<&'a F>,
}

impl<'a, F> CheckStep<'a> for CheckFn<'a, F>
where
    F: Fn(&mut TroubleshooterRunner) -> anyhow::Result<CheckResult> + 'a,
{
    fn name(&self) -> &'static str {
        self.name
    }

    fn run_check(&self, tr: &mut TroubleshooterRunner) -> anyhow::Result<CheckResult> {
        (self.check_fn)(tr)
    }
}

/// Convert a simple function to a troubleshooting check step
///
/// ```
/// # use jj_rs::utils::checks::{CheckResult, check_fn};
/// check_fn(
///     "Always return true",
///     |_| {
///         Ok(CheckResult::succeed(
///             "Check has returned true",
///             serde_json::json!(null)
///         ))
///     }
/// );
/// ```
pub fn check_fn<'a, F>(name: &'static str, f: F) -> Box<dyn CheckStep<'a> + 'a>
where
    F: Fn(&mut TroubleshooterRunner) -> anyhow::Result<CheckResult> + 'a,
{
    Box::new(CheckFn {
        name,
        check_fn: f,
        _lifetime: PhantomData,
    })
}

/// Control whether or not run the underlying check for [`filter_check`]
/// is run or not run with the provided error message
pub enum CheckFilterResult {
    Run,
    NoRun(String),
}

#[doc(hidden)]
pub struct CheckFilter<'a, F>
where
    F: Fn(Option<Distro>) -> anyhow::Result<CheckFilterResult> + 'a,
{
    check: Box<dyn CheckStep<'a> + 'a>,
    filter_func: F,
}

/// Allows applying a filter to a check, only running the underlying check
/// if the filter applied matches
///
/// The filter function takes as a parameter the current Linux distribution
///
/// ```
/// # use jj_rs::utils::checks::{CheckResult, CheckFilterResult, check_fn, filter_check};
/// filter_check(
///     check_fn(
///         "Always return true",
///         |_| {
///             Ok(CheckResult::succeed(
///                 "Check has returned true",
///                 serde_json::json!(null)
///             ))
///         }
///     ),
///     |distro| Ok(if distro.map(|d| d.is_deb_based()).unwrap_or(false) {
///         CheckFilterResult::Run
///     } else {
///         CheckFilterResult::NoRun("Test not designed for non-Debian systems".into())
///     })
/// );
/// ```
pub fn filter_check<'a, F>(
    check: Box<dyn CheckStep<'a> + 'a>,
    filter_func: F,
) -> Box<dyn CheckStep<'a> + 'a>
where
    F: Fn(Option<Distro>) -> anyhow::Result<CheckFilterResult> + 'a,
{
    Box::new(CheckFilter { check, filter_func })
}

impl<'a, F> CheckStep<'a> for CheckFilter<'a, F>
where
    F: Fn(Option<Distro>) -> anyhow::Result<CheckFilterResult> + 'a,
{
    fn name(&self) -> &'static str {
        self.check.name()
    }

    fn run_check(&self, tr: &mut TroubleshooterRunner) -> anyhow::Result<CheckResult> {
        let distro = crate::utils::distro::get_distro()?;
        match (self.filter_func)(distro)? {
            CheckFilterResult::Run => self.check.run_check(tr),
            CheckFilterResult::NoRun(v) => Ok(CheckResult::not_run(v, serde_json::json!(null))),
        }
    }
}

#[doc(hidden)]
pub struct SystemdServiceCheck {
    service_name: String,
}

impl<'a> CheckStep<'a> for SystemdServiceCheck {
    fn name(&self) -> &'static str {
        "Check systemd service"
    }

    fn run_check(&self, _tr: &mut TroubleshooterRunner) -> anyhow::Result<CheckResult> {
        if qx("which systemctl 2>/dev/null")?.1.trim().is_empty() {
            return Ok(CheckResult::not_run(
                "`systemctl` not found on host",
                serde_json::json!(null),
            ));
        }

        let service_info = get_service_info(&self.service_name)?;

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
