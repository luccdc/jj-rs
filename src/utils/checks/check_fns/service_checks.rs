use std::convert::Into;

use crate::utils::{
    checks::{CheckResult, CheckResultType, CheckStep, TroubleshooterRunner},
    qx,
};

#[cfg(unix)]
use crate::utils::systemd::{get_service_info, is_service_active};

#[cfg(unix)]
use super::check_fn;

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

        if self.service_names.is_empty() {
            return Ok(CheckResult::not_run(
                format!("No services were provided to check for",),
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

/// A simple check that makes sure a vector of systemd services are up. Provides
/// an iterator of contexts when the server went up or down as well as the PID if it
/// is running
///
/// ```
/// # use jj_rs::utils::checks::systemd_services_check;
/// systemd_services_check([ "ssh" ]);
/// ```
#[allow(dead_code)]
#[cfg(unix)]
pub fn systemd_services_check<'a, S: Into<String>, I: IntoIterator<Item = S>>(
    names: I,
) -> Box<dyn CheckStep<'a> + 'a> {
    Box::new(SystemdServiceCheck {
        service_names: names.into_iter().map(Into::into).collect(),
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

        if self.service_names.is_empty() {
            return Ok(CheckResult::not_run(
                format!("No services were provided to check for"),
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

/// A simple check that makes sure a vector of `OpenRC` services are up
///
/// ```
/// # use jj_rs::utils::checks::openrc_services_check;
/// openrc_services_check(["ssh"]);
/// ```
#[allow(dead_code)]
#[cfg(unix)]
pub fn openrc_services_check<'a, S: Into<String>, I: IntoIterator<Item = S>>(
    names: I,
) -> Box<dyn CheckStep<'a> + 'a> {
    Box::new(OpenrcServiceCheck {
        service_names: names.into_iter().map(Into::into).collect(),
    })
}

#[cfg(windows)]
struct WindowsScServiceCheck {
    service_names: Vec<String>,
}

#[cfg(windows)]
impl CheckStep<'_> for WindowsScServiceCheck {
    fn name(&self) -> &'static str {
        "Check Windows services"
    }

    fn run_check(&self, _tr: &mut dyn TroubleshooterRunner) -> eyre::Result<CheckResult> {
        unsafe {
            use windows::Win32::{
                Foundation::ERROR_INSUFFICIENT_BUFFER,
                System::Services::{
                    OpenSCManagerW, OpenServiceW, QueryServiceStatusEx, SC_MANAGER_CONNECT,
                    SC_MANAGER_ENUMERATE_SERVICE, SC_STATUS_PROCESS_INFO, SERVICE_QUERY_STATUS,
                    SERVICE_STATUS_PROCESS,
                },
            };
            use windows_core::PCWSTR;

            if self.service_names.is_empty() {
                return Ok(CheckResult::not_run(
                    format!("No services were provided to check for"),
                    serde_json::json!(null),
                ));
            }

            let scm = OpenSCManagerW(
                PCWSTR::null(),
                PCWSTR::null(),
                SC_MANAGER_CONNECT | SC_MANAGER_ENUMERATE_SERVICE,
            )?;

            if scm.0.is_null() {
                return Ok(CheckResult::fail(
                    "Could not open connection to sc manager",
                    serde_json::json!({
                        "error": format!("{}", std::io::Error::last_os_error())
                    }),
                ));
            }

            for name in &self.service_names {
                let service_name = name.encode_utf16().chain(Some(0)).collect::<Vec<_>>();

                let mut initial_buffer = vec![0u8; 4096];
                let mut buffer_size = 0u32;

                if let Ok(svc) = OpenServiceW(
                    scm,
                    windows_core::PCWSTR(service_name.as_ptr()),
                    SERVICE_QUERY_STATUS,
                ) {
                    use windows::Win32::System::Services::SERVICE_RUNNING;

                    let status = QueryServiceStatusEx(
                        svc,
                        SC_STATUS_PROCESS_INFO,
                        Some(&mut initial_buffer),
                        &mut buffer_size as _,
                    );

                    if let Err(e) = &status
                        && e.code() == ERROR_INSUFFICIENT_BUFFER.into()
                    {
                        initial_buffer = vec![0u8; buffer_size as usize];
                        QueryServiceStatusEx(
                            svc,
                            SC_STATUS_PROCESS_INFO,
                            Some(&mut initial_buffer),
                            &mut buffer_size as _,
                        )?;
                    } else if status.is_err() {
                        status?;
                    }

                    let status_ptr = &*(initial_buffer.as_ptr() as *const SERVICE_STATUS_PROCESS);

                    if status_ptr.dwCurrentState == SERVICE_RUNNING {
                        return Ok(CheckResult::succeed(
                            format!("Service '{name}' is active"),
                            serde_json::json!({
                                "service": name,
                                "process_id": status_ptr.dwProcessId,
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
}

/// A simple check that makes sure an Windows service is up
///
/// ```
/// # use jj_rs::utils::checks::windows_scm_service_check;
/// windows_scm_service_check(["ssh"]);
/// ```
#[cfg(windows)]
pub fn windows_sc_services_check<'a, S: Into<String>, I: IntoIterator<Item = S>>(
    names: I,
) -> Box<dyn CheckStep<'a> + 'a> {
    Box::new(WindowsScServiceCheck {
        service_names: names.into_iter().map(Into::into).collect(),
    })
}

/// An abstract check to see if any of the specified services are running, abstracting
/// over the service manager (Windows SC, systemd, openrc)
///
/// ```
/// # use jj_rs::utils::checks::service_check;
/// service_check(
///     #[cfg(windows)] ["IIS"],
///     #[cfg(unix)] ["apache2", "nginx"],
/// );
/// ```
pub fn service_check<'a, S: Into<String>, I: IntoIterator<Item = S>>(
    names: I,
) -> Box<dyn CheckStep<'a> + 'a> {
    let service_names = names.into_iter().map(Into::into).collect::<Vec<_>>();
    #[cfg(windows)]
    return Box::new(WindowsScServiceCheck { service_names });

    #[cfg(unix)]
    return {
        let systemd_check = systemd_services_check(service_names.clone());
        let openrc_check = openrc_services_check(service_names);

        check_fn("Systemd and openrc service check", move |tr| {
            let systemd_result = systemd_check.run_check(tr);

            if let Ok(v) = &systemd_result
                && v.result_type != CheckResultType::NotRun
            {
                return systemd_result;
            }

            openrc_check.run_check(tr)
        })
    };
}
