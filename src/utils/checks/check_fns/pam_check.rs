use std::{io::prelude::*, path::Path, process::Stdio};

use crate::utils::checks::{
    CheckResult, CheckStep, CheckValue, TroubleshooterRunner, get_system_logs,
};

struct PamCheck {
    service: Option<String>,
    username: String,
    password: CheckValue,
    run_local: bool,
}

impl CheckStep<'_> for PamCheck {
    fn name(&self) -> &'static str {
        "PAM check"
    }

    fn run_check(&self, tr: &mut dyn TroubleshooterRunner) -> anyhow::Result<CheckResult> {
        if !self.run_local {
            return Ok(CheckResult::not_run(
                "Cannot run check on remote systems",
                serde_json::json!(null),
            ));
        }

        if nix::unistd::geteuid() != 0.into() {
            return Ok(CheckResult::not_run(
                "Cannot run check as non root user",
                serde_json::json!(null),
            ));
        }

        let pamtester = crate::utils::pamtester::Pamtester::new()?;

        let mut cmd = pamtester.command();

        std::thread::sleep(std::time::Duration::from_secs(1));

        let start = chrono::Utc::now();

        if let Some(service) = &self.service {
            cmd.args(["-I", &format!("service={service}")]);
        }
        cmd.args([
            "-v",
            "login",
            &*self.username,
            "authenticate",
            "open_session",
            "close_session",
        ]);
        let (mut reader, writer) = std::io::pipe()?;
        cmd.stdin(Stdio::piped());
        cmd.stdout(writer.try_clone()?);
        cmd.stderr(writer);

        let mut proc = cmd.spawn()?;

        let password = self.password.resolve_prompt(
            tr,
            format!("What is the password for the {} user: ", &self.username),
        )?;

        if let Some(stdin) = &mut proc.stdin {
            writeln!(stdin, "{password}")?;
        }

        // Read the example code for pipe:
        // https://doc.rust-lang.org/stable/std/io/fn.pipe.html
        drop(cmd);
        let mut stdout = String::new();
        reader.read_to_string(&mut stdout)?;
        let success = proc.wait()?.success();

        let end = chrono::Utc::now();

        let logs = get_system_logs(start, end);

        let service_config = self.get_service_config();

        if success {
            Ok(CheckResult::succeed(
                "Successfully signed in as user",
                serde_json::json!({
                    "pam_test_output": stdout.split("\n").collect::<serde_json::Value>(),
                    "system_logs": logs,
                    "service_config": service_config
                }),
            ))
        } else {
            Ok(CheckResult::fail(
                "Failed to sign in as user",
                serde_json::json!({
                    "pam_test_output": stdout.split("\n").collect::<serde_json::Value>(),
                    "system_logs": logs,
                    "service_config": service_config
                }),
            ))
        }
    }
}

impl PamCheck {
    fn get_service_config(&self) -> serde_json::Value {
        let Some(svc) = self.service.as_ref() else {
            return serde_json::json!(null);
        };

        match self.get_service_config_internal(svc) {
            Ok(v) => v,
            Err(e) => serde_json::json!(format!(
                "Could not read PAM configuration for service: {e:?}"
            )),
        }
    }

    fn get_service_config_internal(&self, service: &str) -> anyhow::Result<serde_json::Value> {
        let pam_raw = self.read_pam_file(format!("/etc/pam.d/{service}"))?;

        let auth = pam_raw.iter().filter_map(|l| {
            l.strip_prefix("auth")
                .or_else(|| l.strip_prefix("-auth"))
                .map(|l2| l2.trim_start())
        });
        let password = pam_raw.iter().filter_map(|l| {
            l.strip_prefix("password")
                .or_else(|| l.strip_prefix("-password"))
                .map(|l2| l2.trim_start())
        });
        let account = pam_raw.iter().filter_map(|l| {
            l.strip_prefix("account")
                .or_else(|| l.strip_prefix("-account"))
                .map(|l2| l2.trim_start())
        });
        let session = pam_raw.iter().filter_map(|l| {
            l.strip_prefix("session")
                .or_else(|| l.strip_prefix("-session"))
                .map(|l2| l2.trim_start())
        });

        Ok(serde_json::json!({
            "auth": auth.collect::<serde_json::Value>(),
            "password": password.collect::<serde_json::Value>(),
            "account": account.collect::<serde_json::Value>(),
            "session": session.collect::<serde_json::Value>(),
        }))
    }

    fn read_pam_file<P: AsRef<Path>>(&self, file: P) -> anyhow::Result<Vec<String>> {
        Ok(std::fs::read_to_string(file)?
            .split("\n")
            .flat_map(|line| match line.strip_prefix("@include") {
                Some(p) => {
                    let p = p.trim_start();
                    [
                        vec![line.to_string()],
                        self.read_pam_file(format!("/etc/pam.d/{p}"))
                            .unwrap_or(vec![]),
                    ]
                    .concat()
                }
                None => {
                    let type_stripped = line
                        .strip_prefix("auth")
                        .or_else(|| line.strip_prefix("account"))
                        .or_else(|| line.strip_prefix("password"))
                        .or_else(|| line.strip_prefix("session"))
                        .or_else(|| line.strip_prefix("-account"))
                        .or_else(|| line.strip_prefix("-account"))
                        .or_else(|| line.strip_prefix("-password"))
                        .or_else(|| line.strip_prefix("-session"))
                        .map(|l| l.trim_start());

                    let Some(next) = type_stripped else {
                        return vec![line.to_string()];
                    };

                    let Some(prefix) = line.split_whitespace().next() else {
                        return vec![line.to_string()];
                    };
                    let prefix = prefix.trim_matches('-');

                    if let Some(fp) = next
                        .strip_prefix("include")
                        .or_else(|| next.strip_prefix("substack"))
                    {
                        let fp = fp.trim_start().trim_end();
                        vec![line.to_string()]
                            .into_iter()
                            .chain(
                                self.read_pam_file(format!("/etc/pam.d/{fp}"))
                                    .unwrap_or(vec![])
                                    .into_iter()
                                    .filter(|line| {
                                        line.starts_with(prefix)
                                            || line.starts_with(&format!("-{prefix}"))
                                    }),
                            )
                            .collect()
                    } else {
                        vec![line.to_string()]
                    }
                }
            })
            .collect())
    }
}

/// Try and sign in as the specified user, potentially to a specific service
///
/// Example:
/// ```
/// # use jj_rs::utils::checks::{CheckValue, pam_check};
/// pam_check(
///     Some("sshd"),
///     "root",
///     CheckValue::stdin(),
///     true
/// );
/// ```
pub fn pam_check<'a, A: AsRef<str>, B: AsRef<str>>(
    service: Option<A>,
    username: B,
    password: CheckValue,
    run_local: bool,
) -> Box<dyn CheckStep<'a> + 'a> {
    Box::new(PamCheck {
        service: service.map(|s| s.as_ref().to_string()),
        username: username.as_ref().to_string(),
        password,
        run_local,
    })
}
