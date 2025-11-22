//! Checks are used to assist with debugging a service, and for identifying
//! when the scored services goes down hopefully before it gets scored as going down
//!
//! The basic idea surrounds a Troubleshooter and its Checks. A Troubleshooter will
//! require configuration to make, so it is defined as a struct with the required
//! configuration options. This will usually derive both [`serde::Deserialize`] and
//! [`clap::Parser`] so that it can be used by the `jj-rs check` command as well as
//! the the daemon reading from a configuration file. As an example, here is a
//! configuration for an SSH troubleshooter
//!
//! ```
//! # use jj_rs::utils::checks::CheckValue;
//! #[derive(clap::Parser, serde::Deserialize, serde::Serialize, Default)]
//! #[serde(default)]
//! pub struct SshTroubleshooter {
//!     #[arg(long, short, default_value_t = Default::default())]
//!     password: CheckValue
//! }
//! ```
//!
//! This SshTroubleshooter can then implement [`Troubleshooter`], which requires
//! implementing a function that returns a list of checks. For simple checks,
//! use [`check_fn`] like below:
//!
//! ```
//! # use jj_rs::utils::checks::{CheckValue, Troubleshooter, check_fn, CheckStep, CheckResult, TroubleshooterRunner};
//! # use clap::Parser;
//! # use serde::Deserialize;
//! # #[derive(clap::Parser, serde::Deserialize, serde::Serialize, Default)]
//! # #[serde(default)]
//! # pub struct SshTroubleshooter {
//! #     #[arg(long, short, default_value_t = Default::default())]
//! #     password: CheckValue
//! # }
//! use serde_json::json;
//!
//! fn check_service_is_up() -> anyhow::Result<()> { unimplemented!() }
//! fn check_login(password: String) -> anyhow::Result<()> { unimplemented!() }
//!
//! impl Troubleshooter for SshTroubleshooter {
//!     fn checks<'a>(&'a self) -> anyhow::Result<Vec<Box<dyn CheckStep<'a> + 'a>>> {
//!         Ok(vec![
//!             check_fn("Check systemd service", |_| {
//!                 match check_service_is_up() {
//!                     Ok(_) => Ok(CheckResult::succeed(
//!                         "systemd service is active",
//!                         json!(null)
//!                     )),
//!                     Err(e) => Ok(CheckResult::fail(
//!                         format!("systemd service is not active: {e}"),
//!                         json!(null)
//!                     ))
//!                 }
//!             }),
//!             check_fn("Check login", |tr| {
//!                 let pass = self
//!                     .password
//!                     .clone()
//!                     .resolve_prompt(tr, "Enter password to sign into SSH with: ")?;
//!
//!                 match check_login(pass) {
//!                     Ok(_) => Ok(CheckResult::succeed(
//!                         "login succeeded",
//!                         json!(null)
//!                     )),
//!                     Err(e) => Ok(CheckResult::fail(
//!                         format!("login failed: {e}"),
//!                         json!(null)
//!                     ))
//!                 }
//!             })
//!         ])
//!     }
//! }
//! ```
//!
//! See [`check_fns`] for more check utility functions

use std::{
    fmt,
    io::{BufRead, Write},
    ops::BitAndAssign,
    path::PathBuf,
    str::FromStr,
    sync::{Arc, Mutex},
};

use chrono::prelude::*;
use colored::Colorize;
use serde::{Deserialize, Serialize, de::Visitor};

pub mod check_fns;
pub use check_fns::*;

use super::qx;

/// Represents a value that can be used as a richer parameter type
/// than just String for checks. This struct provides the
/// [`CheckValue::resolve_value`] and [`CheckValue::resolve_prompt`]
/// functions, which when called allows for collapsing this to a String.
/// It allows the operator to specify `:STDIN:`, `:FILE:/path`, or any other
/// value and resolve it by either prompting the operator, reading
/// a file path, or using the value as it is provided
///
/// It can be used directly as a part of a Troubleshooter as an option, e.g.:
///
/// ```no_run
/// # use jj_rs::utils::checks::CheckValue;
/// use clap::Parser;
/// use serde::Deserialize;
/// #[derive(Parser, Deserialize, Debug)]
/// pub struct SshTroubleshooter {
///     #[arg(short, long)]
///     password: CheckValue
/// }
/// ```
///
/// This will allow specifying a value in a config file, such as the following:
///
/// ```toml
/// [tarpit.ssh]
/// password = ":STDIN:"
/// ```
///
/// Or as an argument to a check:
///
/// ```bash
/// jj-rs check ssh -p :FILE:/var/password
/// ```
///
/// Then, in source code you can use the following:
///
/// ```no_run
/// # use jj_rs::utils::checks::{CheckValue, TroubleshooterRunner};
/// # struct SshTs { password: CheckValue }
/// # impl SshTs { fn dummy_check(&self, tr: &mut TroubleshooterRunner) -> anyhow::Result<()> {
/// let pass = self.password
///     .clone()
///     .resolve_prompt(tr, "Enter a password to sign into the SSH server with: ")?;
/// # Ok(())
/// # } }
/// ```
#[derive(Debug, Clone)]
pub struct CheckValue {
    original: CheckValueInternal,
    internal: Arc<Mutex<CheckValueInternal>>,
}

impl fmt::Display for CheckValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.original {
            CheckValueInternal::File(p) => {
                write!(f, ":FILE:{}", p.display())
            }
            CheckValueInternal::Stdin => {
                write!(f, ":STDIN:")
            }
            CheckValueInternal::Value(_) => {
                write!(f, ":REDACTED:")
            }
        }
    }
}

impl Default for CheckValue {
    fn default() -> Self {
        Self::stdin()
    }
}

#[derive(Clone, Debug)]
enum CheckValueInternal {
    Value(String),
    Stdin,
    File(PathBuf),
}

fn resolve_value(
    internal: &CheckValueInternal,
    tr: &mut dyn TroubleshooterRunner,
    prompt: &str,
) -> anyhow::Result<String> {
    match internal {
        CheckValueInternal::Value(s) => Ok(s.to_string()),
        CheckValueInternal::Stdin => {
            let input = tr.prompt_user(prompt)?;
            Ok(input.trim().to_string())
        }
        CheckValueInternal::File(f) => {
            let bytes = std::fs::read(f)?;
            Ok(String::from_utf8_lossy(&bytes).trim().to_string())
        }
    }
}

impl CheckValue {
    /// Provide a default value of "read from stdin"
    pub fn stdin() -> Self {
        Self {
            original: CheckValueInternal::Stdin,
            internal: Arc::new(Mutex::new(CheckValueInternal::Stdin)),
        }
    }

    /// Provide a default value
    #[allow(dead_code)] // to be used in later checks
    pub fn string(s: String) -> Self {
        Self {
            original: CheckValueInternal::Value(s.clone()),
            internal: Arc::new(Mutex::new(CheckValueInternal::Value(s))),
        }
    }

    /// Provide a default value of "read from the specified file"
    #[allow(dead_code)] // to be used in later checks
    pub fn file(p: PathBuf) -> Self {
        Self {
            original: CheckValueInternal::File(p.clone()),
            internal: Arc::new(Mutex::new(CheckValueInternal::File(p))),
        }
    }

    /// Takes the current value and reduces it to a string
    ///
    /// - If the internal value represents `:STDIN:`, it reads from stdin after
    ///   prompting the user
    /// - If the internal value represents `:FILE:<PATH>`, it reads from the file path
    /// - Otherwise, it just reads the internal value
    pub fn resolve_prompt<I: AsRef<str>>(
        &self,
        tr: &mut dyn TroubleshooterRunner,
        prompt: I,
    ) -> anyhow::Result<String> {
        // Yes, this function returns a Result, and yes it deals with Mutexes
        // However, the results are actually based on file system and TTY
        // I/O; if the Mutex fails to lock, this function will resort to using
        // the original input provided
        if let CheckValueInternal::Value(s) = &self.original {
            return Ok(s.to_string());
        };

        let lock = self.internal.lock();
        let mut internal_ref = match lock {
            Ok(r) => r,
            Err(_) => {
                return resolve_value(&self.original, tr, prompt.as_ref());
            }
        };

        if let CheckValueInternal::Value(s) = &*internal_ref {
            return Ok(s.to_string());
        }

        let value = resolve_value(&internal_ref, tr, prompt.as_ref())?;
        *internal_ref = CheckValueInternal::Value(value.clone());

        Ok(value)
    }
}

impl FromStr for CheckValue {
    type Err = !;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s == ":STDIN:" {
            return Ok(CheckValue {
                original: CheckValueInternal::Stdin,
                internal: Mutex::new(CheckValueInternal::Stdin).into(),
            });
        }

        if let Some(path) = s.strip_prefix(":FILE:") {
            return Ok(CheckValue {
                original: CheckValueInternal::File(PathBuf::from(path)),
                internal: Mutex::new(CheckValueInternal::File(PathBuf::from(path))).into(),
            });
        }

        Ok(CheckValue {
            original: CheckValueInternal::Value(s.to_string()),
            internal: Mutex::new(CheckValueInternal::Value(s.to_string())).into(),
        })
    }
}

// Implemented to allow CheckValue to be used directly as a deserialized value in
// a Troubleshooter
impl<'de> Deserialize<'de> for CheckValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct CheckValueVisitor;

        impl<'de> Visitor<'de> for CheckValueVisitor {
            type Value = CheckValue;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("CheckValue")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(CheckValue::from_str(v).into_ok())
            }

            fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                self.visit_str(&v)
            }
        }

        deserializer.deserialize_str(CheckValueVisitor)
    }
}

impl Serialize for CheckValue {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match &self.original {
            CheckValueInternal::File(f) => serializer.serialize_str(&format!("@{}", f.display())),
            CheckValueInternal::Stdin => serializer.serialize_str("-"),
            CheckValueInternal::Value(v) => serializer.serialize_str(&v),
        }
    }
}

/// Represents whether a check failed, succeeded, or was not run
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, Copy, Eq, PartialEq)]
pub enum CheckResultType {
    Success,
    Failure,
    NotRun,
}

impl BitAndAssign for CheckResultType {
    fn bitand_assign(&mut self, rhs: Self) {
        use CheckResultType as CRT;
        match (*self, rhs) {
            (CRT::Failure, _) => {
                *self = CRT::Failure;
            }
            (_, CRT::Failure) => {
                *self = CRT::Failure;
            }
            (CRT::Success, CRT::Success) => {
                *self = CRT::Success;
            }
            (CRT::NotRun, rhs) => {
                *self = rhs;
            }
            (_, CRT::NotRun) => {}
        }
    }
}

/// Contains data about the results of running a check, including
/// when it happened, what happened, a brief summary, and any extra useful information
#[derive(serde::Serialize, serde::Deserialize)]
pub struct CheckResult {
    pub timestamp: DateTime<Utc>,
    pub result_type: CheckResultType,
    pub log_item: String,
    pub extra_details: serde_json::Value,
}

impl CheckResult {
    /// Utility function to quickly fail a check
    pub fn fail<I: Into<String>>(log_item: I, extra_details: serde_json::Value) -> Self {
        Self {
            timestamp: Utc::now(),
            result_type: CheckResultType::Failure,
            log_item: log_item.into(),
            extra_details,
        }
    }

    /// Utility function to quickly mark a check as not being run
    pub fn not_run<I: Into<String>>(log_item: I, extra_details: serde_json::Value) -> Self {
        Self {
            timestamp: Utc::now(),
            result_type: CheckResultType::NotRun,
            log_item: log_item.into(),
            extra_details,
        }
    }

    /// Utility function to quickly mark a check as successful
    pub fn succeed<I: Into<String>>(log_item: I, extra_details: serde_json::Value) -> Self {
        Self {
            timestamp: Utc::now(),
            result_type: CheckResultType::Success,
            log_item: log_item.into(),
            extra_details,
        }
    }

    /// Merge the extra details if both are maps, otherwise overwrite with the new value
    pub fn merge_overwrite_details(self, extra_details: serde_json::Value) -> Self {
        match (self.extra_details, extra_details) {
            (serde_json::Value::Object(mut m1), serde_json::Value::Object(m2)) => {
                m1.extend(m2);

                Self {
                    extra_details: serde_json::Value::Object(m1),
                    ..self
                }
            }
            (_, extra_details) => Self {
                extra_details,
                ..self
            },
        }
    }
}

/// Marks a struct as a valid Troubleshooter
///
/// Merely used to return a list of checks that constitute a troubleshooting process
///
/// Every troubleshooter should extend clap::Parser so that it can be used at the cli
/// and for the daemon, Deserialize and Serialize so that it can be parse configuration
/// from a file for the daemon, and Default so that the daemon tui knows sensible
/// values when editing a troubleshooter and creating a new one
///
/// See [`crate::utils::checks`] for a description of how to make use of this trait
pub trait Troubleshooter:
    clap::Parser + for<'de> Deserialize<'de> + serde::Serialize + Default + Clone
{
    fn checks<'a>(&'a self) -> anyhow::Result<Vec<Box<dyn CheckStep<'a> + 'a>>>;
}

/// A check step identifies a part of the troubleshooting process that could potentially
/// identify the underlying issue with the system or service. Most checks are implemented
/// using functions in [`check_fns`]
pub trait CheckStep<'a> {
    fn name(&self) -> &'static str;

    fn run_check(&self, tr: &mut dyn TroubleshooterRunner) -> anyhow::Result<CheckResult>;
}

impl<'a, T> CheckStep<'a> for Box<T>
where
    T: CheckStep<'a>,
{
    fn name(&self) -> &'static str {
        T::name(self)
    }

    fn run_check(&self, tr: &mut dyn TroubleshooterRunner) -> anyhow::Result<CheckResult> {
        T::run_check(self, tr)
    }
}

/// Utility used to allow troubleshooters to interact with users and run steps
pub trait TroubleshooterRunner {
    fn prompt_user(&mut self, prompt: &str) -> anyhow::Result<String>;
}

/// Holds troubleshooting settings to change behavior when running a troubleshooter later
pub struct CliTroubleshooter {
    show_successful_steps: bool,
    show_not_run_steps: bool,
    hide_extra_details: bool,
    has_rendered_newline_for_step: bool,
}

impl TroubleshooterRunner for CliTroubleshooter {
    fn prompt_user(&mut self, prompt: &str) -> anyhow::Result<String> {
        print!(
            "{}{prompt}",
            if self.has_rendered_newline_for_step {
                ""
            } else {
                "\n"
            }
        );
        self.has_rendered_newline_for_step = true;
        std::io::stdout().lock().flush()?;

        let mut input = String::new();
        std::io::stdin().lock().read_line(&mut input)?;

        Ok(input)
    }
}

impl CliTroubleshooter {
    pub fn new(
        show_successful_steps: bool,
        show_not_run_steps: bool,
        hide_extra_details: bool,
    ) -> Self {
        Self {
            show_successful_steps,
            show_not_run_steps,
            hide_extra_details,
            has_rendered_newline_for_step: false,
        }
    }

    /// Actually runs the troubleshooter specified on the CLI
    pub fn run_cli(&mut self, t: Box<impl Troubleshooter>) -> anyhow::Result<CheckResultType> {
        let checks = t.checks()?;
        let mut start = CheckResultType::NotRun;

        for check in checks {
            print!("\r\x1B[2K");
            print!("Running check {}...", check.name().yellow());
            std::io::stdout().lock().flush()?;

            self.has_rendered_newline_for_step = false;

            let value = check.run_check(self)?;

            start &= value.result_type;

            let has_extra = value.extra_details != serde_json::Value::Null;
            let has_extra_nl = if has_extra { "" } else { "\n" };
            match value.result_type {
                CheckResultType::Success => {
                    if !self.show_successful_steps {
                        continue;
                    }

                    println!(
                        "{}[{}] {} {}{has_extra_nl}",
                        if self.has_rendered_newline_for_step {
                            ""
                        } else {
                            "\n"
                        },
                        check.name().green(),
                        "Check succeeds: ".green(),
                        &value.log_item
                    );
                    self.has_rendered_newline_for_step = true;
                }
                CheckResultType::NotRun => {
                    if !self.show_not_run_steps {
                        continue;
                    }

                    println!(
                        "{}[{}] {} {}{has_extra_nl}",
                        if self.has_rendered_newline_for_step {
                            ""
                        } else {
                            "\n"
                        },
                        check.name().cyan(),
                        "Check not run: ".cyan(),
                        &value.log_item
                    );
                    self.has_rendered_newline_for_step = true;
                }
                CheckResultType::Failure => {
                    println!(
                        "{}[{}] {} {}{has_extra_nl}",
                        if self.has_rendered_newline_for_step {
                            ""
                        } else {
                            "\n"
                        },
                        check.name().red(),
                        "Check failed! ".red(),
                        &value.log_item
                    );
                    self.has_rendered_newline_for_step = true;
                }
            }

            if has_extra && !self.hide_extra_details {
                println!("Extra details: ");
                print!("    ");
                render_extra_details(4, &value.extra_details);
                println!("\n");
            }
        }

        if !self.has_rendered_newline_for_step {
            print!("\r\x1B[2K");
        }

        match start {
            CheckResultType::Failure => {
                println!("{}", "Some troubleshoot steps failed".red());
            }
            CheckResultType::NotRun => {
                println!("{}", "No troubleshooting steps were run".cyan());
            }
            CheckResultType::Success => {
                println!("{}", "Service appears to be up!".green());
            }
        }

        Ok(start)
    }
}

fn render_extra_details(depth: usize, obj: &serde_json::Value) {
    use serde_json::Value;
    match obj {
        Value::Bool(b) => {
            print!("{b}");
        }
        Value::Null => {
            print!("null");
        }
        Value::Number(n) => {
            print!("{n}");
        }
        Value::String(s) => {
            print!(r#""{s}""#);
        }
        Value::Array(ve) => {
            if ve.is_empty() {
                print!("[]");
            } else {
                println!("[");
                for val in ve {
                    print!("{:depth$}", "", depth = depth + 4);
                    render_extra_details(depth + 4, val);
                    println!(",");
                }
                print!("{:depth$}]", "");
            }
        }
        Value::Object(o) => {
            println!("{{");
            for (k, v) in o {
                print!("{:depth$}{k}: ", "", depth = depth + 4);
                render_extra_details(depth + 4, v);
                println!(",");
            }
            print!("{:depth$}}}", "");
        }
    }
}

pub struct DaemonTroubleshooter<F>
where
    F: FnMut(&str) -> anyhow::Result<String>,
{
    prompt_f: F,
}

impl<F> TroubleshooterRunner for DaemonTroubleshooter<F>
where
    F: FnMut(&str) -> anyhow::Result<String>,
{
    fn prompt_user(&mut self, prompt: &str) -> anyhow::Result<String> {
        (self.prompt_f)(prompt)
    }
}

impl<F> DaemonTroubleshooter<F>
where
    F: FnMut(&str) -> anyhow::Result<String>,
{
    pub fn new(prompt_f: F) -> Self {
        Self { prompt_f }
    }
}

/// Utility trait to convert things into a CheckResult but taking a parameter
/// Mostly used to convert Results into CheckResults
pub trait IntoCheckResult {
    fn into_check_result<I: Into<String>>(self, a: I) -> CheckResult;
}

impl<E> IntoCheckResult for Result<CheckResult, E>
where
    E: std::fmt::Debug,
{
    fn into_check_result<I: Into<String>>(self, a: I) -> CheckResult {
        match self {
            Ok(v) => v,
            Err(e) => CheckResult::fail(
                a,
                serde_json::json!({
                    "error": format!("{e:?}")
                }),
            ),
        }
    }
}

/// Utility function to get logs between two timestamps. It returns only a
/// [`serde_json::value::Value`] to make it easy for inclusion in extra details
///
/// If there are errors acquiring system logs, this will return a string with the
/// error message. If there is no compatible log provider, it just returns null
pub fn get_system_logs(start: DateTime<Utc>, end: DateTime<Utc>) -> serde_json::value::Value {
    use serde_json::value::Value;

    if let Ok((_, path)) = qx("which journalctl 2>/dev/null")
        && !path.is_empty()
    {
        return match get_logs_systemd(start, end) {
            Ok(v) => v.into_iter().map(Value::String).collect::<Value>(),
            Err(e) => Value::String(format!("Could not pull system logs: {e:?}")),
        };
    }

    Value::Null
}

fn get_logs_systemd(start: DateTime<Utc>, end: DateTime<Utc>) -> anyhow::Result<Vec<String>> {
    let start = start.with_timezone(&Local);
    let end = end.with_timezone(&Local);

    let format = "%Y-%m-%d %H:%M:%S";

    qx(&format!(
        "journalctl --no-pager '--since={}' '--until={}' --utc",
        start.format(format),
        // journalctl will go up to but not including the time, and has second precision
        // This includes the final second of logs, or all the logs if the start and end
        //   datetimes are the same (down to the second)
        end.checked_add_signed(chrono::TimeDelta::seconds(1))
            .unwrap_or(end)
            .format(format)
    ))
    .map(|(_, o)| o.trim().split("\n").map(String::from).collect())
}
