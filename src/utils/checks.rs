//!

use std::{
    fmt,
    io::{BufRead, Write},
    marker::PhantomData,
    ops::BitAndAssign,
    path::PathBuf,
    str::FromStr,
};

use chrono::prelude::*;
use colored::Colorize;
use serde::{Deserialize, de::Visitor};

#[derive(Debug, Clone)]
pub enum CheckValue {
    Value(String),
    Stdin,
    File(PathBuf),
}

impl CheckValue {
    #[allow(dead_code)] // to be used in later checks
    pub fn resolve_value(self) -> anyhow::Result<String> {
        match self {
            CheckValue::Value(s) => Ok(s),
            CheckValue::Stdin => {
                let mut input = String::new();
                std::io::stdin().lock().read_line(&mut input)?;
                Ok(input)
            }
            CheckValue::File(p) => {
                let bytes = std::fs::read(p)?;
                Ok(String::from_utf8_lossy(&bytes).to_string())
            }
        }
    }

    pub fn resolve_prompt(
        self,
        tr: &mut TroubleshooterRunner,
        prompt: String,
    ) -> anyhow::Result<String> {
        match self {
            CheckValue::Value(s) => Ok(s),
            CheckValue::Stdin => {
                print!(
                    "{}{prompt}",
                    if tr.has_rendered_newline_for_step {
                        ""
                    } else {
                        "\n"
                    }
                );
                tr.has_rendered_newline_for_step = true;
                std::io::stdout().lock().flush()?;
                let mut input = String::new();
                std::io::stdin().lock().read_line(&mut input)?;
                Ok(input)
            }
            CheckValue::File(p) => {
                let bytes = std::fs::read(p)?;
                Ok(String::from_utf8_lossy(&bytes).to_string())
            }
        }
    }
}

impl FromStr for CheckValue {
    type Err = !;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s == ":STDIN:" {
            return Ok(CheckValue::Stdin);
        }

        if s.starts_with(":FILE:") {
            return Ok(CheckValue::File(PathBuf::from(&s[6..])));
        }

        return Ok(CheckValue::Value(s.to_string()));
    }
}

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

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
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

pub struct CheckResult {
    #[allow(dead_code)] // to be used for the daemon
    timestamp: DateTime<Utc>,
    result_type: CheckResultType,
    log_item: String,
    extra_details: serde_json::Value,
}

impl CheckResult {
    pub fn fail(log_item: String, extra_details: serde_json::Value) -> Self {
        Self {
            timestamp: Utc::now(),
            result_type: CheckResultType::Failure,
            log_item,
            extra_details,
        }
    }

    pub fn not_run(log_item: String, extra_details: serde_json::Value) -> Self {
        Self {
            timestamp: Utc::now(),
            result_type: CheckResultType::NotRun,
            log_item,
            extra_details,
        }
    }

    pub fn succeed(log_item: String, extra_details: serde_json::Value) -> Self {
        Self {
            timestamp: Utc::now(),
            result_type: CheckResultType::Success,
            log_item,
            extra_details,
        }
    }
}

pub trait Troubleshooter: for<'de> Deserialize<'de> {
    fn checks<'a>(&'a self) -> Vec<Box<dyn CheckStep<'a> + 'a>>;
}

pub trait CheckStep<'a> {
    fn name(&self) -> &'static str;

    fn run_check(&self, tr: &mut TroubleshooterRunner) -> anyhow::Result<CheckResult>;
}

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

pub fn check_fn<'a, F>(name: &'static str, f: F) -> Box<CheckFn<'a, F>>
where
    F: Fn(&mut TroubleshooterRunner) -> anyhow::Result<CheckResult> + 'a,
{
    Box::new(CheckFn {
        name,
        check_fn: f,
        _lifetime: PhantomData,
    })
}

pub struct TroubleshooterRunner {
    show_successful_steps: bool,
    show_not_run_steps: bool,
    has_rendered_newline_for_step: bool,
}

impl TroubleshooterRunner {
    pub fn new(show_successful_steps: bool, show_not_run_steps: bool) -> Self {
        Self {
            show_successful_steps,
            show_not_run_steps,
            has_rendered_newline_for_step: false,
        }
    }

    pub fn run_cli<T: Troubleshooter>(&mut self, t: T) -> anyhow::Result<CheckResultType> {
        let checks = t.checks();
        let mut start = CheckResultType::NotRun;

        for check in checks {
            print!("\r\x1B[2K");
            print!("Running check {}...", check.name().yellow());
            std::io::stdout().lock().flush()?;

            self.has_rendered_newline_for_step = false;

            let value = check.run_check(self)?;

            start &= value.result_type;

            match value.result_type {
                CheckResultType::Success => {
                    if !self.show_successful_steps {
                        continue;
                    }

                    println!(
                        "{}[{}] {} {}",
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
                        "{}[{}] {} {}",
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
                        "{}[{}] {} {}",
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

            if value.extra_details != serde_json::Value::Null {
                println!("Extra details: ");
                print!("    ");
                render_extra_details(4, &value.extra_details);
                println!("\n\n");
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
            print!("{s}");
        }
        Value::Array(ve) => {
            println!("[");
            for val in ve {
                print!("{:depth$}", "", depth = depth + 4);
                render_extra_details(depth + 4, val);
                println!(",");
            }
            print!("{:depth$}]", "");
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
