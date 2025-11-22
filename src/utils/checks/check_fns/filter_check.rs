use anyhow::Context;

use crate::utils::{
    checks::{CheckResult, CheckStep, TroubleshooterRunner},
    distro::Distro,
};

/// Control whether or not run the underlying check for [`filter_check`] or [`filter_check_when`]
/// is run or not run with the provided error message
pub enum CheckFilterResult {
    Run,
    NoRun(String),
}

pub trait IntoCheckFilterResult {
    fn into_check_filter_result(self) -> CheckFilterResult;
}

impl IntoCheckFilterResult for CheckFilterResult {
    fn into_check_filter_result(self) -> CheckFilterResult {
        self
    }
}

impl IntoCheckFilterResult for Option<CheckFilterResult> {
    fn into_check_filter_result(self) -> CheckFilterResult {
        self.unwrap_or(CheckFilterResult::Run)
    }
}

impl<E, I> IntoCheckFilterResult for Result<I, E>
where
    E: std::fmt::Debug,
    I: IntoCheckFilterResult,
{
    fn into_check_filter_result(self) -> CheckFilterResult {
        match self {
            Ok(v) => v.into_check_filter_result(),
            Err(e) => CheckFilterResult::NoRun(format!(
                "Could not decide whether or not to run check: {e:?}"
            )),
        }
    }
}

struct CheckFilter<'a, F, T>
where
    F: Fn(Option<Distro>) -> T + 'a,
{
    check: Box<dyn CheckStep<'a> + 'a>,
    filter_func: F,
}

impl<'a, F, T> CheckStep<'a> for CheckFilter<'a, F, T>
where
    F: Fn(Option<Distro>) -> T + 'a,
    T: IntoCheckFilterResult + 'a,
{
    fn name(&self) -> &'static str {
        self.check.name()
    }

    fn run_check(&self, tr: &mut dyn TroubleshooterRunner) -> anyhow::Result<CheckResult> {
        let distro = crate::utils::distro::get_distro().context(
            "Could not query current Linux distribution to determine if a check should run",
        )?;
        match (self.filter_func)(distro).into_check_filter_result() {
            CheckFilterResult::Run => self.check.run_check(tr),
            CheckFilterResult::NoRun(v) => Ok(CheckResult::not_run(v, serde_json::json!(null))),
        }
    }
}

/// Allows applying a filter to a check, only running the underlying check
/// if the filter applied matches
///
/// The filter function takes as a parameter the current Linux distribution
///
/// ```
/// # use jj_rs::utils::checks::{CheckResult, CheckFilterResult, check_fn, filter_check_when};
/// filter_check_when(
///     check_fn(
///         "Always return true",
///         |_| {
///             Ok(CheckResult::succeed(
///                 "Check has returned true",
///                 serde_json::json!(null)
///             ))
///         }
///     ),
///     |distro| Ok::<_, ()>(if distro.map(|d| d.is_deb_based()).unwrap_or(false) {
///         CheckFilterResult::Run
///     } else {
///         CheckFilterResult::NoRun("Test not designed for non-Debian systems".into())
///     })
/// );
/// ```
pub fn filter_check_when<'a, F, T>(
    check: Box<dyn CheckStep<'a> + 'a>,
    filter_func: F,
) -> Box<dyn CheckStep<'a> + 'a>
where
    F: Fn(Option<Distro>) -> T + 'a,
    T: IntoCheckFilterResult + 'a,
{
    Box::new(CheckFilter { check, filter_func })
}

/// Runs the check only when the provided input is true. Uses the message provided if the
/// boolean expression results in false
///
/// ```
/// # use jj_rs::utils::checks::{CheckResult, check_fn, filter_check};
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
///     false,
///     "Always not run"
/// );
/// ```
pub fn filter_check<'a, I: Into<String> + Clone + 'a>(
    check: Box<dyn CheckStep<'a> + 'a>,
    predicate: bool,
    message: I,
) -> Box<dyn CheckStep<'a> + 'a> {
    filter_check_when(check, move |_| {
        if predicate {
            CheckFilterResult::Run
        } else {
            CheckFilterResult::NoRun(message.clone().into())
        }
    })
}
