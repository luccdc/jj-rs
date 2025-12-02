use std::marker::PhantomData;

use crate::utils::checks::{CheckResult, CheckStep, TroubleshooterRunner};

struct CheckFn<'a, F>
where
    F: Fn(&mut dyn TroubleshooterRunner) -> eyre::Result<CheckResult> + 'a,
{
    name: &'static str,
    internal_fn: F,
    _lifetime: PhantomData<&'a F>,
}

impl<'a, F> CheckStep<'a> for CheckFn<'a, F>
where
    F: Fn(&mut dyn TroubleshooterRunner) -> eyre::Result<CheckResult> + 'a,
{
    fn name(&self) -> &'static str {
        self.name
    }

    fn run_check(&self, tr: &mut dyn TroubleshooterRunner) -> eyre::Result<CheckResult> {
        (self.internal_fn)(tr)
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
    F: Fn(&mut dyn TroubleshooterRunner) -> eyre::Result<CheckResult> + 'a,
{
    Box::new(CheckFn {
        name,
        internal_fn: f,
        _lifetime: PhantomData,
    })
}
