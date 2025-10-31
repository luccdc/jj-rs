pub enum CheckResultType {
    Success,
    Failure,
    NotRun,
}

pub struct CheckResult {
    result_type: CheckResultType,
    log_item: String,
    extra_details: serde_json::Value,
}

pub struct TroubleshooterConfig {}

pub trait Troubleshooter {
    fn name(&self) -> &'static str;

    fn checks<'a>(&'a self) -> anyhow::Result<Vec<&'a dyn CheckStep>>;
}

pub trait CheckStep {
    fn name(&self) -> &'static str;

    fn run_check(&self, config: &mut TroubleshooterConfig) -> anyhow::Result<CheckResult>;
}

pub struct TroubleshooterEnvironment {}

impl TroubleshooterEnvironment {
    pub fn new<P: Into<Option<AsRef<Path>>>>(conf_path: P) -> anyhow::Result<Self> {
        Ok(Self)
    }

    pub fn run_troubleshooter_cli(
        &mut self,
        troubleshooter: &dyn Troubleshooter,
    ) -> anyhow::Result<()> {
        Ok(())
    }
}
