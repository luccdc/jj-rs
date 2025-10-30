use clap::Parser;

#[derive(Parser, Debug)]
pub struct Enum;

impl super::Command for Enum {
    fn execute(self) -> anyhow::Result<()> {
        super::ports::Ports.execute()?;

        Ok(())
    }
}
