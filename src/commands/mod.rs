pub mod backup;

pub trait Command: clap::Parser {
    fn execute(self) -> anyhow::Result<()>;
}
