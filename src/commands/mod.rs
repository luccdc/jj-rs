pub mod backup;
pub mod busybox;

pub trait Command: clap::Parser {
    fn execute(self) -> anyhow::Result<()>;
}
