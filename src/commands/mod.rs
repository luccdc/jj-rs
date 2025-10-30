pub mod backup;
pub mod busybox;
pub mod download_shell;

pub trait Command: clap::Parser {
    fn execute(self) -> anyhow::Result<()>;
}
