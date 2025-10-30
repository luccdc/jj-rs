pub mod backup;
pub mod busybox;
pub mod download_shell;
pub mod r#enum;
pub mod ports;
pub mod stat;

pub trait Command: clap::Parser {
    fn execute(self) -> anyhow::Result<()>;
}
