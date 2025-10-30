pub mod backup;
pub mod busybox;
pub mod download_shell;
pub mod r#enum;
pub mod jq;
pub mod nft;
pub mod ports;
pub mod stat;
pub mod useradd;

pub trait Command: clap::Parser {
    fn execute(self) -> anyhow::Result<()>;
}
