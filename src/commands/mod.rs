pub mod backup;
pub mod busybox;
pub mod download_shell;
pub mod elk;
pub mod r#enum;
pub mod firewall;
pub mod jq;
pub mod nft;
pub mod ports;
pub mod serve;
pub mod stat;
pub mod tcpdump;
pub mod tmux;
pub mod useradd;

pub trait Command: clap::Parser {
    fn execute(self) -> anyhow::Result<()>;
}
