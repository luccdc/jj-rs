use cfg_if::cfg_if;

cfg_if! {
    if #[cfg(unix)] {
        pub mod busybox;
        pub mod check_daemon;
        pub mod download_shell;
        pub mod elk;
        pub mod r#enum;
        pub mod firewall;
        pub mod jq;
        pub mod nft;
        pub mod ports;
        pub mod ssh;
        pub mod stat;
        pub mod tcpdump;
        pub mod tmux;
        pub mod useradd;
        pub mod zsh;
    }
}

pub mod backup;
pub mod check;
pub mod serve;

pub trait Command: clap::Parser {
    fn execute(self) -> eyre::Result<()>;
}
