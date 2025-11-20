//! Daemon to regularly perform checks against configured services
//!
//! Architecture:
//!
//! Logging thread:
//! - Accepts incoming logs from several logging sources, and will dispatch to the
//!   UI thread, the log file (optional), and the log IP:port (optional)
//!   All logs will be newline delimited JSON instances of TroubleshooterResult
//! Daemon thread:
//! - Manages current check processes. Checks will be run by forking and use
//!   anonymous pipes to communicate state and commands with JSON, or signals to
//!   indicate killing processes. Processes will be used instead of threads because
//!   certain checks make use of download containers and modify nftables, hopping
//!   between namespaces and performing actions based on a process ID
//! - The daemon will spawn a sub thread that muxes together prompts from the checks
//!   to obtain values via "stdin", ensuring that different checks don't read values
//!   intended for another check value
//! UI thread:
//! - Display results of check logs, or use ratatui to display a TUI in interactive
//!   mode. Both cases need to handle reading from stdin to gather user input for
//!   checks that ask for it

use std::{
    collections::HashMap,
    io::{Read, Write},
    net::SocketAddr,
    os::fd::AsFd,
    path::PathBuf,
    sync::RwLock,
};

use anyhow::Context;
use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};

use crate::checks::{CheckResult, CheckResultType};

use super::check::CheckCommands;

mod daemon;
mod logs;
mod tui;

#[derive(Serialize, Deserialize)]
pub struct TroubleshooterResult {
    timestamp: chrono::DateTime<chrono::Utc>,
    overall_result: CheckResultType,
    steps: HashMap<String, CheckResult>,
}

type HostCheck = HashMap<String, crate::commands::check::CheckCommands>;
type ChecksConfig = HashMap<String, HostCheck>;

#[derive(Serialize, Deserialize, Clone, Default)]
struct DaemonConfig {
    checks: ChecksConfig,
}

type RuntimeHostCheck = HashMap<String, (CheckCommands, daemon::RuntimeCheckStateHandle)>;
type RuntimeChecksConfig = HashMap<String, RuntimeHostCheck>;

#[derive(Default)]
struct RuntimeDaemonConfig {
    check_interval: std::time::Duration,
    checks: RuntimeChecksConfig,
}

/// Loads a configuration file and performs checks against the services in the
/// configuration file
///
/// See the help page for the check subcommand for more information on individual
/// checks
#[derive(Parser, Debug)]
#[command(version, about)]
pub struct CheckDaemon {
    /// Run an interactive daemon that will allow navigating check information
    /// in the terminal using an ncurses like interface
    #[arg(short, long)]
    interactive_mode: bool,

    /// Specify where to send newline delimited JSON log entries for the daemon
    #[arg(short = 'I', long)]
    logs_ip: Option<SocketAddr>,

    /// Specify a log file to save results to
    #[arg(short = 'f', long)]
    log_file: Option<PathBuf>,

    /// Specify how long to wait before running another check (in seconds)
    #[arg(short, long, default_value = "90")]
    check_interval: u16,

    #[command(subcommand)]
    daemon_config: DaemonConfigArg,
}

/// Runs a daemon that performs checks periodically
#[derive(Subcommand, Debug)]
pub enum DaemonConfigArg {
    /// Watch a single service and perform a single check
    #[command(visible_alias("s"))]
    Single {
        /// Specify the host name that this check will be running against
        host: String,

        /// Specify the name of the service this check will run against
        service: String,

        #[command(subcommand)]
        check: CheckCommands,
    },
    #[command(visible_alias("c"))]
    /// Load from a file path different checks to perform
    ConfigPath { config_file: PathBuf },
}

impl super::Command for CheckDaemon {
    fn execute(self) -> anyhow::Result<()> {
        let logs = logs::LogHandler::new(self.logs_ip.clone(), self.log_file.clone());
        let checks: RwLock<RuntimeDaemonConfig> = RwLock::new(RuntimeDaemonConfig {
            check_interval: std::time::Duration::from_secs(self.check_interval.into()),
            ..Default::default()
        });

        let config = match self.daemon_config {
            DaemonConfigArg::ConfigPath { config_file } => {
                let config_parsed: anyhow::Result<DaemonConfig> = std::fs::read(config_file)
                    .context("Could not read daemon configuration")
                    .and_then(|c| {
                        toml::from_slice(&c).context("Could not parse daemon configuration")
                    });

                if self.interactive_mode {
                    config_parsed.unwrap_or_default()
                } else {
                    config_parsed?
                }
            }
            DaemonConfigArg::Single {
                host,
                service,
                check,
            } => {
                let mut host_svcs = HashMap::new();
                host_svcs.insert(service, check);
                let mut checks = HashMap::new();
                checks.insert(host, host_svcs);
                DaemonConfig { checks }
            }
        };

        let (prompt_reader, prompt_writer) = std::io::pipe()?;
        let (answer_reader, answer_writer) = std::io::pipe()?;

        std::thread::scope(|scope| -> anyhow::Result<()> {
            let daemon = daemon::spawn_daemon(&logs, &checks, prompt_writer, answer_reader, scope);

            daemon.import_config(&config)?;
            daemon.start_all_unstarted()?;

            if self.interactive_mode {
                tui::main(&checks, &daemon, &logs, prompt_reader, answer_writer, scope)
            } else {
                basic_log_runner(&logs, prompt_reader, answer_writer, scope)
            }
        })
    }
}

fn basic_log_runner<'scope, 'env: 'scope>(
    logs: &'env logs::LogHandler,
    mut prompt_reader: std::io::PipeReader,
    mut answer_writer: std::io::PipeWriter,
    scope: &'scope std::thread::Scope<'scope, 'env>,
) -> anyhow::Result<()> {
    let (mut logs_reader, logs_writer) = std::io::pipe()?;

    scope.spawn(|| {
        if let Err(e) = logs.run(logs_writer) {
            eprintln!("Error running logs thread! {e}");
        };
    });

    let mut logs_buffer = [0u8; 8192];
    let mut prompt_buffer = [0u8; 8192];
    let mut answer_buffer = [0u8; 8192];

    loop {
        let pr_raw = prompt_reader.as_fd();
        let logs_raw = logs_reader.as_fd();

        let mut fds = nix::sys::select::FdSet::new();
        fds.insert(pr_raw);
        fds.insert(logs_raw);

        nix::sys::select::select(None, &mut fds, None, None, None)?;

        if let Ok(bytes) = prompt_reader.read(&mut prompt_buffer) {
            std::io::stdout().write(&prompt_buffer[..bytes])?;

            let bytes = std::io::stdin().read(&mut answer_buffer)?;
            answer_writer.write_all(&answer_buffer[..bytes])?;
        }

        if let Ok(bytes) = logs_reader.read(&mut logs_buffer) {
            std::io::stdout().write(&logs_buffer[..bytes])?;
        }
    }
}
