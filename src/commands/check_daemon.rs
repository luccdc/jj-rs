//! Daemon to regularly perform checks against configured services
//!
//! Architecture:
//!
//! Logging thread:
//! - Accepts incoming logs from several logging sources, and will dispatch to the
//!   UI thread, the log file (optional), and the log IP:port (optional)
//!   All logs will be newline delimited JSON instances of TroubleshooterResult
//!   Logging thread does not own logs, but merely passes them to all designated
//!   storage targets
//! UI thread:
//! - Display results of check logs, or use ratatui to display a TUI in interactive
//!   mode. Both cases need to handle reading from stdin to gather user input for
//!   checks that ask for it
//! - Can spawn check threads
//! Check threads:
//! - Check threads are used to transition between two states, waiting and
//!   performing a check. When waiting, it is ready to handle some basic IPC
//!   messages such as Stop or TriggerCheck, but when performing a check
//!   the check thread can then fork. While forking, the child process actually
//!   performs the check, but the parent process will switch to translating IPC
//!   messages between the nicer mpsc channel type and the more powerful pipe
//!   channel. Each check will be given the same mpsc Sender to respond to IPC
//!   messages with, and they will be required to use the same Sender to send
//!   messages and responses back

use std::{
    collections::HashMap,
    net::SocketAddr,
    path::PathBuf,
    sync::{Arc, RwLock, atomic::AtomicBool},
};

use anyhow::Context;
use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, stdin, stdout},
    net::unix::pipe,
    sync::mpsc,
};

use crate::checks::{CheckResult, CheckResultType};

use super::check::CheckCommands;

mod check_thread;
mod logs;
mod tui;

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
pub struct CheckId(Arc<str>, Arc<str>);

#[derive(Serialize, Deserialize)]
pub struct TroubleshooterResult {
    timestamp: chrono::DateTime<chrono::Utc>,
    check_id: CheckId,
    overall_result: CheckResultType,
    steps: HashMap<String, CheckResult>,
}

type HostCheck = HashMap<String, crate::commands::check::CheckCommands>;
type ChecksConfig = HashMap<String, HostCheck>;

#[derive(Serialize, Deserialize, Clone, Default)]
struct DaemonConfig {
    checks: ChecksConfig,
}

struct RuntimeCheckHandle {
    message_sender: mpsc::Sender<check_thread::OutboundMessage>,
    currently_running: AtomicBool,
}

type RuntimeHostCheck = HashMap<String, (CheckCommands, RuntimeCheckHandle)>;
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
        let log_config = logs::LogConfig::new(self.logs_ip.clone(), self.log_file.clone());

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

        let (prompt_writer, prompt_reader) = mpsc::channel(128);
        let (log_writer, log_receiver) = pipe::pipe()?;
        let (log_event_sender, log_event_receiver) = mpsc::channel(128);

        std::thread::scope(|scope| -> anyhow::Result<()> {
            scope.spawn(|| {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()?
                    .block_on(async {
                        logs::log_handler_thread(log_config, log_receiver, log_event_sender).await
                    })
            });

            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?
                .block_on(async {
                    if self.interactive_mode {
                        // tui::main(&checks, &daemon, &logs, prompt_reader, answer_writer, scope)
                        todo!()
                    } else {
                        basic_log_runner(&checks, log_event_receiver, prompt_reader).await
                    }
                })
        })
    }
}

async fn basic_log_runner<'scope, 'env: 'scope>(
    checks: &RwLock<RuntimeDaemonConfig>,
    mut logs_reader: mpsc::Receiver<logs::LogEvent>,
    mut prompt_reader: mpsc::Receiver<(CheckId, Option<String>)>,
) -> anyhow::Result<()> {
    let mut answer_buffer = [0u8; 8192];

    loop {
        tokio::select! {
            Some(event) = logs_reader.recv() => {
                let logs::LogEvent::Result(res) = event;

                println!(
                    "{}: {}.{} - {:?}; {}",
                    res.timestamp,
                    res.check_id.0,
                    res.check_id.1,
                    res.overall_result,
                    serde_json::to_string(&res).unwrap_or("<serialization error>".to_string())
                );
            }
            Some((check_id, prompt)) = prompt_reader.recv() => {
                if let Some(p) = prompt {
                    print!("{p}");
                    stdout().flush().await?;
                }

                let bytes = stdin().read(&mut answer_buffer).await?;

                let checks = match checks.read() {
                    Ok(v) => v,
                    Err(e) => {
                        eprintln!(
                            "Could not send response back to check {}.{}! {e}",
                            check_id.0,
                            check_id.1
                        );
                        continue;
                    }
                };

                let Some(host_handle) = checks.checks.get(&*check_id.0) else {
                    eprintln!("Could not identify host in current configuration: {}", check_id.0);
                    continue;
                };

                let Some(check_handle) = host_handle.get(&*check_id.1) else {
                    eprintln!("Could not identify check in current configuration: {}", check_id.1);
                    continue;
                };

                if let Err(e) = check_handle.1.message_sender.send(
                    check_thread::OutboundMessage::PromptResponse(
                        String::from_utf8_lossy(&answer_buffer[..bytes]).to_string()
                    )
                ).await {
                    eprintln!("Could not send prompt response back to check thread: {e}");
                }
            }
        }
    }
}
