//! Daemon to regularly perform checks against configured services
//!
//! Architecture:
//!
//! Logging thread:
//! - Accepts incoming logs from several logging sources, and will dispatch to the
//!   UI thread, the log file (optional), and the log IP:port (optional)
//!   All logs will be newline delimited JSON instances of `TroubleshooterResult`
//!   Logging thread does not own logs, but merely passes them to all designated
//!   storage targets
//!
//! UI thread:
//! - Display results of check logs, or use ratatui to display a TUI in interactive
//!   mode. Both cases need to handle reading from stdin to gather user input for
//!   checks that ask for it
//! - Can spawn check threads
//!
//! Check threads:
//! - Check threads are used to transition between three states documented below
//!   When waiting, it is ready to handle some basic IPC messages such as Stop or
//!   `TriggerCheck`, but when performing a check the check thread can then fork.
//!   While forking, the child process actually performs the check, but the
//!   parent process will switch to translating IPC messages between the nicer
//!   mpsc channel type and the more powerful pipe channel. Each check will be
//!   given the same mpsc Sender to respond to IPC messages with, and they will
//!   be required to use the same Sender to send messages and responses back
//!   When running, the only message the child will respond to is `PromptResponse`.
//!   Other messages are ignored and discarded, removed from the event queue
//!
//! Check thread state machine:
//! - Paused: can transition to Running with `TriggerNow` or Waiting with Start
//! - Waiting: can transition to Paused with Stop, halt with Die, or Running
//!   after a timeout
//! - Running: Performing a check. Returns to the state it was in when it started
//!   running

use std::{
    collections::HashMap,
    io::{Read, Write, stdin, stdout},
    net::SocketAddr,
    path::PathBuf,
    sync::{Arc, RwLock, atomic::AtomicBool},
};

use clap::{Parser, Subcommand};
use colored::Colorize;
use eyre::Context;
use serde::{Deserialize, Serialize};
use tokio::sync::{broadcast, mpsc};

use crate::{
    checks::{CheckResult, CheckResultType},
    spawn_rt,
};

pub use crate::checks::CheckTypes;

mod check_thread;
mod logs;
mod tui;

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
pub struct CheckId(Arc<str>, Arc<str>);

#[derive(Serialize, Deserialize)]
struct TroubleshooterResult {
    timestamp: chrono::DateTime<chrono::Utc>,
    check_id: CheckId,
    overall_result: CheckResultType,
    steps: Vec<(String, CheckResult)>,
}

type HostCheck = HashMap<Arc<str>, CheckTypes>;
type ChecksConfig = HashMap<Arc<str>, HostCheck>;

#[derive(Serialize, Deserialize, Clone, Default)]
struct DaemonConfig {
    checks: ChecksConfig,
}

// Maps to states:
// currently_running: Running
// !currently_running && started: Waiting
// !currently_running && !started: Paused
struct RuntimeCheckHandle {
    message_sender: mpsc::Sender<check_thread::OutboundMessage>,
    currently_running: AtomicBool,
    started: AtomicBool,
}

type RuntimeHostCheck = HashMap<Arc<str>, (CheckTypes, RuntimeCheckHandle)>;
type RuntimeChecksConfig = HashMap<Arc<str>, RuntimeHostCheck>;

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

    /// When not in interactive mode, show extra details in stdout as well as
    /// sent to files and the socket
    #[arg(short, long)]
    show_extra_details: bool,

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
        #[arg(short = 'H', long)]
        host: String,

        /// Specify the name of the service this check will run against
        #[arg(short, long)]
        service: String,

        #[command(subcommand)]
        check: CheckTypes,
    },
    #[command(visible_alias("c"))]
    /// Load from a file path different checks to perform
    ConfigPath { config_file: PathBuf },
}

impl super::Command for CheckDaemon {
    fn execute(self) -> eyre::Result<()> {
        let log_config = logs::LogConfig::new(self.logs_ip, self.log_file.clone());

        let daemon: RwLock<RuntimeDaemonConfig> = RwLock::new(RuntimeDaemonConfig {
            check_interval: std::time::Duration::from_secs(self.check_interval.into()),
            ..Default::default()
        });

        let config = match self.daemon_config {
            DaemonConfigArg::ConfigPath { config_file } => {
                let config_parsed: eyre::Result<DaemonConfig> = std::fs::read(config_file)
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
                host_svcs.insert(Arc::from(service), check);
                let mut checks = HashMap::new();
                checks.insert(Arc::from(host), host_svcs);
                DaemonConfig { checks }
            }
        };

        std::thread::scope(|scope| -> eyre::Result<()> {
            spawn_rt!(async {
                let (send_shutdown, shutdown) = broadcast::channel(1);
                let (prompt_writer, prompt_reader) = mpsc::channel(128);
                let (log_event_sender, log_event_receiver) = mpsc::channel(128);

                #[cfg(unix)]
                let (log_writer, log_receiver) = {
                    let (log_writer, log_receiver) = tokio::net::unix::pipe::pipe()?;
                    (
                        std::io::PipeWriter::from(log_writer.into_blocking_fd()?),
                        log_receiver,
                    )
                };
                #[cfg(windows)]
                let (log_writer, log_receiver) = tokio::sync::mpsc::channel(8192);

                scope.spawn(|| {
                    spawn_rt!(async {
                        Box::pin(logs::log_handler_thread(
                            log_config,
                            log_receiver,
                            log_event_sender,
                            shutdown,
                        ))
                        .await
                    })
                });

                for (host, checks) in &config.checks {
                    for (check_name, check) in checks {
                        check_thread::register_check(
                            &daemon,
                            (
                                CheckId(Arc::clone(host), Arc::clone(check_name)),
                                check.clone(),
                            ),
                            scope,
                            prompt_writer.clone(),
                            #[cfg(unix)]
                            log_writer.try_clone()?,
                            #[cfg(windows)]
                            log_writer.clone(),
                            send_shutdown.subscribe(),
                            !self.interactive_mode,
                        )?;
                    }
                }

                if self.interactive_mode {
                    tui::main(
                        self.log_file,
                        &daemon,
                        (log_event_receiver, prompt_reader),
                        log_writer,
                        (prompt_writer, scope),
                        send_shutdown,
                    )
                    .await
                } else {
                    basic_log_runner(
                        &daemon,
                        log_event_receiver,
                        prompt_reader,
                        send_shutdown,
                        self.show_extra_details,
                    )
                    .await
                }
            })
        })
    }

    fn setup_tracing(&self) -> eyre::Result<()> {
        // do nothing; let TUI do rendering and handle events
        Ok(())
    }
}

async fn basic_log_runner<'scope, 'env: 'scope>(
    checks: &RwLock<RuntimeDaemonConfig>,
    mut logs_reader: mpsc::Receiver<logs::LogEvent>,
    mut prompt_reader: mpsc::Receiver<(CheckId, String)>,
    send_shutdown: broadcast::Sender<()>,
    show_extra_details: bool,
) -> eyre::Result<()> {
    let ctrl_c = tokio::signal::ctrl_c();
    tokio::pin!(ctrl_c);

    let mut answer_buffer = [0u8; 8192];

    loop {
        tokio::select! {
            _ = &mut ctrl_c => {
                eprintln!("Sending shutdown signal!");
                send_shutdown.send(())?;
                break Ok(());
            }
            Some(event) = logs_reader.recv() => {
                let logs::LogEvent::Result(res) = event else { continue; };

                let mut stdout = stdout().lock();

                writeln!(
                    stdout,
                    "{}: {}.{} - {}",
                    res.timestamp,
                    res.check_id.0,
                    res.check_id.1,
                    match res.overall_result {
                        CheckResultType::Failure => "Failure".red(),
                        CheckResultType::NotRun => "NotRun".cyan(),
                        CheckResultType::Success => "Success".green(),
                    },
                )?;

                for check in &res.steps {
                    let details_str = serde_json::to_string(&check.1.extra_details);
                    if show_extra_details {
                        writeln!(
                            stdout,
                            "\t{}: {} - {} - {} - {}",
                            format!("{}", check.1.timestamp).white(),
                            check.0,
                            match check.1.result_type {
                                CheckResultType::Failure => "Failure".red(),
                                CheckResultType::NotRun => "NotRun".cyan(),
                                CheckResultType::Success => "Success".green(),
                            },
                            check.1.log_item,
                            details_str.unwrap_or("<serialization error>".to_string())
                        )?;
                    } else {
                        writeln!(
                            stdout,
                            "\t{}: {} - {} - {}",
                            format!("{}", check.1.timestamp).white(),
                            check.0,
                            match check.1.result_type {
                                CheckResultType::Failure => "Failure".red(),
                                CheckResultType::NotRun => "NotRun".cyan(),
                                CheckResultType::Success => "Success".green(),
                            },
                            check.1.log_item,
                        )?;
                    }
                }

                writeln!(stdout)?;
            }
            Some((check_id, prompt)) = prompt_reader.recv() => {
                write!(stdout().lock(), "[{}.{}] {prompt}", &check_id.0, &check_id.1)?;
                stdout().flush()?;

                let bytes = stdin().read(&mut answer_buffer)?;

                let message_sender = {
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

                    check_handle.1.message_sender.clone()
                };

                if let Err(e) = message_sender.send(
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
