use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
};

use tokio::{
    fs::File,
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

use super::TroubleshooterResult;

pub struct LogConfig {
    ip: Option<SocketAddr>,
    file: Option<PathBuf>,
}

impl LogConfig {
    pub fn new(ip: Option<SocketAddr>, file: Option<PathBuf>) -> Self {
        Self { ip, file }
    }
}

pub enum LogEvent {
    Result(TroubleshooterResult),
}

async fn get_log_file(p: &Path) -> Option<File> {
    tokio::fs::OpenOptions::new()
        .append(true)
        .write(true)
        .open(p)
        .await
        .ok()
}

async fn get_log_socket(ip: SocketAddr) -> Option<TcpStream> {
    tokio::net::TcpStream::connect(ip).await.ok()
}

pub async fn log_handler_thread(
    config: LogConfig,
    mut log_pipe: tokio::net::unix::pipe::Receiver,
    log_event_sender: tokio::sync::mpsc::Sender<LogEvent>,
) -> anyhow::Result<()> {
    let mut log_file = match config.file.as_deref() {
        Some(f) => get_log_file(f).await,
        None => None,
    };
    let mut log_socket = match config.ip.clone() {
        Some(f) => get_log_socket(f).await,
        None => None,
    };

    let mut log_buffer = [0u8; 65536];

    loop {
        let bytes = match log_pipe.read(&mut log_buffer).await {
            Ok(v) => v,
            Err(e) => {
                eprintln!("Could not receive bytes from child process: {e}");
                continue;
            }
        };

        // EOF means all children and the main thread have closed the pipe
        if bytes == 0 {
            break Ok(());
        }

        let Ok(msg) = serde_json::from_slice(&log_buffer[..bytes]) else {
            eprintln!("Could not deserialize message from check");
            continue;
        };

        if let Err(e) = log_event_sender.blocking_send(LogEvent::Result(msg)) {
            eprintln!("Could not dispatch log event: {e}");
        }

        if let Some(ref mut lf) = log_file {
            if let Err(e) = lf.write(&log_buffer[..bytes]).await {
                eprintln!("Could not write to log file: {e}");
            }
        }

        if let Some(ref mut ls) = log_socket {
            if let Err(e) = ls.write(&log_buffer[..bytes]).await {
                eprintln!("Could not write to log file: {e}");
            }
        }
    }
}
