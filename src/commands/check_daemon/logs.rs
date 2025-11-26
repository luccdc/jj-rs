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

#[derive(serde::Serialize, serde::Deserialize)]
#[non_exhaustive]
pub enum LogEvent {
    Result(TroubleshooterResult),
}

async fn get_log_file(p: &Path) -> Option<File> {
    match tokio::fs::OpenOptions::new()
        .append(true)
        .write(true)
        .create(true)
        .open(p)
        .await
    {
        Ok(v) => Some(v),
        Err(e) => {
            eprintln!("Could not open specified log file: {e}");
            None
        }
    }
}

async fn get_log_socket(ip: SocketAddr) -> Option<TcpStream> {
    match tokio::net::TcpStream::connect(ip).await {
        Ok(v) => Some(v),
        Err(e) => {
            eprintln!("Could not open connection to log server: {e}");
            None
        }
    }
}

pub async fn log_handler_thread(
    config: LogConfig,
    log_pipe: tokio::net::unix::pipe::Receiver,
    log_event_sender: tokio::sync::mpsc::Sender<LogEvent>,
    mut shutdown: tokio::sync::broadcast::Receiver<()>,
) -> eyre::Result<()> {
    // into_blocking_fd unregisters it from the previous tokio runtime it was
    // created on, and from_owned_fd registers it on the current runtime
    let mut log_pipe =
        tokio::net::unix::pipe::Receiver::from_owned_fd(log_pipe.into_blocking_fd()?)?;

    let mut log_file = match config.file.as_deref() {
        Some(f) => get_log_file(f).await,
        None => None,
    };
    let mut log_socket = match config.ip {
        Some(f) => get_log_socket(f).await,
        None => None,
    };

    let mut log_buffer = [0u8; 65536];

    loop {
        let bytes_res = tokio::select! {
            b = log_pipe.read(&mut log_buffer) => b,
            _ = shutdown.recv() => {
                break Ok(());
            }
        };

        let bytes = match bytes_res {
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

        // The idea is that other log events can be sent, such as progress updates
        #[allow(irrefutable_let_patterns)]
        if let LogEvent::Result(r) = &msg
            && (log_file.is_some() || log_socket.is_some())
        {
            let Ok(json) = serde_json::to_string(&r) else {
                eprintln!("Could not serialize message to log and send to file and socket");
                continue;
            };

            let json = json + "\n";

            if let Some(ref mut lf) = log_file
                && let Err(e) = lf.write(json.as_bytes()).await
            {
                eprintln!("Could not write to log file: {e}");
            }

            if let Some(ref mut ls) = log_socket
                && let Err(e) = ls.write(json.as_bytes()).await
            {
                eprintln!("Could not write to log file: {e}");
            }
        }

        if let Err(e) = log_event_sender.send(msg).await {
            eprintln!("Could not dispatch log event: {e}");
        }
    }
}
