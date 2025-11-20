use std::{net::SocketAddr, path::PathBuf};

pub struct LogHandler {}

impl LogHandler {
    pub fn new(ip: Option<SocketAddr>, file: Option<PathBuf>) -> Self {
        todo!()
    }

    pub fn register_new_client<R: std::io::Read>(&self, input: R) -> anyhow::Result<()> {
        todo!()
    }

    pub fn run<W: std::io::Write>(&self, output: W) -> anyhow::Result<()> {
        todo!()
    }
}
