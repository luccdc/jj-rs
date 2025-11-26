use clap::Parser;

use crate::utils::tcpdump;

/// Runs an embedded copy of tcpdump
///
/// Use it by specifying -- and then arguments to pass to tcpdump, e.g.:
///
/// ```sh
/// jj-rs tcpdump -- -nnei eth0 tcp port 80
/// ```
#[derive(Parser, Debug)]
#[command(version, about)]
pub struct Tcpdump {
    /// Arguments to pass to the tcpdump binary
    args: Vec<String>,
}

impl super::Command for Tcpdump {
    fn execute(self) -> eyre::Result<()> {
        let tcpdump = tcpdump::Tcpdump::new()?;

        tcpdump.command(&self.args, None)?;

        Ok(())
    }
}
