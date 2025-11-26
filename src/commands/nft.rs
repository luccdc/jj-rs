use clap::Parser;

use crate::utils::nft;

/// Runs an embedded copy of nft
///
/// Use it by specifying -- and then arguments to pass to nft, e.g.:
///
/// ```sh
/// jj-rs nft -- ls -al
/// ```
#[derive(Parser, Debug)]
#[command(version, about)]
pub struct Nft {
    /// Arguments to pass to the nft binary
    args: Vec<String>,
}

impl super::Command for Nft {
    fn execute(self) -> eyre::Result<()> {
        let nft = nft::Nft::new()?;

        nft.command().args(self.args).spawn()?.wait()?;

        Ok(())
    }
}
