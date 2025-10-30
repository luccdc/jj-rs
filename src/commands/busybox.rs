use std::process::Stdio;

use clap::Parser;

use crate::utils::busybox;

/// Runs an embedded copy of busybox
///
/// Use it by specifying -- and then arguments to pass to busybox, e.g.:
///
/// ```sh
/// jj-rs busybox -- ls -al
/// ```
#[derive(Parser, Debug)]
#[command(version, about)]
pub struct Busybox {
    /// Arguments to pass to the busybox binary
    args: Vec<String>,
}

impl super::Command for Busybox {
    fn execute(self) -> anyhow::Result<()> {
        let bb = busybox::Busybox::new()?;

        let args = if self.args.is_empty() {
            &["busybox".to_string()][..]
        } else {
            &self.args
        };

        bb.execv(args)?;

        Ok(())
    }
}
