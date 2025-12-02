use std::{path::PathBuf};

use clap::Parser;

use crate::utils::{system};

/// File hash verification tool
#[derive(Parser, Debug)]
#[command(version, about)]
pub struct File {
    /// A path to perform a task with
    #[arg(short = 'f', long, default_value = ".")]
    path_arg: PathBuf
}

impl super::Command for File {
    fn execute(self) -> eyre::Result<()> {
        system("systemctl status ssh")?;
        Ok(())
    }
}