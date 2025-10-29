use clap::Parser;

use crate::strvec;

#[derive(Parser, Debug)]
#[command(version, about)]
pub struct Backup {
    /// Paths to save data to
    #[arg(
        short, long,
        default_values_t = strvec!["/var/games/.luanti.tgz"]
    )]
    tarballs: Vec<String>,

    /// Source directories to back up
    #[arg(
        short, long,
        default_values_t = strvec![
            "/etc", "/var/lib", "/var/www", "/lib/systemd",
            "/usr/lib/systemd", "/opt"
        ]
    )]
    paths: Vec<String>,
}

impl super::Command for Backup {
    fn execute(self) -> Result<(), std::process::ExitCode> {
        dbg!(&self);

        Ok(())
    }
}
