use std::fs::{copy, exists, File};

use anyhow::Context;
use clap::Parser;
use flate2::{write::GzEncoder, Compression};
use tar::Builder;

use crate::strvec;

#[derive(Parser, Debug)]
#[command(version, about)]
pub struct Backup {
    /// Temporary backup location used when creating initial archive before copying
    #[arg(long, default_value = "/tmp/i.tgz")]
    temp_tarball: String,

    /// Paths to save data to
    #[arg(
        short, long,
        default_values_t = strvec!["/var/games/.luanti.tgz"]
    )]
    tarballs: Vec<String>,

    /// Source directories to back up. Always includes /etc, /var/lib, /var/www, /lib/systemd,
    /// /usr/lib/systemd, and /opt
    #[arg(short, long)]
    paths: Vec<String>,
}

impl super::Command for Backup {
    fn execute(self) -> anyhow::Result<()> {
        // Scope: by forcing this action to be scoped, `archive`, `encoder`, and
        // `initial_tarball` will be closed, allowing
        {
            println!("Creating source tarball...");

            let initial_tarball =
                File::create(&self.temp_tarball).context("Could not create tarball")?;
            let encoder = GzEncoder::new(initial_tarball, Compression::default());
            let mut archive = Builder::new(encoder);

            for path in [
                "/etc",
                "/var/lib",
                "/var/www",
                "/lib/systemd",
                "/usr/lib/systemd",
                "/opt",
            ] {
                if !exists(&path).context("Could not check if path existed")? {
                    continue;
                }

                archive
                    .append_dir_all(&path[1..], &path)
                    .with_context(|| format!("Could not add path: {path}"))?;
            }

            for path in &self.paths {
                let offset = if path.starts_with("/") { 1 } else { 0 };

                archive
                    .append_dir_all(&path[offset..], &path)
                    .with_context(|| format!("Could not add path: {path}"))?;
            }
            println!("Done creating initial backup!");
        }

        for backup in &self.tarballs {
            println!("Copying backup to {backup}...");
            copy(&self.temp_tarball, &backup)?;
        }

        println!("Done with file backups!");

        Ok(())
    }
}
