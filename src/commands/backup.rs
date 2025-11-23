use std::{
    fs::{File, copy, exists},
    path::PathBuf,
};

use anyhow::Context;
use clap::Parser;
use colored::Colorize;
use flate2::{Compression, write::GzEncoder};
use tar::Builder;
use walkdir::WalkDir;

use crate::strvec;

/// Perform system backups
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
                if !exists(path).context("Could not check if path existed")? {
                    continue;
                }

                println!("{} {}", "--- Adding ".green(), path.green());

                for entry in WalkDir::new(path).into_iter().filter_map(Result::ok) {
                    let Ok(mut file) = File::open(entry.path()) else {
                        continue;
                    };
                    let path =
                        PathBuf::from(entry.path().to_string_lossy().trim_start_matches('/'));
                    let Ok(()) = archive.append_file(path, &mut file) else {
                        continue;
                    };
                    println!("{}", entry.path().display());
                }
            }

            for path in &self.paths {
                println!("{} {}", "--- Adding ".green(), path.green());

                for entry in WalkDir::new(path).into_iter().filter_map(Result::ok) {
                    let Ok(mut file) = File::open(entry.path()) else {
                        continue;
                    };
                    let path =
                        PathBuf::from(entry.path().to_string_lossy().trim_start_matches('/'));
                    let Ok(()) = archive.append_file(path, &mut file) else {
                        continue;
                    };
                    println!("{}", entry.path().display());
                }
            }
            println!("Done creating initial backup!");
        }

        for backup in &self.tarballs {
            println!("Copying backup to {backup}...");
            copy(&self.temp_tarball, backup)?;
        }

        println!("Done with file backups!");

        Ok(())
    }
}
