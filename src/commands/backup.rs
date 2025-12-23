use std::{
    fs::{File, copy, exists},
    io::{Read, Write},
    path::PathBuf,
};

use clap::Parser;
use colored::Colorize;
use eyre::Context;
use flate2::{Compression, write::GzEncoder};
use tar::Builder;
use walkdir::WalkDir;

use crate::strvec;

#[derive(Clone, Debug)]
pub enum ArchiveFormat {
    Zip,
    GzipTar,
}

impl std::str::FromStr for ArchiveFormat {
    type Err = eyre::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s == "zip" {
            Ok(ArchiveFormat::Zip)
        } else if s == "gzip" || s == "gziptar" || s == "tar" {
            Ok(ArchiveFormat::GzipTar)
        } else {
            eyre::bail!("Invalid archive format type: {s}")
        }
    }
}

/// Perform system backups
#[derive(Parser, Debug)]
#[command(version, about)]
pub struct Backup {
    /// Temporary backup location used when creating initial archive before copying
    #[cfg_attr(unix, arg(long, default_value = "/tmp/i.tgz"))]
    #[cfg_attr(windows, arg(long, default_value = r"C:\i.zip"))]
    temp_tarball: String,

    /// Paths to save data to
    #[cfg_attr(unix, arg(short, long, default_values_t = strvec!["/var/games/.luanti.tgz"]))]
    #[cfg_attr(windows, arg(short, long, default_values_t = strvec![r"C:\Windows\minecraft.zip"]))]
    tarballs: Vec<String>,

    /// Algorithm to use when creating archives
    #[cfg_attr(unix, arg(short, long, default_value = "tar"))]
    #[cfg_attr(windows, arg(short, long, default_value = "zip"))]
    archive_format: ArchiveFormat,

    /// Source directories to back up. Always includes /etc, /var/lib, /var/www, /lib/systemd,
    /// /usr/lib/systemd, and /opt on Linux
    #[arg(short, long)]
    paths: Vec<String>,
}

impl super::Command for Backup {
    fn execute(self) -> eyre::Result<()> {
        match self.archive_format {
            ArchiveFormat::Zip => self.backup_zip(),
            ArchiveFormat::GzipTar => self.backup_tarball(),
        }?;

        for backup in &self.tarballs {
            println!("Copying backup to {backup}...");
            copy(&self.temp_tarball, backup)?;
        }

        println!("Done with file backups!");

        Ok(())
    }
}

impl Backup {
    fn backup_zip(&self) -> eyre::Result<()> {
        println!("Creating source zip...");

        let initial_tarball =
            File::create(&self.temp_tarball).context("Could not create tarball")?;
        let mut archive = zip::ZipWriter::new(initial_tarball);
        let options = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated);

        #[cfg(unix)]
        let static_paths = &[
            "/etc",
            "/var/lib",
            "/var/www",
            "/lib/systemd",
            "/usr/lib/systemd",
            "/opt",
        ][..];

        #[cfg(windows)]
        let static_paths: &[&str] = &[][..];

        let mut paths_ref = self.paths.iter().map(|p| &**p).collect::<Vec<_>>();
        paths_ref.extend_from_slice(static_paths);

        let mut buffer = Vec::new();

        for path in paths_ref {
            if !exists(path).unwrap_or(false) {
                continue;
            }

            println!("{} {}", "--- Adding ".green(), path.green());

            for entry in WalkDir::new(path).into_iter().filter_map(Result::ok) {
                let Some(str_path) = entry.path().to_str().map(str::to_owned) else {
                    continue;
                };
                if entry.path().is_file() {
                    print!("{}...", entry.path().display());
                    let Ok(mut file) = File::open(entry.path()) else {
                        println!("{}", "Err!".red());
                        continue;
                    };

                    let Ok(()) = archive.start_file(str_path, options) else {
                        println!("{}", "Err!".red());
                        continue;
                    };

                    let Ok(_) = file.read_to_end(&mut buffer) else {
                        println!("{}", "Err!".red());
                        continue;
                    };

                    archive.write_all(&buffer)?;
                    buffer.clear();

                    println!("{}", "OK".green());
                } else if entry.path().is_dir() {
                    println!("Adding directory {}", entry.path().display());
                    archive.add_directory(str_path, options)?;
                }
            }
        }
        println!("Done creating initial backup!");

        Ok(())
    }

    fn backup_tarball(&self) -> eyre::Result<()> {
        println!("Creating source tarball...");

        let initial_tarball =
            File::create(&self.temp_tarball).context("Could not create tarball")?;
        let encoder = GzEncoder::new(initial_tarball, Compression::default());
        let mut archive = Builder::new(encoder);

        #[cfg(unix)]
        let static_paths = &[
            "/etc",
            "/var/lib",
            "/var/www",
            "/lib/systemd",
            "/usr/lib/systemd",
            "/opt",
        ][..];

        #[cfg(windows)]
        let static_paths: &[&str] = &[][..];

        let mut paths_ref = self.paths.iter().map(|p| &**p).collect::<Vec<_>>();
        paths_ref.extend_from_slice(static_paths);
        for path in paths_ref {
            if !exists(path).unwrap_or(false) {
                continue;
            }

            println!("{} {}", "--- Adding ".green(), path.green());

            for entry in WalkDir::new(path).into_iter().filter_map(Result::ok) {
                let Ok(mut file) = File::open(entry.path()) else {
                    continue;
                };
                print!("{}... ", entry.path().display());
                let path = PathBuf::from(entry.path().to_string_lossy().trim_start_matches('/'));
                let Ok(()) = archive.append_file(path, &mut file) else {
                    println!("{}", "Err!".red());
                    continue;
                };
                println!("{}", "OK".green());
            }
        }
        println!("Done creating initial backup!");

        Ok(())
    }
}
