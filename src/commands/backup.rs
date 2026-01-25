use std::{
    fs::{File, copy, exists, create_dir_all, rename},
    path::{Path, PathBuf},
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
        if self.tarballs.is_empty() {
            eyre::bail!("No destination tarballs provided.");
        }

        let primary_target = PathBuf::from(&self.tarballs[0]);
        let primary_parent = primary_target.parent().unwrap_or(Path::new("."));
        
        println!("{} Pre-flight checks...", "---".blue());
        create_dir_all(primary_parent).context("Could not create destination directory")?;
        
        let estimated_size = self.get_total_source_size();
        #[cfg(unix)]
        Self::check_disk_space(&primary_target, estimated_size)?;

        // Staging: Write to a .part file in the final destination directory
        let mut staging_path = primary_target.clone();
        staging_path.set_extension(format!(
            "{}.part", 
            primary_target.extension().and_then(|e| e.to_str()).unwrap_or("tmp")
        ));

        match self.archive_format {
            ArchiveFormat::Zip => self.backup_zip(&staging_path),
            ArchiveFormat::GzipTar => self.backup_tarball(&staging_path),
        }?;

        // Atomic Rename
        println!("Finalizing primary backup...");
        rename(&staging_path, &primary_target).context("Failed to finalize backup file")?;

        // Copy to secondary targets
        for backup in self.tarballs.iter().skip(1) {
            let path = Path::new(backup);
            if let Some(parent) = path.parent() {
                create_dir_all(parent).ok();
            }
            println!("Copying backup to {backup}...");
            copy(&primary_target, backup)?;
        }

        println!("{}", "Done with file backups!".green().bold());
        Ok(())
    }
}

impl Backup {
    fn get_total_source_size(&self) -> u64 {
        let mut total = 0;
        let mut paths = self.paths.clone();
        #[cfg(unix)]
        paths.extend(vec!["/etc", "/var/lib", "/var/www", "/lib/systemd", "/usr/lib/systemd", "/opt"].into_iter().map(String::from));

        for path in paths {
            for entry in WalkDir::new(path).into_iter().filter_map(Result::ok) {
                if let Ok(meta) = entry.metadata() {
                    if meta.is_file() {
                        total += meta.len();
                    }
                }
            }
        }
        total
    }

    #[cfg(unix)]
    fn check_disk_space(path: &Path, required_bytes: u64) -> eyre::Result<()> {
        use nix::sys::statvfs::statvfs;
        let parent = path.parent().unwrap_or(Path::new("."));
        let stats = statvfs(parent).context("Failed to check disk space")?;
        let available = stats.blocks_available() * stats.fragment_size();
        
        // Safety margin of 5% to avoid pinning the disk at 100%
        if available < (required_bytes + (required_bytes / 20)) {
            eyre::bail!(
                "Insufficient space on {}: need ~{}MB, have {}MB", 
                parent.display(), 
                required_bytes / 1024 / 1024, 
                available / 1024 / 1024
            );
        }
        Ok(())
    }

    fn backup_zip(&self, output_path: &Path) -> eyre::Result<()> {
        println!("Creating source zip...");

        let initial_tarball = File::create(output_path).context("Could not create archive file")?;
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

                    if let Err(e) = std::io::copy(&mut file, &mut archive) {
                        println!("{}: {}", "Err writing to zip".red(), e);
                        continue;
                    }

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

    fn backup_tarball(&self, output_path: &Path) -> eyre::Result<()> {
        println!("Creating source tarball...");

        let initial_tarball = File::create(output_path).context("Could not create archive file")?;
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
                let archive_path = entry.path().strip_prefix("/").unwrap_or(entry.path());
                let Ok(()) = archive.append_file(archive_path, &mut file) else {
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
