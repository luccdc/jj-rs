use std::{
    collections::{HashMap, HashSet},
    fs,
    io::{BufRead, BufReader, Read, Write},
    path::{Path, PathBuf},
};
use walkdir::WalkDir;

use eyre::Result;
use sha2::{Digest, Sha256};

use chrono::Local;

use clap::{Args, Parser, Subcommand};

/// Define common arguments between subcommands
#[derive(Args, Debug)]
pub struct CommonArgs {
    /// Defines paths to evaluate
    #[arg(short = 'f', long = "files", num_args = 1.., value_delimiter = ',')]
    path: Option<Vec<PathBuf>>,

    /// Sets location of hashfile
    #[arg(short = 'l', long = "location", default_value = "./jj_hashes.txt")]
    hashfile: PathBuf,

    /// Search directories recursively
    #[arg(short = 'r', long = "recursive")]
    recursive: bool,
}

#[derive(Subcommand, Debug)]
enum FileCmd {
    /// Save file hashes to a file
    #[command(visible_alias = "s")]
    SaveHashes(SaveHashes),

    /// Save file hashes stored in a file
    #[command(visible_alias = "v")]
    VerifyHashes(VerifyHashes),
}

/// File hash verification
#[derive(Parser, Debug)]
#[command(about, version)]
pub struct File {
    #[command(subcommand)]
    cmd: FileCmd,
}

impl super::Command for File {
    fn execute(self) -> eyre::Result<()> {
        match self.cmd {
            FileCmd::SaveHashes(sh) => sh.execute(),
            FileCmd::VerifyHashes(vh) => vh.execute(),
        }
    }
}

#[derive(Parser, Debug)]
struct SaveHashes {
    #[command(flatten)]
    common: CommonArgs,
}

impl SaveHashes {
    fn execute(self) -> eyre::Result<()> {
        let mut ob = std::fs::File::create(&self.common.hashfile)?;

        let paths: Vec<PathBuf> = match &self.common.path {
            Some(v) => v.clone(),
            None => vec![PathBuf::from(".")],
        };

        for path in paths {
            let wd = WalkDir::new(path);
            for entry in if self.common.recursive {
                wd
            } else {
                wd.max_depth(1)
            } {
                let e = match entry {
                    Ok(v) => v,
                    Err(e) => {
                        eprintln!("Error: {e}");
                        continue;
                    }
                };

                if e.path().is_file() {
                    writeln!(
                        ob,
                        "F {} {} {}",
                        e.path().display(),
                        sha256_file(e.path())?,
                        Local::now().format("%Y-%m-%d %H:%M:%S"),
                    )?;
                } else if e.path().is_dir() {
                    writeln!(ob, "D {}", e.path().display())?;
                }
            }
        }

        Ok(())
    }
}

#[derive(Parser, Debug)]
struct VerifyHashes {
    #[command(flatten)]
    common: CommonArgs,

    /// Only output changed files
    #[arg(short = 's', long = "short")]
    short: bool,

    /// Verify all files in hash file
    #[arg(short = 'a', long = "all")]
    all: bool,
}

impl VerifyHashes {
    fn execute(self) -> eyre::Result<()> {
        let hashfile_reader = BufReader::new(fs::File::open(self.common.hashfile.clone())?);

        let mut tracked_dirs = HashSet::new();
        let mut tracked_files = HashMap::new();

        for line_result in hashfile_reader.lines() {
            let line: String = line_result?;

            let mut split = line.split_whitespace();
            match (split.next(), split.next(), split.next()) {
                (Some("F"), Some(path), Some(hash)) => {
                    tracked_files.insert(PathBuf::from(path.to_string()), hash.to_string());
                }
                (Some("D"), Some(path), _) => {
                    tracked_dirs.insert(PathBuf::from(path.to_string()));
                }
                _ => eprintln!("Bad line: {line}"),
            }
        }

        let paths: Vec<PathBuf> = match &self.common.path {
            Some(v) => v.clone(),
            None => tracked_dirs.clone().into_iter().collect::<Vec<_>>(),
        };

        for path in paths {
            let wd = WalkDir::new(path);
            for entry in if self.common.recursive {
                wd
            } else {
                wd.max_depth(1)
            } {
                let e = match entry {
                    Ok(v) => v,
                    Err(e) => {
                        eprintln!("Error: {e}");
                        continue;
                    }
                };
                let disp = e.path().display();
                if e.path().is_file() {
                    // Check if present in tracked_paths, otherwise it's new.
                    if let Some(old_hash) = tracked_files.remove(e.path()) {
                        // Ok, it's present. Is it valid?
                        let new_hash = match sha256_file(e.path()) {
                            Ok(h) => h,
                            Err(e) => {
                                eprintln!("Error: {e}");
                                continue;
                            }
                        };

                        if new_hash == old_hash {
                            //Great! It's valid!
                            if !self.short {
                                println!("[1] {disp}");
                            }
                        } else {
                            // Invalid!
                            println!("[0] {disp}");
                        }
                    } else {
                        // New!
                        println!("[+] {disp}");
                    }
                } else if e.path().is_dir() {
                    if tracked_dirs.remove(e.path()) {
                        // Good dir
                        if !self.short {
                            println!("[1] {disp}/");
                        }
                    } else {
                        // New dir
                        println!("[+] {disp}/");
                    }
                }
            }
        }

        // Missing dir/file
        for path in tracked_files.keys() {
            println!("[-] {}", path.display());
        }

        for path in tracked_dirs {
            println!("[-] {}/", path.display());
        }

        Ok(())
    }
}

fn sha256_file(path: &Path) -> Result<String> {
    let file = fs::File::open(path)?;
    let mut reader = BufReader::new(file);
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 8192];
    loop {
        let n = reader.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        hasher.update(&buffer[..n]);
    }

    let result = hasher.finalize();
    Ok(format!("{result:x}"))
}
