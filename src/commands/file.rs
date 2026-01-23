use std::{
    fs::OpenOptions,
    io::{Write, stdout, BufReader, Read},
    net::{IpAddr, Ipv4Addr},
    path::PathBuf,
    process::Stdio,
};

use sha2::{Sha256, Digest};

use chrono::Local;

use clap::{Parser, Subcommand, Args};

/// Define common arguments between subcommands
#[derive(Args, Debug)]
pub struct CommonArgs {
    /// Defines paths to evaluate
    #[arg(short = 'f', long = "files", num_args = 1.., value_delimiter = ',', default_value = ".")]
    path_arg: Vec<PathBuf>,

    /// Sets location of hashfile
    #[arg(short = 'l', long = "location", default_value = "./jj_hashes.txt")]
    hashfile_arg: PathBuf,

    /// Search directories recursively
    #[arg(short = 'r', long = "recursive")]
    recursive_arg: bool,

    /// Show hidden files
    #[arg(short = 'a', long = "all")]
    hidden_arg: bool,

    /// Only output changed files
    #[arg(short = 's', long = "short")]
    short_arg: bool,
}

#[derive(Subcommand, Debug)]
enum FileCmd {
    /// Save file hashes to a file
    #[command(visible_alias = "s")]
    SaveHashes(SaveHashes),

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
        let mut ob: Box<dyn Write> = Box::new(std::fs::File::create(&self.common.hashfile_arg)?);

        let files: Vec<PathBuf> = read_files(&self.common, self.common.path_arg.clone());
        for file in files {
            let filepath = file.display();
            let hash = sha256_file(&file)?;
            let time = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
            writeln!(ob, "{filepath} {hash} {time}")?;
        }

        Ok(())
    }
}

fn read_files(args: &CommonArgs, paths: Vec<PathBuf>) -> Vec<PathBuf> {
    let mut files: Vec<PathBuf> = Vec::new();

    let abs_paths: Vec<PathBuf> = paths        
        .into_iter()
        .filter_map(|p| std::fs::canonicalize(&p).ok()) // skip paths that don’t exist
        .collect();

    for path in abs_paths{
        if path.is_file() {
            files.push(path);
        } else if path.is_dir() {
            if let Ok(entries) = std::fs::read_dir(path) {
                for entry in entries.filter_map(Result::ok) {
                    let p = entry.path();
                    if p.is_file() {
                        files.push(p);
                    }
                }
            }
        }
    }

    files
}

fn sha256_file(path: &std::path::PathBuf) -> std::io::Result<String> {
    let file = std::fs::File::open(path)?;
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
    Ok(format!("{:x}", result))
}