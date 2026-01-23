use std::{
    io::{Write, BufReader, BufRead, Read},
    path::PathBuf,
    collections::HashSet,
};

use sha2::{Sha256, Digest};

use chrono::Local;

use clap::{Parser, Subcommand, Args};

/// Define common arguments between subcommands
#[derive(Args, Debug)]
pub struct CommonArgs {
    /// Defines paths to evaluate
    #[arg(short = 'f', long = "files", num_args = 1.., value_delimiter = ',')]
    path_arg: Option<Vec<PathBuf>>,

    /// Sets location of hashfile
    #[arg(short = 'l', long = "location", default_value = "./jj_hashes.txt")]
    hashfile_arg: PathBuf,

    /// Search directories recursively
    #[arg(short = 'r', long = "recursive")]
    recursive_arg: bool,

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
        let mut ob: Box<dyn Write> = Box::new(std::fs::File::create(&self.common.hashfile_arg)?);

        let paths: Vec<PathBuf> = match &self.common.path_arg {
            Some(v) => v.clone(),
            None => vec![PathBuf::from(".")],
        };

        let tuple: (Vec<PathBuf>, Vec<PathBuf>) = get_file_paths(&self.common, paths);
        
        for dir in tuple.1 {
            let dirpath = dir.display();
            writeln!(ob, "D {dirpath}")?;
        }
        for file in tuple.0 {
            let filepath = file.display();
            let hash = sha256_file(&file)?;
            let time = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
            writeln!(ob, "F {filepath} {hash} {time}")?;
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
    short_arg: bool,

    /// Verify all files in hash file
    #[arg(short = 'a', long = "all")]
    all_arg: bool,
}

impl VerifyHashes {
    fn execute(self) -> eyre::Result<()> {
        let hashfile = std::fs::File::open(self.common.hashfile_arg.clone())?;
        let hashfile_reader = BufReader::new(hashfile);

        let mut tracked_dirs: Vec<PathBuf> = Vec::new();
        let mut tracked_files: Vec<(PathBuf, String)> = Vec::new();

        for line_result in hashfile_reader.lines() {
            let line: String = line_result?;
            let mut parts = line.split_whitespace();
            let pathtype = match parts.next() {
                Some(t) => t.to_string(),
                None => continue,
            };
            let path = match parts.next() {
                Some(p) => PathBuf::from(p),
                None => continue,
            };
            
            if pathtype == "D" {
                tracked_dirs.push(path);
            }
            else if pathtype == "F" {
                let old_hash = match parts.next() {
                    Some(h) => h.to_string(),
                    None => continue,
                };
                tracked_files.push((path, old_hash));
            }
        }
    
        let paths: Vec<PathBuf> = match &self.common.path_arg {
            Some(v) => v.clone(),
            None => tracked_dirs,
        };

        let tuple: (Vec<PathBuf>, Vec<PathBuf>) = get_file_paths(&self.common, paths);
        let current_files = tuple.0;

        let hashset_current: HashSet<&PathBuf> = current_files.iter().collect();
        let hashset_old: HashSet<&PathBuf> = tracked_files.iter().map(|(p,_)| p).collect();
        let intersection: Vec<(PathBuf,String)> = tracked_files
            .iter()
            .filter(|(path, _)| hashset_current.contains(path))
            .cloned()
            .collect();
        let only_old: Vec<(PathBuf,String)> = tracked_files //This needs to be checked against the supplied dirs
            .iter()
            .filter(|(path, _)| !hashset_current.contains(path))
            .cloned()
            .collect();
        let only_current: Vec<PathBuf> = current_files
            .iter()
            .filter(|path| !hashset_old.contains(path))
            .cloned()
            .collect();

        for (path, old_hash) in intersection {
            let path_str = path.display();
            let new_hash = sha256_file(&path)?;
            if new_hash == old_hash {
                if !self.short_arg {
                    println!("[1] {path_str}");
                }
            }
            else {
                println!("[0] {path_str}");
            }
        }
        for (path, _) in only_old {
            let path_str = path.display();
            println!("[-] {path_str}");
        }
        for path in only_current {
            let path_str = path.display();
            println!("[+] {path_str}");
        }

        Ok(())
    }
}

fn get_file_paths(args: &CommonArgs, paths: Vec<PathBuf>) -> (Vec<PathBuf>, Vec<PathBuf>) {
    let mut files: Vec<PathBuf> = Vec::new();
    let mut dirs: Vec<PathBuf> = Vec::new();
    let mut more_dirs: Vec<PathBuf> = Vec::new();

    let abs_paths: Vec<PathBuf> = paths        
        .into_iter()
        .filter_map(|p| std::fs::canonicalize(&p).ok())
        .collect();

    for path in abs_paths{
        if path.is_file() {
            files.push(path);
        } else if path.is_dir() {
            dirs.push(path.clone());
            if let Ok(entries) = std::fs::read_dir(path) {
                for entry in entries.filter_map(Result::ok) {
                    let p = entry.path();
                    if p.is_file() {
                        files.push(p);
                    }
                    else if args.recursive_arg && p.is_dir() {
                        more_dirs.push(p);
                    }
                }
            }
        }
    }

    if args.recursive_arg && more_dirs.len() > 0 {
        let mut new_tuple: (Vec<PathBuf>, Vec<PathBuf>) = get_file_paths(args, more_dirs);
        files.append(&mut new_tuple.0);
        dirs.append(&mut new_tuple.1);
    }

    (files, dirs)
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