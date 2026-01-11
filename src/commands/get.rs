use std::{path::PathBuf, str::FromStr};

use clap::Parser;

/// Gets a url and downloads to a file
#[derive(Parser, Debug)]
pub struct Get {
    /// URL to download
    url: reqwest::Url,

    /// Filepath to store to. Defaults to filename in URL
    path: Option<PathBuf>,
}

impl super::Command for Get {
    fn execute(self) -> eyre::Result<()> {
        let path = self.path.or_else(|| {
            self.url
                .path_segments()
                .and_then(|segments| segments.last().map(PathBuf::from_str))
                .and_then(Result::ok)
        });

        let path = path.ok_or(eyre::eyre!(
            "File path was not specified, and URL did not end in a file name"
        ))?;

        let path = if path.is_dir() {
            let mut path = path;

            let Some(file_name) = self
                .url
                .path_segments()
                .and_then(|segments| segments.last().map(PathBuf::from_str))
            else {
                eyre::bail!(
                    "Directory was specified for both download path and file to download; specify a file download path"
                );
            };

            path.push(file_name?);
            path
        } else {
            path
        };

        let mut target_file = std::fs::OpenOptions::new()
            .truncate(true)
            .create(true)
            .write(true)
            .open(&path)?;

        let client = reqwest::blocking::Client::new();
        let request = client.get(self.url.clone());

        let request = if path.extension().map(|e| e == "zip").unwrap_or(false) {
            request.header("accept", "application/zip")
        } else {
            request
        };

        let mut response = request.send()?;

        if !response.status().is_success() {
            eyre::bail!(
                "Got response of {} when downloading {}",
                response.status(),
                self.url
            );
        }

        response.copy_to(&mut target_file)?;

        println!("File successfully downloaded!");

        Ok(())
    }
}
