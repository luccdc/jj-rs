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

        crate::utils::download_file(self.url.as_str(), path)?;

        println!("File successfully downloaded!");

        Ok(())
    }
}
