use std::net::Ipv4Addr;

use crate::utils::packages::{DownloadSettings, install_apt_packages};

/// Install packages and their dependencies using apt and
/// a download container
#[derive(clap::Parser, Debug)]
pub struct AptInstall {
    /// Use the download shell
    #[arg(long, short = 'd')]
    use_download_shell: bool,

    /// Sneaky IP to use when downloading packages
    #[arg(long, short)]
    sneaky_ip: Option<Ipv4Addr>,

    /// Packages to install
    packages: Vec<String>,
}

impl super::Command for AptInstall {
    fn execute(self) -> eyre::Result<()> {
        let settings = if self.use_download_shell {
            DownloadSettings::Container {
                name: None,
                sneaky_ip: self.sneaky_ip,
            }
        } else {
            DownloadSettings::NoContainer
        };

        install_apt_packages(settings, &self.packages)
    }
}
