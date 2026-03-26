use std::net::Ipv4Addr;

use crate::utils::packages::{DownloadSettings, install_dnf_packages};

/// Install packages and their dependencies using dnf and
/// a download container
#[derive(clap::Parser, Debug)]
pub struct DnfInstall {
    /// Sneaky IP to use when downloading packages
    #[arg(long, short)]
    sneaky_ip: Option<Ipv4Addr>,

    /// Packages to install
    packages: Vec<String>,
}

impl super::Command for DnfInstall {
    fn execute(self) -> eyre::Result<()> {
        install_dnf_packages(
            DownloadSettings::Container {
                name: None,
                sneaky_ip: self.sneaky_ip,
            },
            &self.packages,
        )
    }
}
