use std::{fs, net::Ipv4Addr};

use clap::{Parser, Subcommand};
use eyre::Context;

use crate::utils::{
    download_container::DownloadContainer,
    packages::{install_apt_packages, install_dnf_packages, DownloadSettings},
    qx,
    system,
};

#[derive(Parser, Debug)]
pub struct ClamAv {
    #[command(subcommand)]
    cmd: ClamAvCmd,
}

#[derive(Subcommand, Debug)]
pub enum ClamAvCmd {
    /// Install ClamAV packages
    ///
    /// - dnf:         clamav + clamav-freshclam
    /// - apt/apt-get: clamav + clamav-daemon
    Install {
        /// Use the download shell / container for outbound traffic
        #[arg(long, short = 'd')]
        use_download_shell: bool,

        /// Sneaky IP to use when downloading packages
        #[arg(long, short)]
        sneaky_ip: Option<Ipv4Addr>,

        /// On RHEL-family (Rocky/Alma/RHEL/CentOS), auto-enable EPEL if clamav is not found
        #[arg(long, default_value_t = true)]
        enable_epel: bool,
    },

    /// Update ClamAV definitions using freshclam
    Update {
        /// Use the download shell / container for outbound traffic
        #[arg(long, short = 'd')]
        use_download_shell: bool,

        /// Sneaky IP to use when updating definitions
        #[arg(long, short)]
        sneaky_ip: Option<Ipv4Addr>,
    },
}

fn settings(use_download_shell: bool, sneaky_ip: Option<Ipv4Addr>) -> DownloadSettings {
    if use_download_shell {
        DownloadSettings::Container { name: None, sneaky_ip }
    } else {
        DownloadSettings::NoContainer
    }
}

/// True if `command -v <cmd>` returns success.
fn has_cmd(cmd: &str) -> bool {
    qx(&format!("command -v {cmd}"))
        .map(|(status, _)| status.success())
        .unwrap_or(false)
}

/// Run a closure either inside the download container (if enabled) or directly.
fn run_in_settings<F>(settings: &DownloadSettings, f: F) -> eyre::Result<()>
where
    F: FnOnce() -> eyre::Result<()>,
{
    match settings {
        DownloadSettings::Container { name, sneaky_ip } => {
            let container = DownloadContainer::new(name.clone(), *sneaky_ip)?;
            container.run(|| -> eyre::Result<()> { f() })??;
            Ok(())
        }
        DownloadSettings::NoContainer => f(),
    }
}

/// Cheap detection for Rocky/Alma/RHEL/CentOS-like systems.
fn is_rhel_family() -> bool {
    let os_release = fs::read_to_string("/etc/os-release")
        .unwrap_or_default()
        .to_lowercase();

    // Examples:
    // ID="rocky"
    // ID_LIKE="rhel fedora"
    let id_match = ["id=rocky", "id=rhel", "id=almalinux", "id=centos"]
        .iter()
        .any(|k| os_release.contains(k));
    let like_match = os_release.contains("id_like=") && os_release.contains("rhel");
    id_match || like_match
}

/// Check whether a dnf package exists in enabled repositories.
fn dnf_pkg_available(pkg: &str) -> bool {
    // `dnf list --available <pkg>` returns nonzero if not found.
    qx(&format!("dnf -q list --available {pkg}"))
        .map(|(status, _)| status.success())
        .unwrap_or(false)
}

fn maybe_enable_epel(settings: &DownloadSettings) -> eyre::Result<()> {
    run_in_settings(settings, || -> eyre::Result<()> {
        // Standard method on RHEL-family.
        system("dnf -y install epel-release")
            .context("Failed to install epel-release (EPEL enable)")?;
        // Best-effort refresh; not fatal if it fails.
        let _ = system("dnf -y makecache");
        Ok(())
    })
}

fn install_clamav(settings: DownloadSettings, enable_epel: bool) -> eyre::Result<()> {
    // Prefer DNF if present
    if has_cmd("dnf") {
        // On Rocky/RHEL-family, clamav often isn't in base repos.
        if !dnf_pkg_available("clamav") {
            if enable_epel && is_rhel_family() {
                eprintln!(
                    "clamav not found in enabled repos; attempting to enable EPEL (epel-release)..."
                );
                maybe_enable_epel(&settings)?;
            }
        }

        // If still unavailable, produce a clearer error than "No .rpm downloaded".
        if !dnf_pkg_available("clamav") {
            eyre::bail!(
                "clamav package not found in enabled dnf repositories. On Rocky/RHEL-family, enable EPEL (epel-release) then try again."
            );
        }

        return install_dnf_packages(settings, &["clamav", "clamav-freshclam"])
            .context("Failed to install ClamAV via dnf");
    }

    // Debian/Ubuntu path
    if has_cmd("apt") || has_cmd("apt-get") {
        return install_apt_packages(settings, &["clamav", "clamav-daemon"])
            .context("Failed to install ClamAV via apt");
    }

    eyre::bail!("No supported package manager found (dnf, apt, or apt-get).");
}

fn update_defs(settings: DownloadSettings) -> eyre::Result<()> {
    if !has_cmd("freshclam") {
        eyre::bail!("freshclam not found. Install first: jj clam-av install");
    }

    run_in_settings(&settings, || -> eyre::Result<()> {
        system("freshclam").context("freshclam failed")?;
        Ok(())
    })
}

impl super::Command for ClamAv {
    fn execute(self) -> eyre::Result<()> {
        match self.cmd {
            ClamAvCmd::Install {
                use_download_shell,
                sneaky_ip,
                enable_epel,
            } => install_clamav(settings(use_download_shell, sneaky_ip), enable_epel)?,

            ClamAvCmd::Update {
                use_download_shell,
                sneaky_ip,
            } => update_defs(settings(use_download_shell, sneaky_ip))?,
        }
        Ok(())
    }
}
