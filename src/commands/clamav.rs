use std::net::Ipv4Addr;

use clap::{Parser, Subcommand};
use eyre::Context;

use crate::utils::{
    download_container::DownloadContainer,
    os_version::get_distro,
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
    /// - Debian-family: clamav + clamav-daemon
    /// - RHEL-family: clamav + clamav-freshclam (often requires EPEL on Rocky/RHEL)
    Install {
        /// Use the download shell / container for outbound traffic
        #[arg(long, short = 'd')]
        use_download_shell: bool,

        /// Sneaky IP to use when downloading packages
        #[arg(long, short)]
        sneaky_ip: Option<Ipv4Addr>,

        /// (RHEL-family) Attempt to enable EPEL if installation fails due to missing packages
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

/// Manual clone helper so we don't need to change DownloadSettings to derive Clone.
fn clone_settings(s: &DownloadSettings) -> DownloadSettings {
    match s {
        DownloadSettings::NoContainer => DownloadSettings::NoContainer,
        DownloadSettings::Container { name, sneaky_ip } => DownloadSettings::Container {
            name: name.clone(),
            sneaky_ip: *sneaky_ip,
        },
    }
}

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

fn dnf_makecache(settings: &DownloadSettings) -> eyre::Result<()> {
    run_in_settings(settings, || -> eyre::Result<()> {
        // Non-destructive; refreshes metadata so package availability is current.
        let _ = system("dnf -y makecache --refresh");
        Ok(())
    })
}

fn print_rhel_repo_diag(settings: &DownloadSettings) -> eyre::Result<()> {
    run_in_settings(settings, || -> eyre::Result<()> {
        eprintln!("\n--- dnf enabled repos (for debugging) ---");
        let _ = system("dnf -q repolist --enabled");
        eprintln!("--- dnf search clamav (for debugging) ---");
        let _ = system("dnf -q search clamav || true");
        eprintln!("----------------------------------------\n");
        Ok(())
    })
}

/// Enable EPEL by installing epel-release using the shared package installer.
/// This preserves `-d` container behavior and avoids direct `system("dnf install ...")` in command code.
fn maybe_enable_epel(settings: &DownloadSettings) -> eyre::Result<()> {
    // Installing epel-release should be idempotent (already installed => ok).
    install_dnf_packages(clone_settings(settings), &["epel-release"])
        .context("Failed to install epel-release (EPEL enable)")?;

    // After enabling, refresh metadata so newly added repos are visible.
    dnf_makecache(settings)?;

    Ok(())
}

fn install_clamav_dnf(settings: &DownloadSettings) -> eyre::Result<()> {
    dnf_makecache(settings)?;
    install_dnf_packages(clone_settings(settings), &["clamav", "clamav-freshclam"])
        .context("Failed to install ClamAV via dnf")
}

fn install_clamav(settings: DownloadSettings, enable_epel: bool) -> eyre::Result<()> {
    let distro = get_distro().ok();
    let is_rhel = distro.as_ref().map_or(false, |d| d.is_rhel_based());
    let is_deb = distro.as_ref().map_or(false, |d| d.is_deb_based());

    // Prefer RHEL path when appropriate
    if is_rhel || has_cmd("dnf") {
        if !has_cmd("dnf") {
            eyre::bail!("Detected RHEL-family but 'dnf' was not found on PATH.");
        }

        // 1) First attempt install
        match install_clamav_dnf(&settings) {
            Ok(()) => return Ok(()),
            Err(e) => {
                // 2) If requested, attempt EPEL and retry once
                if enable_epel {
                    eprintln!("ClamAV install failed; attempting to enable EPEL then retry...");
                    maybe_enable_epel(&settings).ok();
                    match install_clamav_dnf(&settings) {
                        Ok(()) => return Ok(()),
                        Err(e2) => {
                            // 3) Still failing -> print repo diagnostics and return useful error
                            let _ = print_rhel_repo_diag(&settings);
                            return Err(e2).wrap_err_with(|| {
                                "ClamAV install still failed after EPEL attempt. \
                                 Repos may not provide clamav for this OS/repo set, \
                                 or the host has repo restrictions/excludes."
                            });
                        }
                    }
                }

                // No EPEL attempt requested; return the original error.
                return Err(e);
            }
        }
    }

    // Debian-family path
    if is_deb || has_cmd("apt") || has_cmd("apt-get") {
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
