//! Utilities to install packages
//!
//! Utilities are built using the download container and package manager to download
//! packages, and then use the package manager to further install packages

use std::{net::Ipv4Addr, os::unix::fs::PermissionsExt};

use eyre::Context;
use nix::{
    mount::{MsFlags, mount},
    sched::{CloneFlags, unshare},
};

use crate::utils::{busybox::Busybox, download_container::DownloadContainer, system};

pub enum DownloadSettings {
    NoContainer,
    Container {
        name: Option<String>,
        sneaky_ip: Option<Ipv4Addr>,
    },
}

/// Download and install apt packages
pub fn install_apt_packages<S: AsRef<str>>(
    settings: DownloadSettings,
    packages: &[S],
) -> eyre::Result<()> {
    unshare(CloneFlags::CLONE_NEWNS).context("Could not unshare to get mount namespace")?;

    let bb = Busybox::new()?;
    let file_raw = bb.execute(&["mktemp"])?;
    let file = file_raw.trim();
    std::fs::write(file, "nameserver 1.1.1.1")?;
    std::fs::set_permissions(file, PermissionsExt::from_mode(0o555))?;

    mount(
        None::<&str>,
        "/",
        None::<&str>,
        MsFlags::MS_REC | MsFlags::MS_PRIVATE,
        None::<&str>,
    )?;

    mount(
        Some(file),
        "/etc/resolv.conf",
        None::<&str>,
        MsFlags::MS_BIND,
        None::<&str>,
    )?;

    let lists_raw = bb.execute(&["mktemp", "-d"])?;
    let lists = lists_raw.trim();
    let archives_raw = bb.execute(&["mktemp", "-d"])?;
    let archives = archives_raw.trim();

    mount(
        Some(lists),
        "/var/lib/apt/lists",
        None::<&str>,
        MsFlags::MS_BIND,
        None::<&str>,
    )?;

    mount(
        Some(archives),
        "/var/cache/apt/",
        None::<&str>,
        MsFlags::MS_BIND,
        None::<&str>,
    )?;

    match settings {
        DownloadSettings::Container { name, sneaky_ip } => {
            let container = DownloadContainer::new(name, sneaky_ip)?;

            container.run(|| -> eyre::Result<()> {
                system("apt update")?;

                system(&format!(
                    "apt install --download-only -y {}",
                    packages
                        .iter()
                        .map(AsRef::as_ref)
                        .collect::<Vec<_>>()
                        .join(" ")
                ))?;

                Ok(())
            })??;
        }
        DownloadSettings::NoContainer => {
            system("apt update")?;

            system(&format!(
                "apt install --download-only -y {}",
                packages
                    .iter()
                    .map(AsRef::as_ref)
                    .collect::<Vec<_>>()
                    .join(" ")
            ))?;
        }
    }

    let downloaded_package_paths = std::fs::read_dir("/var/cache/apt/archives")?
        .flat_map(|entry| entry)
        .flat_map(|entry| entry.file_name().into_string())
        .filter(|entry| entry.ends_with(".deb"))
        .map(|entry| format!("/var/cache/apt/archives/{entry}"))
        .collect::<Vec<_>>();

    system(&format!(
        "apt install -y {}",
        downloaded_package_paths.join(" ")
    ))?;

    let _ = std::fs::remove_dir_all(archives);
    let _ = std::fs::remove_dir_all(lists);

    Ok(())
}

/// Download and install DNF packages
pub fn install_dnf_packages<S: AsRef<str>>(
    settings: DownloadSettings,
    packages: &[S],
) -> eyre::Result<()> {
    let bb = Busybox::new()?;
    let packages_dir_raw = bb.execute(&["mktemp", "-d"])?;
    let packages_dir = packages_dir_raw.trim();

    dbg!(packages.iter().map(AsRef::as_ref).collect::<Vec<_>>());

    match settings {
        DownloadSettings::Container { name, sneaky_ip } => {
            let container = DownloadContainer::new(name, sneaky_ip)?;

            container.run(|| -> eyre::Result<()> {
                std::process::Command::new("/bin/sh")
                    .args([
                        "-c",
                        &format!(
                            "dnf download --resolve {}",
                            packages
                                .iter()
                                .map(AsRef::as_ref)
                                .collect::<Vec<_>>()
                                .join(" ")
                        ),
                    ])
                    .current_dir(&packages_dir)
                    .spawn()
                    .context("Could not spawn sh")?
                    .wait()
                    .context("Could not wait for command to finish")?;

                Ok(())
            })??;
        }
        DownloadSettings::NoContainer => {
            std::process::Command::new("/bin/sh")
                .args([
                    "-c",
                    &format!(
                        "dnf download --resolve {}",
                        packages
                            .iter()
                            .map(AsRef::as_ref)
                            .collect::<Vec<_>>()
                            .join(" ")
                    ),
                ])
                .current_dir(&packages_dir)
                .spawn()
                .context("Could not spawn sh")?
                .wait()
                .context("Could not wait for command to finish")?;
        }
    }

    let downloaded_package_paths = std::fs::read_dir(&packages_dir)?
        .flat_map(|entry| entry)
        .flat_map(|entry| entry.file_name().into_string())
        .filter(|entry| entry.ends_with(".rpm"))
        .map(|entry| format!("{packages_dir}/{entry}"))
        .collect::<Vec<_>>();

    system(&format!(
        "dnf install -y {}",
        downloaded_package_paths.join(" ")
    ))?;

    Ok(())
}
