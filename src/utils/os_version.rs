//! Some actions have to change their behavior based on which Linux
//! distribution it's running on. Utilities in this module provide
//! the ability to determine which Linux distribution is being used
use std::collections::HashMap;

use crate::pcre;

#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(dead_code)]
pub enum OsFamily {
    Windows,
    RedHat,
    Debian,
    Alpine,
    Fedora,
    CentOS,
    Ubuntu,
    Arch,
    Rocky,
    Oracle,
    Other(String),
}

/// Cover the most important Linux distributions we come across
/// in competition
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Distro {
    pub root_family: OsFamily,
    pub derived_family: Option<OsFamily>,
}

#[allow(dead_code)]
impl Distro {
    pub fn is_deb_based(&self) -> bool {
        use OsFamily as OsF;
        self.root_family == OsF::Debian || self.derived_family == Some(OsF::Debian)
    }

    pub fn is_rhel_based(&self) -> bool {
        use OsFamily as OsF;
        matches!(self.root_family, OsF::RedHat | OsF::Fedora)
            || matches!(self.derived_family, Some(OsF::RedHat | OsF::Fedora))
    }

    pub fn is_rhel_or_deb_based(&self) -> bool {
        self.is_deb_based() || self.is_rhel_based()
    }

    pub fn is_windows(&self) -> bool {
        self.root_family == OsFamily::Windows
    }
}

impl From<&str> for OsFamily {
    fn from(s: &str) -> Self {
        let s = s.to_lowercase();

        if s.contains("rhel") || s.contains("redhat") {
            return OsFamily::RedHat;
        }
        if s.contains("debian") {
            return OsFamily::Debian;
        }
        if s.contains("alpine") {
            return OsFamily::Alpine;
        }
        if s.contains("arch") {
            return OsFamily::Arch;
        }
        if s.contains("centos") {
            return OsFamily::CentOS;
        }
        if s.contains("fedora") {
            return OsFamily::Fedora;
        }
        if s.contains("ubuntu") {
            return OsFamily::Ubuntu;
        }
        if s.contains("rocky") {
            return OsFamily::Rocky;
        }
        if s.contains("oracle") {
            return OsFamily::Oracle;
        }

        OsFamily::Other(s)
    }
}

/// Load the current distribution. May fail if there is a malformed
/// /etc/os-release file
#[cfg(unix)]
pub fn get_distro() -> eyre::Result<Distro> {
    let env = std::fs::read_to_string("/etc/os-release")?;

    let matches = pcre!(
        &env =~ m{r"([^=]+)=([^\n]+)"}gxms
    )
    .into_iter()
    .map(|c| c.extract::<2>().1)
    .map(|[k, v]| (k.trim(), v.trim()))
    .collect::<HashMap<_, _>>();

    let distro_like = matches.get(&"ID_LIKE").map(|d| OsFamily::from(*d));
    let distro = matches
        .get(&"ID")
        .map(|d| OsFamily::from(*d))
        .ok_or(eyre::eyre!("Could not identify current Linux distribution"))?;

    Ok(Distro {
        root_family: distro_like.clone().unwrap_or(distro.clone()),
        derived_family: distro_like.and(Some(distro)),
    })
}

/// Load the current distribution. May fail if there is a malformed
/// /etc/os-release file
#[cfg(windows)]
pub fn get_distro() -> eyre::Result<Distro> {
    Ok(Distro {
        root_family: OsFamily::Windows,
        derived_family: None,
    })
}
