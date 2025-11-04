//! Some actions have to change their behavior based on which Linux
//! distribution it's running on. Utilities in this module provide
//! the ability to determine which Linux distribution is being used
use std::collections::HashMap;

use crate::pcre;

/// Cover the most important Linux distributions we come across
/// in competition
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Distro {
    RedHat,
    Debian,
    Alpine,
    Fedora,
    CentOS,
    Ubuntu,
    Arch,
    Other(String),
}

impl Distro {
    pub fn is_deb_based(&self) -> bool {
        matches!(self, Distro::Debian | Distro::Ubuntu)
    }

    pub fn is_rhel_based(&self) -> bool {
        matches!(self, Distro::RedHat | Distro::Fedora | Distro::CentOS)
    }

    pub fn is_rhel_or_deb_based(&self) -> bool {
        self.is_deb_based() || self.is_rhel_based()
    }
}

impl From<&str> for Distro {
    fn from(s: &str) -> Self {
        let s = s.to_lowercase();

        if s.contains("centos") {
            return Distro::CentOS;
        }
        if s.contains("fedora") {
            return Distro::Fedora;
        }
        if s.contains("ubuntu") {
            return Distro::Ubuntu;
        }
        if s.contains("debian") {
            return Distro::Debian;
        }
        if s.contains("rhel") || s.contains("redhat") {
            return Distro::RedHat;
        }
        if s.contains("alpine") {
            return Distro::Alpine;
        }
        if s.contains("arch") {
            return Distro::Arch;
        }

        return Distro::Other(s);
    }
}

/// Load the current distribution. May fail if there is a malformed
/// /etc/os-release file
pub fn get_distro() -> anyhow::Result<Option<Distro>> {
    let env = std::fs::read_to_string("/etc/os-release")?;

    let matches = pcre!(
        &env =~ m{r"([^=]+)=([^\n]+)"}gxms
    )
    .into_iter()
    .map(|c| c.extract::<2>().1)
    .map(|[k, v]| (k.trim(), v.trim()))
    .collect::<HashMap<_, _>>();

    let distro_like = matches.get(&"ID_LIKE").map(|d| Distro::from(*d));
    let distro = matches.get(&"ID").map(|d| Distro::from(*d));

    Ok(distro.or(distro_like))
}
