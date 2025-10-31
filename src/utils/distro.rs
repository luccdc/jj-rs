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
    Other(String),
}

impl From<&str> for Distro {
    fn from(s: &str) -> Self {
        if s.contains("rhel") {
            return Distro::RedHat;
        }

        match s {
            "debian" => Distro::Debian,
            "redhat" | "rhel" => Distro::RedHat,
            "alpine" => Distro::Alpine,
            _ => Distro::Other(s.to_string()),
        }
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

    Ok(distro_like.or(distro))
}
