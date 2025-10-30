use std::collections::HashMap;

use crate::pcre;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Distro {
    RedHat,
    Debian,
    Alpine,
    Other(String),
}

impl From<&str> for Distro {
    fn from(s: &str) -> Self {
        match s {
            "debian" => Distro::Debian,
            "redhat" => Distro::RedHat,
            "alpine" => Distro::Alpine,
            _ => Distro::Other(s.to_string()),
        }
    }
}

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
