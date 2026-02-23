use std::net::IpAddr;
use std::str::FromStr;

#[derive(Debug, Clone)]
pub enum Host {
    Ip(IpAddr),
    Domain(String),
}

impl std::fmt::Display for Host {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Host::Ip(ip) => ip.fmt(f),
            Host::Domain(host) => host.fmt(f),
        }
    }
}

impl serde::Serialize for Host {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match &self {
            Host::Ip(i) => serializer.serialize_str(&format!("{}", i)),
            Host::Domain(s) => serializer.serialize_str(s),
        }
    }
}

impl<'de> serde::Deserialize<'de> for Host {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct HostVisitor;

        impl serde::de::Visitor<'_> for HostVisitor {
            type Value = Host;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("Host")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(v.into())
            }

            fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                self.visit_str(&v)
            }
        }

        deserializer.deserialize_str(HostVisitor)
    }
}

impl From<&str> for Host {
    fn from(v: &str) -> Self {
        match IpAddr::from_str(v) {
            Ok(ip) => Host::Ip(ip),
            _ => Host::Domain(v.to_owned()),
        }
    }
}

impl From<String> for Host {
    fn from(v: String) -> Self {
        match IpAddr::from_str(&v) {
            Ok(ip) => Host::Ip(ip),
            _ => Host::Domain(v),
        }
    }
}

impl Host {
    pub fn is_loopback(&self) -> bool {
        let common_loopbacks = [
            "localhost",
            "localhost.localdomain",
            "localhost4",
            "localhost4.localdomain4",
        ];

        match self {
            Host::Ip(ip) => ip.is_loopback(),
            Host::Domain(host) => {
                if common_loopbacks.contains(&host.as_str()) {
                    true
                } else {
                    false
                }
            }
        }
    }
}
