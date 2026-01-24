//! Not all checks have to be reimplemented from the ground up. This module
//! includes building blocks for applying simple checks or applying filters
//! to checks

#[cfg(target_os = "linux")]
mod binary_ports_check;
mod check_fn;
mod filter_check;
#[cfg(target_os = "linux")]
mod immediate_tcpdump_check;
#[cfg(target_os = "linux")]
mod pam_check;
#[cfg(target_os = "linux")]
mod passive_tcpdump_check;
mod service_checks;
mod tcp_connect_check;

#[cfg(target_os = "linux")]
pub use binary_ports_check::*;
pub use check_fn::*;
pub use filter_check::*;
#[cfg(target_os = "linux")]
pub use immediate_tcpdump_check::*;
#[cfg(target_os = "linux")]
pub use pam_check::*;
#[cfg(target_os = "linux")]
pub use passive_tcpdump_check::*;
pub use service_checks::*;
pub use tcp_connect_check::*;

/// Option used to configure the layer 4 protocol
#[derive(Clone, Debug, PartialEq, Eq, Copy)]
#[allow(dead_code)]
pub enum CheckIpProtocol {
    Tcp,
    Udp,
}

impl CheckIpProtocol {
    fn from_int(i: u8) -> Option<Self> {
        match i {
            6 => Some(CheckIpProtocol::Tcp),
            17 => Some(CheckIpProtocol::Udp),
            _ => None,
        }
    }
}

#[cfg(unix)]
struct TcpdumpCodec;

#[cfg(unix)]
impl pcap::PacketCodec for TcpdumpCodec {
    type Item = (pcap::PacketHeader, Vec<u8>);

    fn decode(&mut self, p: pcap::Packet<'_>) -> Self::Item {
        (*p.header, p.data.to_owned())
    }
}
