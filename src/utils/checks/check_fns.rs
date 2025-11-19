//! Not all checks have to be reimplemented from the ground up. This module
//! includes building blocks for applying simple checks or applying filters
//! to checks

mod binary_ports_check;
mod check_fn;
mod filter_check;
mod immediate_tcpdump_check;
mod pam_check;
mod passive_tcpdump_check;
mod service_checks;
mod tcp_connect_check;

pub use binary_ports_check::*;
pub use check_fn::*;
pub use filter_check::*;
pub use immediate_tcpdump_check::*;
pub use pam_check::*;
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

struct TcpdumpCodec;

impl pcap::PacketCodec for TcpdumpCodec {
    type Item = (pcap::PacketHeader, Vec<u8>);

    fn decode(&mut self, p: pcap::Packet<'_>) -> Self::Item {
        (*p.header, p.data.to_owned())
    }
}
