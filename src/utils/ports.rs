//! A collection of utilities designed around querying open ports
//!
//! The `ss -peanut` command loads data from the /proc filesystem,
//! and the utilities in this module do so as well.

use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    path::Path,
};

use anyhow::Context;
use nix::fcntl::readlink;
use num_traits::{Num, PrimInt};

/// Used to differentiate socket records, as records from multiple
/// files in /proc might be mixed together
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocketType {
    Tcp,
    Udp,
}

/// Mirrors the states [used internally](https://github.com/iproute2/iproute2/blob/ca756f36a0c6d24ab60657f8d14312c17443e5f0/misc/ss.c#L222-L238) for `ss`
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
#[allow(non_camel_case_types)]
pub enum SocketState {
    UNKNOWN,
    ESTABLISHED,
    SYN_SENT,
    SYN_RECV,
    FIN_WAIT1,
    FIN_WAIT2,
    TIME_WAIT,
    CLOSE,
    CLOSE_WAIT,
    LAST_ACK,
    LISTEN,
    CLOSING,
    NEW_SYN_RECV,
    BOUND_INACTIVE,
    MAX_STATES,
}

impl From<u8> for SocketState {
    fn from(value: u8) -> Self {
        match value {
            1 => Self::ESTABLISHED,
            2 => Self::SYN_SENT,
            3 => Self::SYN_RECV,
            4 => Self::FIN_WAIT1,
            5 => Self::FIN_WAIT2,
            6 => Self::TIME_WAIT,
            7 => Self::CLOSE,
            8 => Self::CLOSE_WAIT,
            9 => Self::LAST_ACK,
            10 => Self::LISTEN,
            11 => Self::CLOSING,
            12 => Self::NEW_SYN_RECV,
            13 => Self::BOUND_INACTIVE,
            14 => Self::MAX_STATES,

            _ => Self::UNKNOWN,
        }
    }
}

/// Represents fields selected from `/proc/net/tcp` and `/proc/net/udp`
///
/// <https://www.kernel.org/doc/Documentation/networking/proc_net_tcp.txt>
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct SocketRecord {
    pub socket_type: SocketType,
    pub local_address: IpAddr,
    pub local_port: u16,
    pub remote_address: IpAddr,
    pub remote_port: u16,
    pub state: SocketState,
    pub inode: u64,
    pub pid: Option<u64>,
    pub cmdline: Option<String>,
    pub cgroup: Option<String>,
}

/// Returns a mapping of inodes to the process ID that has the inode
pub fn socket_inodes() -> anyhow::Result<HashMap<u64, u64>> {
    let dir_re = regex::Regex::new(r"[0-9]+")?;
    let socket_re = regex::Regex::new(r"socket:\[([0-9]+)\]")?;

    Ok(std::fs::read_dir("/proc")
        .context("Could not open /proc")?
        .filter_map(|entry| {
            entry
                .ok()
                .map(|dir| dir.file_name().to_string_lossy().to_string())
        })
        .filter(|dir| dir_re.is_match(&dir))
        .flat_map(|dir| {
            std::fs::read_dir(format!("/proc/{dir}/fd"))
                .into_iter()
                .flatten()
                .into_iter()
                .flatten()
                .filter_map({
                    let dir = dir.clone();
                    let socket_re = &socket_re;
                    move |fd| -> Option<(u64, u64)> {
                        let fd_name = fd.file_name().to_string_lossy().to_string();
                        let path = format!("/proc/{}/fd/{}", dir, fd_name);
                        let link = readlink(&*path).ok()?.to_string_lossy().to_string();

                        let inode_str = socket_re.captures(&link)?.extract::<1>().1[0];

                        dir.parse()
                            .and_then(|pid| inode_str.parse().map(|inode| (inode, pid)))
                            .ok()
                    }
                })
        })
        .collect())
}

trait IpSize: From<Self::Size> {
    type Size: Num + PrimInt + std::fmt::Debug;
    const HEX_COUNT: &str;
}

impl IpSize for Ipv4Addr {
    type Size = u32;
    const HEX_COUNT: &str = "8";
}

impl IpSize for Ipv6Addr {
    type Size = u128;
    const HEX_COUNT: &str = "32";
}

/// Parse statistics from a file such as /proc/net/tcp or /proc/net/udp
fn parse_ip_stats<P, A>(path: P, socket_type: SocketType) -> anyhow::Result<Vec<SocketRecord>>
where
    P: AsRef<Path>,
    A: IpSize + Into<IpAddr>,
    <<A as IpSize>::Size as Num>::FromStrRadixErr: 'static + std::error::Error + Send + Sync,
{
    let inode_pids = socket_inodes()?;

    let tcp_sockets = std::fs::read_to_string(path)?;

    let regex = regex::Regex::new(&format!(
        r"(?xms)
        \s+
        [0-9]+: \s+
        ([0-9A-F]{{{}}}):([0-9A-F]{{4}}) \s+
        ([0-9A-F]{{{}}}):([0-9A-F]{{4}}) \s+
        ([0-9A-F]{{2}}) \s+
        ([0-9A-F]{{8}}):([0-9A-F]{{8}}) \s+
        ([0-9A-F]{{2}}):([0-9A-F]{{8}}) \s+
        ([0-9A-F]{{8}}) \s+
        ([0-9]+) \s+
        ([0-9]+) \s+
        ([0-9]+) \s+
    ",
        A::HEX_COUNT,
        A::HEX_COUNT
    ))?;

    let results = regex
        .captures_iter(&tcp_sockets)
        .map(|row| row.extract().1)
        .map(
            |[
                loc_addr,
                loc_port,
                rem_addr,
                rem_port,
                stat,
                _tx_queue,
                _rx_queue,
                _tr,
                _tmwhen,
                _retrnsmt,
                _uid,
                _timeout,
                inode,
            ]|
             -> anyhow::Result<SocketRecord> {
                let inode = inode.parse()?;
                let pid = inode_pids.get(&inode).cloned();

                let cmdline = pid
                    .and_then(|p| std::fs::read_to_string(format!("/proc/{p}/cmdline")).ok())
                    .map(|cmd| cmd.replace("\0", " "));

                let cgroup = pid
                    .and_then(|p| std::fs::read_to_string(format!("/proc/{p}/cgroup")).ok())
                    .map(|cg| cg.trim_end().to_string());

                let local_address = A::Size::from_be(A::Size::from_str_radix(loc_addr, 16)?);
                let remote_address = A::Size::from_be(A::Size::from_str_radix(rem_addr, 16)?);

                Ok(SocketRecord {
                    socket_type,
                    local_address: A::from(local_address).into(),
                    local_port: u16::from_str_radix(loc_port, 16)?,
                    remote_address: A::from(remote_address).into(),
                    remote_port: u16::from_str_radix(rem_port, 16)?,
                    state: u8::from_str_radix(stat, 16)?.into(),
                    inode,
                    pid,
                    cmdline,
                    cgroup,
                })
            },
        )
        .collect::<Result<Vec<_>, _>>()?;

    Ok(results)
}

/// Shortcut to parse statistics from /proc/net/tcp
#[allow(dead_code)]
pub fn parse_net_tcp() -> anyhow::Result<Vec<SocketRecord>> {
    Ok([
        parse_ip_stats::<_, Ipv4Addr>("/proc/net/tcp", SocketType::Tcp)?,
        parse_ip_stats::<_, Ipv6Addr>("/proc/net/tcp6", SocketType::Tcp)?,
    ]
    .concat())
}

/// Shortcut to parse statistics from /proc/net/udp
#[allow(dead_code)]
pub fn parse_net_udp() -> anyhow::Result<Vec<SocketRecord>> {
    Ok([
        parse_ip_stats::<_, Ipv4Addr>("/proc/net/udp", SocketType::Udp)?,
        parse_ip_stats::<_, Ipv6Addr>("/proc/net/udp6", SocketType::Udp)?,
    ]
    .concat())
}

/// Shortcut to parse statistics from both /proc/net/tcp and /proc/net/udp
pub fn parse_ports() -> anyhow::Result<Vec<SocketRecord>> {
    Ok([
        parse_ip_stats::<_, Ipv4Addr>("/proc/net/tcp", SocketType::Tcp)?,
        parse_ip_stats::<_, Ipv6Addr>("/proc/net/udp", SocketType::Udp)?,
        parse_ip_stats::<_, Ipv4Addr>("/proc/net/tcp6", SocketType::Tcp)?,
        parse_ip_stats::<_, Ipv6Addr>("/proc/net/tcp6", SocketType::Udp)?,
    ]
    .concat())
}
