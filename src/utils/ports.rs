use std::{collections::HashMap, net::Ipv4Addr};

use anyhow::Context;
use nix::fcntl::readlink;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
#[allow(non_camel_case_types)]
pub enum TcpStates {
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

impl From<u8> for TcpStates {
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

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct TcpSocketRecord {
    pub local_address: Ipv4Addr,
    pub local_port: u16,
    pub remote_address: Ipv4Addr,
    pub remote_port: u16,
    pub state: TcpStates,
    pub inode: u64,
    pub pid: Option<u64>,
    pub cmdline: Option<String>,
    pub cgroup: Option<String>,
}

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

pub fn parse_net_tcp() -> anyhow::Result<Vec<TcpSocketRecord>> {
    let inode_pids = socket_inodes()?;
    let tcp_sockets = std::fs::read_to_string("/proc/net/tcp")?;

    let regex = regex::Regex::new(
        r"(?xms)
        \s+
        [0-9]+: \s+
        ([0-9A-F]{8}):([0-9A-F]{4}) \s+
        ([0-9A-F]{8}):([0-9A-F]{4}) \s+
        ([0-9A-F]{2}) \s+
        ([0-9A-F]{8}):([0-9A-F]{8}) \s+
        ([0-9A-F]{2}):([0-9A-F]{8}) \s+
        ([0-9A-F]{8}) \s+
        ([0-9]+) \s+
        ([0-9]+) \s+
        ([0-9]+) \s+
    ",
    )?;

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
             -> anyhow::Result<TcpSocketRecord> {
                let inode = inode.parse()?;
                let pid = inode_pids.get(&inode).cloned();

                let cmdline = pid
                    .and_then(|p| std::fs::read_to_string(format!("/proc/{p}/cmdline")).ok())
                    .map(|cmd| cmd.replace("\0", " "));

                let cgroup = pid
                    .and_then(|p| std::fs::read_to_string(format!("/proc/{p}/cgroup")).ok())
                    .map(|cg| cg.trim_end().to_string());

                let local_address: u32 = u32::from_be(u32::from_str_radix(loc_addr, 16)?);
                let remote_address: u32 = u32::from_be(u32::from_str_radix(rem_addr, 16)?);

                Ok(TcpSocketRecord {
                    local_address: local_address.into(),
                    local_port: u16::from_str_radix(loc_port, 16)?,
                    remote_address: remote_address.into(),
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
