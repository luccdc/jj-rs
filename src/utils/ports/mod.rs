use std::net::IpAddr;

/// Used to differentiate socket records, as records from multiple
/// files in /proc might be mixed together
/// Or for Windows, multiple sockets from GetExtendedTcpTable or
/// GetExtendedUdpTable
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocketType {
    Tcp,
    Udp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocketState {
    Unknown,
    Established,
    SynSent,
    SynRecv,
    FinWait1,
    FinWait2,
    TimeWait,
    Closed,
    CloseWait,
    LastAck,
    Listen,
    Closing,
}

impl Default for SocketState {
    fn default() -> Self {
        Self::Unknown
    }
}

impl From<Option<SocketState>> for SocketState {
    fn from(value: Option<SocketState>) -> Self {
        value.unwrap_or_default()
    }
}

#[cfg(target_os = "linux")]
pub mod linux;

#[cfg(target_os = "linux")]
use linux::LinuxSocketRecord as OsSocketRecordImpl;

#[cfg(windows)]
pub mod windows;

#[cfg(windows)]
use windows::WindowsSocketRecord as OsSocketRecordImpl;

/// Trait to generalize and abstract over socket records for different
/// operating systems
pub trait OsSocketRecord {
    /// Is the socket a UDP or TCP socket
    fn socket_type(&self) -> SocketType;

    /// Getter for the local IP address associated with this socket
    fn local_addr(&self) -> IpAddr;

    /// Getter for the local port associated with this socket
    fn local_port(&self) -> u16;

    /// Getter for the remote IP address associated with this socket
    ///
    /// For listening TCP ports and all UDP ports (Windows) or listening UDP ports (Linux), this will be none
    fn remote_addr(&self) -> Option<IpAddr>;

    /// Getter for the remote port associated with this socket
    ///
    /// For listening TCP ports and all UDP ports (Windows) or listening UDP ports (Linux), this will be none
    fn remote_port(&self) -> Option<u16>;

    /// Getter for the current state of the network connection
    fn state(&self) -> SocketState;

    /// Getter for a potential PID for the process owning this socket
    ///
    /// Can be empty if jj is not run with the appropriate permissions
    fn pid(&self) -> Option<u64>;

    /// Getter for a potential command line for the process owning the socket
    ///
    /// Can be empty if jj is not run with the appropriate permissions
    fn cmdline(&self) -> Option<&str>;

    /// Getter for a potential executable name for the process owning the socket
    ///
    /// Can be empty if jj is not run with the appropriate permissions
    fn exe(&self) -> Option<&str>;
}

pub struct SocketRecord {
    inner: OsSocketRecordImpl,
}

#[allow(dead_code)]
impl SocketRecord {
    pub fn socket_type(&self) -> SocketType {
        self.inner.socket_type()
    }

    pub fn local_addr(&self) -> IpAddr {
        self.inner.local_addr()
    }

    pub fn local_port(&self) -> u16 {
        self.inner.local_port()
    }

    pub fn remote_addr(&self) -> Option<IpAddr> {
        self.inner.remote_addr()
    }

    pub fn remote_port(&self) -> Option<u16> {
        self.inner.remote_port()
    }

    pub fn state(&self) -> SocketState {
        self.inner.state()
    }

    pub fn pid(&self) -> Option<u64> {
        self.inner.pid()
    }

    pub fn cmdline(&self) -> Option<&str> {
        self.inner.cmdline()
    }

    pub fn exe(&self) -> Option<&str> {
        self.inner.exe()
    }
}
#[cfg(target_os = "linux")]
#[allow(dead_code)]
pub fn list_udp_ports() -> eyre::Result<Vec<SocketRecord>> {
    let inode_pids = linux::socket_inodes()?;
    let ports_raw = linux::parse_net_udp()?;
    let ports_enriched = linux::enrich_ip_stats(ports_raw, &inode_pids);
    Ok(ports_enriched
        .into_iter()
        .map(|inner| SocketRecord { inner })
        .collect())
}

#[cfg(target_os = "linux")]
#[allow(dead_code)]
pub fn list_tcp_ports() -> eyre::Result<Vec<SocketRecord>> {
    let inode_pids = linux::socket_inodes()?;
    let ports_raw = linux::parse_net_tcp()?;
    let ports_enriched = linux::enrich_ip_stats(ports_raw, &inode_pids);
    Ok(ports_enriched
        .into_iter()
        .map(|inner| SocketRecord { inner })
        .collect())
}

#[cfg(target_os = "linux")]
#[allow(dead_code)]
pub fn list_ports() -> eyre::Result<Vec<SocketRecord>> {
    let inode_pids = linux::socket_inodes()?;
    let ports_raw = linux::parse_ports()?;
    let ports_enriched = linux::enrich_ip_stats(ports_raw, &inode_pids);
    Ok(ports_enriched
        .into_iter()
        .map(|inner| SocketRecord { inner })
        .collect())
}

#[cfg(windows)]
pub fn list_ports() -> eyre::Result<Vec<SocketRecord>> {
    windows::list_ports().map(|p| p.into_iter().map(|inner| SocketRecord { inner }).collect())
}
