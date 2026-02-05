use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::Arc,
};

use windows::Win32::{
    Foundation::ERROR_INSUFFICIENT_BUFFER,
    NetworkManagement::IpHelper::{
        GetExtendedTcpTable, GetExtendedUdpTable, MIB_TCP6TABLE_OWNER_PID, MIB_TCPTABLE_OWNER_PID,
        MIB_UDP6TABLE_OWNER_PID, MIB_UDPTABLE_OWNER_PID, TCP_TABLE_OWNER_PID_ALL,
        UDP_TABLE_OWNER_PID,
    },
    Networking::WinSock::{AF_INET, AF_INET6},
    System::{
        ProcessStatus::GetProcessImageFileNameA,
        Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION},
    },
};

use super::{SocketState, SocketType};

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct WindowsSocketRecord {
    pub socket_type: SocketType,
    pub local_address: IpAddr,
    pub local_port: u16,
    pub remote_address: Option<IpAddr>,
    pub remote_port: Option<u16>,
    pub state: SocketState,
    pub pid: Option<u32>,
    pub image: Option<Arc<str>>,
    pub cmdline: Option<Arc<str>>,
}

impl super::OsSocketRecord for WindowsSocketRecord {
    fn socket_type(&self) -> SocketType {
        self.socket_type
    }

    fn local_addr(&self) -> IpAddr {
        self.local_address
    }

    fn local_port(&self) -> u16 {
        self.local_port
    }

    fn remote_addr(&self) -> Option<IpAddr> {
        self.remote_address
    }

    fn remote_port(&self) -> Option<u16> {
        self.remote_port
    }

    fn state(&self) -> super::SocketState {
        self.state.into()
    }

    fn cmdline(&self) -> Option<&str> {
        self.cmdline.as_deref()
    }

    fn pid(&self) -> Option<u64> {
        self.pid.map(|p| p as u64)
    }

    fn exe(&self) -> Option<&str> {
        self.image.as_deref()
    }
}

#[derive(Default)]
struct WinProc {
    image: Option<Arc<str>>,
    cmdline: Option<Arc<str>>,
}

fn unicode_to_std(w16: &windows::Win32::Foundation::UNICODE_STRING) -> String {
    let bytes = unsafe { std::slice::from_raw_parts(w16.Buffer.0, w16.Length as usize) };
    String::from_utf16_lossy(bytes)
}

unsafe fn get_winproc_info(pid: u32) -> Option<WinProc> {
    let proc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).ok()?;

    let mut image_name = [0; 1024];

    let len = GetProcessImageFileNameA(proc, &mut image_name) as usize;

    let image: Arc<str> = String::from_utf8_lossy(&image_name[..len])
        .to_string()
        .into();

    Some(WinProc {
        image: Some(Arc::clone(&image)),
        cmdline: Some(image),
    })
}

fn get_state(dwState: u32) -> SocketState {
    match dwState {
        1 => SocketState::Closed,
        2 => SocketState::Listen,
        3 => SocketState::SynSent,
        4 => SocketState::SynRecv,
        5 => SocketState::Established,
        6 => SocketState::FinWait1,
        7 => SocketState::FinWait2,
        8 => SocketState::CloseWait,
        9 => SocketState::Closing,
        10 => SocketState::LastAck,
        11 => SocketState::TimeWait,
        _ => SocketState::Unknown,
    }
}

unsafe fn get_tcp_ports(
    proc_list: &mut HashMap<u32, WinProc>,
) -> eyre::Result<Vec<WindowsSocketRecord>> {
    let mut tcptable = vec![0; 4096];
    let mut size = 4096u32;

    let res = GetExtendedTcpTable(
        Some(tcptable.as_mut_ptr() as _),
        &mut size as _,
        true,
        AF_INET.0.into(),
        TCP_TABLE_OWNER_PID_ALL,
        0,
    );

    match res {
        0 => {}
        v if v == ERROR_INSUFFICIENT_BUFFER.0 => {
            tcptable = vec![0; size as usize];

            let res = GetExtendedTcpTable(
                Some(tcptable.as_mut_ptr() as _),
                &mut size as _,
                true,
                AF_INET.0.into(),
                TCP_TABLE_OWNER_PID_ALL,
                0,
            );

            match res {
                0 => {}
                v => {
                    eyre::bail!("Unknown error: {v}");
                }
            }
        }
        v => {
            eyre::bail!("Unknown error: {v}");
        }
    }

    let table = &*(tcptable.as_ptr() as *const MIB_TCPTABLE_OWNER_PID);
    let entries = std::slice::from_raw_parts(table.table.as_ptr(), table.dwNumEntries as usize);

    let mut current = 0;

    Ok(entries
        .iter()
        .filter_map(|entry| {
            current += 1;
            let (cmdline, image) = if entry.dwOwningPid != 0 {
                let winproc = proc_list
                    .entry(entry.dwOwningPid)
                    .or_insert_with(|| get_winproc_info(entry.dwOwningPid).unwrap_or_default());

                (
                    winproc.cmdline.as_ref().map(Arc::clone),
                    winproc.image.as_ref().map(Arc::clone),
                )
            } else {
                (None, None)
            };

            Some(WindowsSocketRecord {
                socket_type: SocketType::Tcp,
                local_address: Ipv4Addr::from(entry.dwLocalAddr.swap_bytes()).into(),
                local_port: u16::swap_bytes(entry.dwLocalPort.try_into().ok()?),
                remote_address: Some(Ipv4Addr::from(entry.dwRemoteAddr.swap_bytes()).into())
                    .filter(|addr: &IpAddr| !addr.is_unspecified()),
                remote_port: entry
                    .dwRemotePort
                    .try_into()
                    .ok()
                    .filter(|p| *p != 0)
                    .map(u16::swap_bytes),
                pid: Some(entry.dwOwningPid).filter(|p| *p != 0),
                state: get_state(entry.dwState),
                cmdline,
                image,
            })
        })
        .collect())
}

unsafe fn get_tcp6_ports(
    proc_list: &mut HashMap<u32, WinProc>,
) -> eyre::Result<Vec<WindowsSocketRecord>> {
    let mut tcptable = vec![0; 4096];
    let mut size = 4096u32;

    let res = GetExtendedTcpTable(
        Some(tcptable.as_mut_ptr() as _),
        &mut size as _,
        true,
        AF_INET6.0.into(),
        TCP_TABLE_OWNER_PID_ALL,
        0,
    );

    match res {
        0 => {}
        v if v == ERROR_INSUFFICIENT_BUFFER.0 => {
            tcptable = vec![0; size as usize];

            let res = GetExtendedTcpTable(
                Some(tcptable.as_mut_ptr() as _),
                &mut size as _,
                true,
                AF_INET6.0.into(),
                TCP_TABLE_OWNER_PID_ALL,
                0,
            );

            match res {
                0 => {}
                v => {
                    eyre::bail!("Unknown error: {v}");
                }
            }
        }
        v => {
            eyre::bail!("Unknown error: {v}");
        }
    }

    let table = &*(tcptable.as_ptr() as *const MIB_TCP6TABLE_OWNER_PID);
    let entries = std::slice::from_raw_parts(table.table.as_ptr(), table.dwNumEntries as usize);

    let mut current = 0;

    Ok(entries
        .iter()
        .filter_map(|entry| {
            current += 1;
            let (cmdline, image) = if entry.dwOwningPid != 0 {
                let winproc = proc_list
                    .entry(entry.dwOwningPid)
                    .or_insert_with(|| get_winproc_info(entry.dwOwningPid).unwrap_or_default());

                (
                    winproc.cmdline.as_ref().map(Arc::clone),
                    winproc.image.as_ref().map(Arc::clone),
                )
            } else {
                (None, None)
            };

            Some(WindowsSocketRecord {
                socket_type: SocketType::Tcp,
                local_address: Ipv6Addr::from_octets(entry.ucLocalAddr).into(),
                local_port: u16::swap_bytes(entry.dwLocalPort.try_into().ok()?),
                remote_address: Some(Ipv6Addr::from_octets(entry.ucRemoteAddr).into())
                    .filter(|addr: &IpAddr| !addr.is_unspecified()),
                remote_port: entry
                    .dwRemotePort
                    .try_into()
                    .ok()
                    .filter(|p| *p != 0)
                    .map(u16::swap_bytes),
                pid: Some(entry.dwOwningPid).filter(|p| *p != 0),
                state: get_state(entry.dwState),
                cmdline,
                image,
            })
        })
        .collect())
}

unsafe fn get_udp_ports(
    proc_list: &mut HashMap<u32, WinProc>,
) -> eyre::Result<Vec<WindowsSocketRecord>> {
    let mut udptable = vec![0; 4096];
    let mut size = 4096u32;

    let res = GetExtendedUdpTable(
        Some(udptable.as_mut_ptr() as _),
        &mut size as _,
        true,
        AF_INET.0.into(),
        UDP_TABLE_OWNER_PID,
        0,
    );

    match res {
        0 => {}
        v if v == ERROR_INSUFFICIENT_BUFFER.0 => {
            udptable = vec![0; size as usize];

            let res = GetExtendedUdpTable(
                Some(udptable.as_mut_ptr() as _),
                &mut size as _,
                true,
                AF_INET.0.into(),
                UDP_TABLE_OWNER_PID,
                0,
            );

            match res {
                0 => {}
                v => {
                    eyre::bail!("Unknown error: {v}");
                }
            }
        }
        v => {
            eyre::bail!("Unknown error: {v}");
        }
    }

    let table = &*(udptable.as_ptr() as *const MIB_UDPTABLE_OWNER_PID);
    let entries = std::slice::from_raw_parts(table.table.as_ptr(), table.dwNumEntries as usize);

    let mut current = 0;

    Ok(entries
        .iter()
        .filter_map(|entry| {
            current += 1;
            let (cmdline, image) = if entry.dwOwningPid != 0 {
                let winproc = proc_list
                    .entry(entry.dwOwningPid)
                    .or_insert_with(|| get_winproc_info(entry.dwOwningPid).unwrap_or_default());

                (
                    winproc.cmdline.as_ref().map(Arc::clone),
                    winproc.image.as_ref().map(Arc::clone),
                )
            } else {
                (None, None)
            };

            Some(WindowsSocketRecord {
                socket_type: SocketType::Udp,
                local_address: Ipv4Addr::from(entry.dwLocalAddr.swap_bytes()).into(),
                local_port: u16::swap_bytes(entry.dwLocalPort.try_into().ok()?),
                remote_address: None,
                remote_port: None,
                pid: Some(entry.dwOwningPid).filter(|p| *p != 0),
                state: SocketState::Unknown,
                cmdline,
                image,
            })
        })
        .collect())
}

unsafe fn get_udp6_ports(
    proc_list: &mut HashMap<u32, WinProc>,
) -> eyre::Result<Vec<WindowsSocketRecord>> {
    let mut udptable = vec![0; 4096];
    let mut size = 4096u32;

    let res = GetExtendedUdpTable(
        Some(udptable.as_mut_ptr() as _),
        &mut size as _,
        true,
        AF_INET6.0.into(),
        UDP_TABLE_OWNER_PID,
        0,
    );

    match res {
        0 => {}
        v if v == ERROR_INSUFFICIENT_BUFFER.0 => {
            udptable = vec![0; size as usize];

            let res = GetExtendedUdpTable(
                Some(udptable.as_mut_ptr() as _),
                &mut size as _,
                true,
                AF_INET6.0.into(),
                UDP_TABLE_OWNER_PID,
                0,
            );

            match res {
                0 => {}
                v => {
                    eyre::bail!("Unknown error: {v}");
                }
            }
        }
        v => {
            eyre::bail!("Unknown error: {v}");
        }
    }

    let table = &*(udptable.as_ptr() as *const MIB_UDP6TABLE_OWNER_PID);
    let entries = std::slice::from_raw_parts(table.table.as_ptr(), table.dwNumEntries as usize);

    let mut current = 0;

    Ok(entries
        .iter()
        .filter_map(|entry| {
            current += 1;
            let (cmdline, image) = if entry.dwOwningPid != 0 {
                let winproc = proc_list
                    .entry(entry.dwOwningPid)
                    .or_insert_with(|| get_winproc_info(entry.dwOwningPid).unwrap_or_default());

                (
                    winproc.cmdline.as_ref().map(Arc::clone),
                    winproc.image.as_ref().map(Arc::clone),
                )
            } else {
                (None, None)
            };

            Some(WindowsSocketRecord {
                socket_type: SocketType::Udp,
                local_address: Ipv6Addr::from_octets(entry.ucLocalAddr).into(),
                local_port: u16::swap_bytes(entry.dwLocalPort.try_into().ok()?),
                remote_address: None,
                remote_port: None,
                pid: Some(entry.dwOwningPid).filter(|p| *p != 0),
                state: SocketState::Unknown,
                cmdline,
                image,
            })
        })
        .collect())
}

pub fn list_ports() -> eyre::Result<Vec<WindowsSocketRecord>> {
    let mut procs = HashMap::new();

    unsafe {
        let tcp4 = get_tcp_ports(&mut procs)?;
        let tcp6 = get_tcp6_ports(&mut procs)?;
        let udp4 = get_udp_ports(&mut procs)?;
        let udp6 = get_udp6_ports(&mut procs)?;

        Ok([tcp4, tcp6, udp4, udp6].concat())
    }
}
