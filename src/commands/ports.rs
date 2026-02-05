use std::{collections::HashSet, io::Write, net::IpAddr, path::PathBuf};

use clap::Parser;

use crate::utils::{
    pager,
    ports::{self, SocketRecord, SocketState, SocketType},
};

/// Query the system for network status and display results
#[derive(Parser, Debug, Default)]
#[command(version, about)]
pub struct Ports {
    /// Do not use less to page the output
    #[cfg(target_os = "linux")]
    #[arg(long, short = 'n')]
    pub no_pager: bool,

    /// Don't group results, grouping PID, type, and ports
    #[arg(long, short = 'G')]
    pub no_grouping: bool,

    /// Display the command line as opposed to just the executable
    #[arg(long, short = 'c')]
    pub display_cmdline: bool,

    /// Display established connections. Defaults to only displaying listening connections
    #[arg(long, short = 'e')]
    pub display_established: bool,

    /// Display listening connections. Defaults to only displaying listening connections
    #[arg(long, short = 'l')]
    pub display_listening: bool,

    /// Hide the path to the executable, just showing the binary name
    #[arg(long, short = 'p')]
    pub hide_path: bool,

    /// Display the cgroup the process is a part of
    #[cfg(target_os = "linux")]
    #[arg(long, short = 'g')]
    pub display_cgroup: bool,

    /// Display TCP sockets. Defaults to only displaying TCP sockets
    #[arg(long, short = 't')]
    pub display_tcp: bool,

    /// Display UDP sockets. Defaults to only displaying TCP sockets
    #[arg(long, short = 'u')]
    pub display_udp: bool,

    /// Display all TCP/UDP, IPv4/IPv6 sockets, regardless of state
    #[arg(long, short = 'a')]
    pub display_all: bool,

    /// Display only IPv4 sockets
    #[arg(long, short = '4')]
    pub display_ipv4: bool,

    /// Display only IPv6 sockets
    #[arg(long, short = '6')]
    pub display_ipv6: bool,
}

impl super::Command for Ports {
    fn execute(self) -> eyre::Result<()> {
        #[cfg(target_os = "linux")]
        let mut ob = pager::get_pager_output(self.no_pager);
        #[cfg(windows)]
        let mut ob = pager::get_pager_output(true);
        self.run(&mut ob)
    }
}

struct PortGroups {
    pids: HashSet<u64>,
    local_addr: HashSet<IpAddr>,
    local_port_start: u16,
    local_port_end: u16,
    remote_addr: Option<IpAddr>,
    remote_port: Option<u16>,
    cmd: String,
    state: SocketState,
    socket_type: HashSet<SocketType>,
}

struct RenderPortGroups {
    pids: String,
    local_addr: String,
    local_port: String,
    remote_addr: String,
    remote_port: String,
    cmd: String,
    state: String,
    socket_type: String,
}

impl Ports {
    pub fn run(self, out: &mut impl Write) -> eyre::Result<()> {
        let mut ports = ports::list_ports()?;

        ports.sort_by_key(|r| (r.local_port(), r.local_addr()));

        let Ports {
            display_listening,
            display_established,
            display_tcp,
            display_udp,
            display_all,
            display_ipv4,
            display_ipv6,
            ..
        } = self;
        let display_listening = display_listening || !display_established;
        let display_tcp = display_tcp || !display_udp;
        let (display_ipv4, display_ipv6) =
            (display_ipv4 || !display_ipv6, display_ipv6 || !display_ipv4);

        #[cfg(target_os = "linux")]
        let reducer = reduce_port_list(
            !self.no_grouping,
            self.display_cmdline,
            self.hide_path,
            self.display_cgroup,
        );
        #[cfg(windows)]
        let reducer = reduce_port_list(!self.no_grouping, self.display_cmdline, self.hide_path);

        let ports = ports
            .into_iter()
            .filter(|r| {
                (r.local_addr().is_ipv4() && display_ipv4)
                    || (r.local_addr().is_ipv6() && display_ipv6)
            })
            .fold(vec![], reducer);

        let rendered_ports = ports
            .into_iter()
            .filter(|p| {
                if display_all {
                    return true;
                }

                if display_listening {
                    if p.socket_type.contains(&SocketType::Tcp) && p.state == SocketState::Listen {
                        return true;
                    }

                    #[cfg(target_os = "linux")]
                    if let SocketState::Listen | SocketState::Closed = p.state
                        && p.socket_type.contains(&SocketType::Udp)
                    {
                        return true;
                    }

                    #[cfg(windows)]
                    if p.socket_type.contains(&SocketType::Udp) {
                        return true;
                    }
                }

                if display_established {
                    if p.socket_type.contains(&SocketType::Tcp)
                        && p.state == SocketState::Established
                    {
                        return true;
                    }

                    #[cfg(target_os = "linux")]
                    if p.socket_type.contains(&SocketType::Udp)
                        && p.state == SocketState::Established
                    {
                        return true;
                    }

                    #[cfg(windows)]
                    if p.socket_type.contains(&SocketType::Udp) {
                        return true;
                    }
                }

                false
            })
            .filter(|p| {
                if display_all {
                    return true;
                }

                if display_udp {
                    return p.socket_type.contains(&SocketType::Udp);
                }

                if display_tcp {
                    return p.socket_type.contains(&SocketType::Tcp);
                }

                false
            });

        let rendered_ports = rendered_ports
            .into_iter()
            .map(|port| {
                let pids = port
                    .pids
                    .iter()
                    .map(|p| format!("{p}"))
                    .collect::<Vec<_>>()
                    .join(",");
                let local_addr = port
                    .local_addr
                    .iter()
                    .map(|p| {
                        if p.is_ipv6() && (p.is_loopback() || p.is_unspecified()) {
                            format!("[{p}]")
                        } else {
                            format!("{p}")
                        }
                    })
                    .collect::<Vec<_>>()
                    .join(",");
                let local_port = if port.local_port_start != port.local_port_end {
                    format!("{}-{}", port.local_port_start, port.local_port_end)
                } else {
                    format!("{}", port.local_port_start)
                };
                let remote_addr = port.remote_addr.map(|a| format!("{a}")).unwrap_or_default();
                let remote_port = port.remote_port.map(|p| format!("{p}")).unwrap_or_default();
                let socket_type = port
                    .socket_type
                    .iter()
                    .map(|st| format!("{st}"))
                    .collect::<Vec<_>>()
                    .join(",");

                RenderPortGroups {
                    pids,
                    local_addr,
                    local_port,
                    remote_addr,
                    remote_port,
                    cmd: port.cmd,
                    state: format!("{}", port.state),
                    socket_type,
                }
            })
            .collect::<Vec<_>>();

        let max_socket_type_len = rendered_ports
            .iter()
            .map(|p| p.socket_type.len())
            .max()
            .unwrap_or(4)
            .max(4);
        let max_local_addr_len = rendered_ports
            .iter()
            .map(|p| p.local_addr.len())
            .max()
            .unwrap_or(11)
            .max(11);
        let max_local_port_len = rendered_ports
            .iter()
            .map(|p| p.local_port.len())
            .max()
            .unwrap_or(11)
            .max(11);
        let max_pid_len = rendered_ports
            .iter()
            .map(|p| p.pids.len())
            .max()
            .unwrap_or(4)
            .max(4);
        let max_remote_addr_len = rendered_ports
            .iter()
            .map(|p| p.remote_addr.len())
            .max()
            .unwrap_or(12)
            .max(12);
        let max_remote_port_len = rendered_ports
            .iter()
            .map(|p| p.remote_port.len())
            .max()
            .unwrap_or(12)
            .max(12);
        let max_state_len = rendered_ports
            .iter()
            .map(|p| p.state.len())
            .max()
            .unwrap_or(6)
            .max(6);

        #[cfg(target_os = "linux")]
        let cmd_display = match (self.display_cmdline, self.display_cgroup) {
            (true, true) => "Command line (cgroup)",
            (true, false) => "Command line",
            (false, true) => "Executable (cgroup)",
            (false, false) => "Executable",
        };
        #[cfg(windows)]
        let cmd_display = "Executable";

        if display_all || (display_tcp && display_udp) {
            write!(out, "{:>max_socket_type_len$}", "Type")?;
        }
        if display_all
            || ((display_tcp && display_udp) && (display_established && display_listening))
        {
            write!(out, ":")?;
        }
        if display_all || (display_established && display_listening) {
            write!(out, "{:<max_state_len$}", "State")?;
        }

        if display_all || (display_established && display_listening) || (display_tcp && display_udp)
        {
            write!(out, "  ")?;
        }

        write!(
            out,
            "{:>max_local_addr_len$}:{:<max_local_port_len$}",
            "Local addr", "Local port"
        )?;

        if display_all || display_established {
            write!(
                out,
                "  {:>max_remote_addr_len$}:{:<max_remote_port_len$}",
                "Remote addr", "Remote port"
            )?;
        }

        writeln!(out, "  {:>max_pid_len$}: {}", "PIDs", cmd_display)?;

        for port in rendered_ports {
            if display_all || (display_tcp && display_udp) {
                write!(out, "{:>max_socket_type_len$}", port.socket_type)?;
            }
            if display_all
                || ((display_tcp && display_udp) && (display_established && display_listening))
            {
                write!(out, ":")?;
            }
            if display_all || (display_established && display_listening) {
                write!(out, "{:<max_state_len$}", port.state)?;
            }

            if display_all
                || (display_established && display_listening)
                || (display_tcp && display_udp)
            {
                write!(out, "  ")?;
            }

            write!(
                out,
                "{:>max_local_addr_len$}:{:<max_local_port_len$}",
                port.local_addr, port.local_port
            )?;

            if display_all || display_established {
                write!(
                    out,
                    "  {:>max_remote_addr_len$}:{:<max_remote_port_len$}",
                    port.remote_addr, port.remote_port
                )?;
            }

            writeln!(out, "  {:>max_pid_len$}: {}", port.pids, port.cmd)?;
        }

        Ok(())
    }
}

// Identify ranges/groups that are useful to reduce:
//
// Type, PID: port, cmdline, and local IP must all match (e.g., bind, nginx, apache all forking for performance)
// Type, Port: pid, cmdline, and local IP must all match, and port must be next to a range of ports (e.g., DNS on Windows DC)
//
// IPs "match" if they actually match, if they are both unspecified (0.0.0.0, ::), or if they are both loopback (127.0.0.1, 127.0.0.53, ::1)
//
// Only TCP listening or UDP unconnected sockets can be reduced
fn reduce_port_list(
    perform_grouping: bool,
    display_cmdline: bool,
    hide_path: bool,
    #[cfg(target_os = "linux")] display_cgroup: bool,
) -> impl FnMut(Vec<PortGroups>, SocketRecord) -> Vec<PortGroups> {
    #[cfg(target_os = "linux")]
    use crate::utils::ports::linux::OsSocketRecordExt;

    move |mut groups: Vec<PortGroups>, record: SocketRecord| {
        #[cfg(target_os = "linux")]
        let cmd = match (display_cmdline, display_cgroup, hide_path) {
            (true, true, false) => {
                format!(
                    "{} {}",
                    record.cmdline().unwrap_or(""),
                    record
                        .cgroup()
                        .map(|cg| format!("({cg})"))
                        .unwrap_or("".to_string())
                )
            }
            (true, false, false) => record.cmdline().unwrap_or("").to_string(),
            (false, true, false) => {
                format!(
                    "{} {}",
                    record.exe().unwrap_or(""),
                    record
                        .cgroup()
                        .map(|cg| format!("({cg})"))
                        .unwrap_or("".to_string())
                )
            }
            (false, false, false) => record.exe().unwrap_or("").to_string(),
            (_, true, true) => {
                format!(
                    "{} {}",
                    record
                        .exe()
                        .map(PathBuf::from)
                        .and_then(|p| p.file_name().map(|p| p.to_string_lossy().to_string()))
                        .or(record.exe().map(str::to_string))
                        .unwrap_or("".to_string()),
                    record
                        .cgroup()
                        .map(|cg| format!("({cg})"))
                        .unwrap_or("".to_string())
                )
            }
            (_, false, true) => record
                .exe()
                .map(PathBuf::from)
                .and_then(|p| p.file_name().map(|p| p.to_string_lossy().to_string()))
                .or(record.exe().map(str::to_string))
                .unwrap_or("".to_string()),
        };

        #[cfg(windows)]
        let cmd = record
            .exe()
            .unwrap_or("")
            .to_owned()
            .replace(r"\Device\HarddiskVolume3\", r"C:\");

        #[cfg(target_os = "linux")]
        let udp_state_matches = matches!(record.state(), SocketState::Closed | SocketState::Listen);

        #[cfg(windows)]
        let udp_state_matches = true;

        if (record.state() == SocketState::Listen
            || (record.socket_type() == SocketType::Udp && udp_state_matches))
            && perform_grouping
        {
            let mut iter = groups.iter_mut();
            // These changes are being made under the assumption that SocketRecord is coming in ordered by port
            while let Some(prev_record) = iter.next_back() {
                if !((prev_record.local_port_start - 1)..=(prev_record.local_port_end + 1))
                    .contains(&record.local_port())
                {
                    break;
                }

                if prev_record.cmd != cmd {
                    continue;
                }

                let local_ip_matches = prev_record.local_addr.iter().any(|addr| {
                    (addr.is_unspecified() && record.local_addr().is_unspecified())
                        || (addr.is_loopback() && record.local_addr().is_loopback())
                        || (*addr == record.local_addr())
                });

                if !local_ip_matches {
                    continue;
                }

                if prev_record.pids.len() == 1
                    && record
                        .pid()
                        .map(|p| prev_record.pids.contains(&p))
                        .unwrap_or_default()
                {
                    prev_record.socket_type.insert(record.socket_type());
                    prev_record.local_addr.insert(record.local_addr());

                    prev_record.local_port_start =
                        prev_record.local_port_start.min(record.local_port());
                    prev_record.local_port_end =
                        prev_record.local_port_end.max(record.local_port());

                    return groups;
                }

                if prev_record.local_port_start == prev_record.local_port_end
                    && prev_record.local_port_start == record.local_port()
                {
                    prev_record.socket_type.insert(record.socket_type());
                    prev_record.local_addr.insert(record.local_addr());

                    return groups;
                }
            }
        }

        groups.push(PortGroups {
            pids: record.pid().into_iter().collect(),
            local_addr: vec![record.local_addr()].into_iter().collect(),
            local_port_start: record.local_port(),
            local_port_end: record.local_port(),
            remote_addr: record.remote_addr(),
            remote_port: record.remote_port(),
            cmd,
            state: match record.state() {
                st if record.socket_type() == SocketType::Tcp => st,
                st if record.socket_type() == SocketType::Udp => SocketState::Listen,
                st => st,
            },
            socket_type: vec![record.socket_type()].into_iter().collect(),
        });

        groups
    }
}
