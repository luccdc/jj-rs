use std::net::{Ipv4Addr, Ipv6Addr};

use eyre::Context;

use crate::utils::{
    checks::{CheckResult, CheckStep, TroubleshooterRunner},
    ports,
};

use super::CheckIpProtocol;

struct BinaryPortsCheck {
    process_names: Vec<String>,
    port: u16,
    protocol: CheckIpProtocol,
    run_local: bool,
}

impl CheckStep<'_> for BinaryPortsCheck {
    fn name(&self) -> &'static str {
        "Sockstat check"
    }

    #[cfg(target_os = "linux")]
    fn run_check(&self, _tr: &mut dyn TroubleshooterRunner) -> eyre::Result<CheckResult> {
        if !self.run_local {
            return Ok(CheckResult::not_run(
                "Cannot check listening ports on a remote system",
                serde_json::json!(null),
            ));
        }

        let procs = std::fs::read_dir("/proc").context("Could not open /proc")?;

        let procs = procs
            .filter_map(|entry| {
                entry
                    .ok()
                    .map(|dir| dir.file_name().to_string_lossy().to_string())
            })
            .filter_map(|dir| dir.parse::<u32>().ok())
            .filter_map(|dir| {
                nix::fcntl::readlink(&*format!("/proc/{dir}/exe"))
                    .ok()
                    .filter(|exe| {
                        let exe_str = exe.to_string_lossy();
                        self.process_names
                            .iter()
                            .any(|proc_name| exe_str.ends_with(&**proc_name))
                    })
                    .map(|exe| (dir, exe.to_string_lossy().to_string()))
            })
            .filter_map(|(pid, exe)| {
                let inodes = ports::linux::socket_inodes_for_pid(pid)
                    .ok()?
                    .into_iter()
                    .map(|inode| (inode, u64::from(pid)))
                    .collect();

                // Read from /proc/{pid}/net/{tcp,udp}6 instead to make sure that
                // we are checking accross namespaces. It is the responsibility of
                // the operator to verify firewall rules are correct

                let ports = ports::linux::parse_raw_ip_stats::<_, Ipv4Addr>(
                    format!("/proc/{pid}/net/tcp"),
                    ports::SocketType::Tcp,
                )
                .into_iter()
                .flatten()
                .chain(
                    ports::linux::parse_raw_ip_stats::<_, Ipv6Addr>(
                        format!("/proc/{pid}/net/tcp6"),
                        ports::SocketType::Tcp,
                    )
                    .into_iter()
                    .flatten(),
                )
                .chain(
                    ports::linux::parse_raw_ip_stats::<_, Ipv4Addr>(
                        format!("/proc/{pid}/net/udp"),
                        ports::SocketType::Udp,
                    )
                    .into_iter()
                    .flatten(),
                )
                .chain(
                    ports::linux::parse_raw_ip_stats::<_, Ipv6Addr>(
                        format!("/proc/{pid}/net/udp6"),
                        ports::SocketType::Udp,
                    )
                    .into_iter()
                    .flatten(),
                )
                .collect::<Vec<_>>();

                let ports_enriched = ports::linux::enrich_ip_stats(ports, &inodes)
                    .into_iter()
                    .filter(|port| port.pid == Some(pid.into()))
                    .collect::<Vec<_>>();

                Some((pid, exe, ports_enriched))
            })
            .collect::<Vec<_>>();

        let proc_listening = procs.iter().any(|(_, _, ports)| {
            ports.iter().any(|port| {
                !port.local_address.is_loopback()
                    && port.local_port == self.port
                    && (port.state
                        == (match self.protocol {
                            CheckIpProtocol::Tcp => ports::linux::SocketState::LISTEN,
                            CheckIpProtocol::Udp => ports::linux::SocketState::CLOSE,
                        }))
                    && (port.socket_type
                        == (match self.protocol {
                            CheckIpProtocol::Tcp => ports::SocketType::Tcp,
                            CheckIpProtocol::Udp => ports::SocketType::Udp,
                        }))
            })
        });

        let context_procs = procs
            .iter()
            .map(|(pid, exe, ports)| {
                serde_json::json!({
                    "pid": pid,
                    "exe": exe,
                    "ports": ports
                        .iter()
                        .map(|port| serde_json::json!({
                            "local_address": format!("{}", port.local_address),
                            "local_port": port.local_port,
                            "state": format!("{:?}", port.state),
                            "type": format!("{:?}", port.socket_type)
                        }))
                        .collect::<serde_json::Value>()
                })
            })
            .collect::<serde_json::Value>();

        if proc_listening {
            Ok(CheckResult::succeed(
                format!(
                    "Successfully found a process listening on port {}",
                    self.port
                ),
                serde_json::json!({
                    "processes": context_procs
                }),
            ))
        } else {
            let mut msg = format!(
                "Could not find a process with specified names listening on port {}",
                self.port
            );
            #[cfg(unix)]
            if unsafe { libc::getuid() } != 0 {
                msg.push_str(" (Some processes skipped due to permissions. Try running with sudo)");
            }

            Ok(CheckResult::fail(
                msg,
                serde_json::json!({
                    "specified_names": self.process_names,
                    "processes": context_procs
                }),
            ))
        }
    }

    #[cfg(windows)]
    fn run_check(&self, _tr: &mut dyn TroubleshooterRunner) -> eyre::Result<CheckResult> {
        use std::collections::HashMap;

        use crate::utils::ports::SocketRecord;

        use windows::Win32::System::{
            ProcessStatus::{EnumProcesses, GetProcessImageFileNameA},
            Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION},
        };

        let ports = crate::utils::ports::list_ports()?;

        let mut ports = ports.into_iter().fold(
            HashMap::<u64, Vec<SocketRecord>>::new(),
            |mut hash, port| {
                let Some(pid) = port.pid() else {
                    return hash;
                };

                let entry = hash.entry(pid);
                entry.or_default().push(port);

                hash
            },
        );

        let processes = unsafe {
            let mut pids = vec![0u32; 4096];
            let mut pids_enumed = 0u32;

            EnumProcesses(pids.as_mut_ptr() as _, 4096 * 4, &mut pids_enumed as _)?;

            pids[..(pids_enumed as usize)]
                .iter()
                .filter_map(|pid| -> Option<(u32, String)> {
                    let proc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, *pid).ok()?;

                    let mut image_name = [0; 1024];

                    let len = GetProcessImageFileNameA(proc, &mut image_name) as usize;

                    let image = String::from_utf8_lossy(&image_name[..len]).to_string();

                    Some((*pid, image))
                })
                .filter(|(_, image)| {
                    self.process_names
                        .iter()
                        .any(|proc_name| image.ends_with(&**proc_name))
                })
                .collect::<Vec<_>>()
        };

        let proc_listening = processes
            .iter()
            .flat_map(|(pid, _)| ports.get(&(*pid as u64)))
            .any(|sockets| {
                sockets.iter().any(|socket| {
                    !socket.local_addr().is_loopback()
                        && socket.local_port() == self.port
                        && (socket.state()
                            == (match self.protocol {
                                CheckIpProtocol::Tcp => ports::SocketState::Listen,
                                CheckIpProtocol::Udp => ports::SocketState::Unknown,
                            }))
                        && (socket.socket_type()
                            == (match self.protocol {
                                CheckIpProtocol::Tcp => ports::SocketType::Tcp,
                                CheckIpProtocol::Udp => ports::SocketType::Udp,
                            }))
                })
            });

        let context_procs = processes
            .iter()
            .flat_map(|(pid, image)| {
                ports
                    .remove_entry(&(*pid as u64))
                    .map(|(pid, sockets)| (pid, image, sockets))
            })
            .map(|(pid, image, sockets)| {
                serde_json::json!({
                    "pid": pid,
                    "exe": image,
                    "ports": sockets
                        .iter()
                        .filter(|port| self.port > 60000 || port.local_port() < 60000)
                        .take(16) // DNS server has something like 8000 ports open...
                        .map(|port| serde_json::json!({
                            "local_address": format!("{}", port.local_addr()),
                            "local_port": port.local_port(),
                            "state": format!("{}", port.state()),
                            "type": format!("{}", port.socket_type())
                        }))
                        .collect::<serde_json::Value>()
                })
            })
            .collect::<serde_json::Value>();

        if proc_listening {
            Ok(CheckResult::succeed(
                format!(
                    "Successfully found a process listening on port {}",
                    self.port
                ),
                serde_json::json!({
                    "processes": context_procs
                }),
            ))
        } else {
            Ok(CheckResult::fail(
                format!(
                    "Could not find a process with specified names listening on port {}",
                    self.port
                ),
                serde_json::json!({
                    "specified_names": self.process_names,
                    "processes": context_procs
                }),
            ))
        }
    }
}

/// Check for processes started from a binary with the specified name, and
/// verify that a specified port is listening for TCP or open for UDP
///
/// Example:
/// ```
/// # use jj_rs::utils::checks::{CheckIpProtocol, binary_ports_check};
/// binary_ports_check(
///     ["sshd"],
///     22,
///     CheckIpProtocol::Tcp,
///     true
/// );
/// ```
pub fn binary_ports_check<'a, I: IntoIterator<Item = S>, S: AsRef<str>>(
    process_names: I,
    port: u16,
    protocol: CheckIpProtocol,
    run_local: bool,
) -> Box<dyn CheckStep<'a> + 'a> {
    Box::new(BinaryPortsCheck {
        process_names: process_names
            .into_iter()
            .map(|s| s.as_ref().to_string())
            .collect(),
        port,
        protocol,
        run_local,
    })
}
