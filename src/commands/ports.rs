use std::io::Write;

use clap::Parser;

use crate::utils::{
    pager,
    ports::{self, SocketState, SocketType},
};

#[derive(Parser, Debug)]
#[command(version, about)]
pub struct Ports {
    #[arg(long, short = 'c')]
    pub display_cmdline: bool,

    #[arg(long)]
    pub no_pager: bool,
}

impl super::Command for Ports {
    fn execute(self) -> eyre::Result<()> {
        let mut ob = pager::get_pager_output(self.no_pager);
        self.run(&mut ob)
    }
}

impl Ports {
    pub fn run(self, out: &mut impl Write) -> eyre::Result<()> {
        #[cfg(target_os = "linux")]
        use crate::utils::ports::linux::OsSocketRecordExt;

        let tcp_ports = ports::list_ports()?;

        #[cfg(target_os = "linux")]
        writeln!(
            out,
            "{:>15}:{:<10} {:>12}: Command line (Cgroup)",
            "Local addr", "Local port", "PID"
        )?;
        #[cfg(windows)]
        writeln!(
            out,
            "{:>15}:{:<10} {:>12}: Command line",
            "Local addr", "Local port", "PID"
        )?;

        for port in tcp_ports {
            if port.state() != SocketState::Listen && port.socket_type() != SocketType::Udp {
                continue;
            }

            let pid = port
                .pid()
                .map_or("unknown".to_string(), |pid| pid.to_string());

            #[cfg(target_os = "linux")]
            let cmd = if self.display_cmdline {
                port.cmdline().to_owned().unwrap_or_default()
            } else {
                port.exe().to_owned().unwrap_or_default()
            };

            #[cfg(windows)]
            let cmd = port.exe().to_owned().unwrap_or_default();

            #[cfg(target_os = "linux")]
            let cgroup = port
                .cgroup()
                .map(|cg| format!("({cg})"))
                .unwrap_or_default();

            #[cfg(windows)]
            writeln!(
                out,
                "{:>15}:{:<10} {:>12}: {}",
                port.local_addr(),
                port.local_port(),
                pid,
                cmd,
            )?;
            #[cfg(target_os = "linux")]
            writeln!(
                out,
                "{:>15}:{:<10} {:>12}: {} {}",
                port.local_addr(),
                port.local_port(),
                pid,
                cmd,
                cgroup
            )?;
        }

        Ok(())
    }
}
