use std::io::Write;

use clap::Parser;

use crate::utils::{
    pager,
    ports::{self, SocketState},
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
        let tcp_ports = ports::parse_net_tcp()?;

        writeln!(
            out,
            "{:>15}:{:<10} {:>12}: Command line (Cgroup)",
            "Local addr", "Local port", "PID"
        )?;

        for port in tcp_ports {
            if port.state != SocketState::LISTEN {
                continue;
            }

            let pid = port
                .pid
                .map_or("unknown".to_string(), |pid| pid.to_string());
            let cmdline = port.cmdline.clone().unwrap_or_default();
            let exe = port.exe.clone().unwrap_or_default();
            let cgroup = port.cgroup.map(|cg| format!("({cg})")).unwrap_or_default();

            writeln!(
                out,
                "{:>15}:{:<10} {:>12}: {} {}",
                port.local_address,
                port.local_port,
                pid,
                if self.display_cmdline { cmdline } else { exe },
                cgroup
            )?;
        }
        Ok(())
    }
}
