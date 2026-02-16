use std::io::Write;

use clap::{Parser, Subcommand};

use crate::utils::{
    logs::{ellipsize, truncate},
    pager::{self, PagerOutput},
    qx,
};

/// Perform system enumeration or target specific subsystems
#[derive(Parser, Debug)]
#[command(about = "System enumeration tools")]
pub struct Enum {
    #[command(subcommand)]
    pub subcommand: Option<EnumSubcommands>,
}

#[derive(Subcommand, Debug)]
pub enum EnumSubcommands {
    /// Current network ports and listening services
    #[command(visible_alias("p"))]
    Ports(super::ports::Ports),
}

impl super::Command for Enum {
    fn execute(self) -> eyre::Result<()> {
        let mut ob = pager::get_pager_output(true);

        enum_hostname(&mut ob);

        match self.subcommand {
            Some(EnumSubcommands::Ports(ports)) => enum_ports(&mut ob, ports),
            None => {
                enum_ports(
                    &mut ob,
                    super::ports::Ports {
                        display_tcp: true,
                        display_udp: true,
                        ..super::ports::Ports::default()
                    },
                )?;

                Ok(())
            }
        }
    }
}

fn enum_ports(out: &mut impl PagerOutput, p: super::ports::Ports) -> eyre::Result<()> {
    writeln!(out, "\n==== PORTS INFO")?;
    p.run(out)
}

//Hostname enumeration ('H' alias)
fn enum_hostname(out: &mut impl PagerOutput) -> eyre::Result<()> {
    writeln!(out, "\n==== HOSTNAME INFO")?;

    let name = std::env::var("COMPUTERNAME")
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "unable to read hostname".to_string());

    writeln!(out, "Hostname: {name}")?;
    Ok(())
}
