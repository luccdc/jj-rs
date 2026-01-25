use clap::Parser;

use crate::utils::{busybox::Busybox, qx};

/// Perform basic enumeration of the system
#[derive(Parser, Debug)]
pub struct Enum {
    #[arg(long, short = 'c')]
    display_cmdline: bool,
}

impl super::Command for Enum {
    fn execute(self) -> eyre::Result<()> {
        let bb = Busybox::new()?;

        println!("\n==== CPU INFO\n");

        println!(
            "{}",
            qx(r"lscpu | grep -E '^(Core|Thread|CPU)\(s\)'")
                .map(|(_, lscpu)| lscpu)
                .unwrap_or("(unable to query cpu info)".to_string())
        );

        println!("\n==== MEMORY/STORAGE INFO\n");

        bb.command("free").arg("-h").spawn()?.wait()?;
        println!("---");
        bb.command("df").arg("-h").spawn()?.wait()?;

        println!("\n==== PORTS INFO\n");

        super::ports::Ports {
            display_cmdline: self.display_cmdline,
        }
        .execute()?;

        Ok(())
    }
}
