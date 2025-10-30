use clap::Parser;

use crate::pcre;

#[derive(Parser, Debug)]
#[command(version, about)]
pub struct Stat;

impl super::Command for Stat {
    fn execute(self) -> anyhow::Result<()> {
        let stat = std::fs::read_to_string("/proc/stat")?;

        let [user, system, idle] = pcre!(
            &stat =~ m{
                r"^cpu \s+ ([0-9]+) \s+ [0-9]+ \s+ ([0-9]+) \s+ ([0-9]+) \s+ .*$"
            }xms
        )[0]
        .extract::<3>()
        .1;

        let user: f64 = user.parse()?;
        let system: f64 = system.parse()?;
        let idle: f64 = idle.parse()?;

        let usage = (user + system) * 100.0 / (user + system + idle);

        println!("{usage:.5}%");

        Ok(())
    }
}
