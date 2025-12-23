use clap::Parser;

use crate::checks;

/// Troubleshoot network services, remotely or locally
///
/// Check the help menu for each subcommand for more information
///
/// Certain parameters may be marked with [`CheckValue`]; these are fields that
/// can use special values such as :STDIN: to read from standard input or
/// :<FILE:$FILE_PATH> to read the value from a file. This is critical for
/// passwords, to ensure they do not remain in the command line parameters of
/// a check
#[derive(Parser, Debug)]
#[command(version, about)]
pub struct Check {
    /// Show the results of successful steps [default: no]
    #[arg(short = 's', long)]
    show_successful_steps: bool,

    /// Show all the steps that were not run for some reason [default: no]
    #[arg(short = 'n', long)]
    show_not_run_steps: bool,

    /// Hide all the extra details for commands
    #[arg(short = 'e', long)]
    hide_extra_details: bool,

    #[command(subcommand)]
    command: crate::checks::CheckTypes,
}

impl super::Command for Check {
    fn execute(self) -> eyre::Result<()> {
        let mut t = checks::CliTroubleshooter::new(
            self.show_successful_steps,
            self.show_not_run_steps,
            self.hide_extra_details,
        );

        t.run_cli(&*self.command.troubleshooter())?;

        Ok(())
    }
}
