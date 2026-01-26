use crate::utils::busybox::Busybox;
use std::io::{IsTerminal, Write};
use std::process::Stdio;

pub fn page_output(content: &str) -> eyre::Result<()> {
    // 1. Only use the pager if stdout is a terminal
    if !std::io::stdout().is_terminal() {
        print!("{content}");
        return Ok(());
    }

    // 2. Initialize the embedded Busybox
    let bb = Busybox::new()?;

    // 3. Prepare the 'less' command
    // Flags:
    // -F: Quit if the content fits on one screen (like systemctl/git)
    // -R: Output "raw" control characters (allows ANSI colors)
    // -X: Don't clear the screen on exit
    let mut child = bb
        .command("less")
        .args(["-F", "-R", "-X"])
        .stdin(Stdio::piped())
        .spawn()?;

    // 4. Pipe the content into the pager's stdin
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(content.as_bytes())?;
    }

    // 5. Wait for the user to finish viewing
    child.wait()?;
    Ok(())
}
