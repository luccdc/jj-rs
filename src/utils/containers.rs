//! Utilities for summarizing container runtimes like Docker, Podman, and LXC

use crate::utils::qx;

/// Returns a list of summaries for running containers across various runtimes.
pub fn get_container_summary() -> Vec<String> {
    let mut summaries = Vec::new();

    // Check Docker
    if let Ok((status, output)) =
        qx("docker ps --format '{{.Names}} [{{.Image}}] {{.Ports}}' --no-trunc")
        && status.success()
    {
        let lines: Vec<_> = output.lines().filter(|l| !l.trim().is_empty()).collect();
        if lines.is_empty() {
            summaries.push(
                "Docker: Engine active, but no containers are currently running.".to_string(),
            );
        } else {
            summaries.push(format!(
                "Docker: Found {} active container(s):",
                lines.len()
            ));
            for line in lines {
                summaries.push(format!("  [+] {line}"));
            }
        }
    }

    // Check Podman
    if let Ok((status, output)) =
        qx("podman ps --format '{{.Names}} [{{.Image}}] {{.Ports}}' --no-trunc")
        && status.success()
    {
        let lines: Vec<_> = output.lines().filter(|l| !l.trim().is_empty()).collect();
        if lines.is_empty() {
            summaries.push(
                "Podman: Engine active, but no containers are currently running.".to_string(),
            );
        } else {
            summaries.push(format!(
                "Podman: Found {} active container(s):",
                lines.len()
            ));
            for line in lines {
                summaries.push(format!("  [+] {line}"));
            }
        }
    }

    // Check LXC
    if let Ok((status, output)) = qx("lxc list --format csv -c n,s,4")
        && status.success()
    {
        let lines: Vec<_> = output.lines().filter(|l| !l.trim().is_empty()).collect();
        if lines.is_empty() {
            summaries.push("LXC: Service active, but no containers are listed.".to_string());
        } else {
            summaries.push(format!("LXC: Found {} container(s):", lines.len()));
            for line in lines {
                summaries.push(format!("  [+] {line}"));
            }
        }
    }

    summaries
}
