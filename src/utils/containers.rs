//! Utilities for summarizing container runtimes like Docker, Podman, and LXC

use crate::utils::qx;
use walkdir::WalkDir;

/// Unified structure for any container found on the system
pub struct Container {
    pub runtime: String, // e.g., "Docker", "Podman", "Containerd (default)"
    pub id: String,
    pub image: String,
    pub status: String,            // e.g., "Up 2 hours", "Created"
    pub name: String,              // Container name or extra info
    pub namespace: Option<String>, // Specifically for containerd namespaces
}

/// Discovers running containers across Docker, Podman, LXC, and Containerd
pub fn get_containers() -> Vec<Container> {
    let mut results = Vec::new();

    // --- Check Docker ---
    // Format: ID|Image|Status|Names
    match qx("docker ps --format '{{.ID}}|{{.Image}}|{{.Status}}|{{.Names}}' --no-trunc") {
        Ok((status, output)) if status.success() => {
            for line in output.lines().filter(|l| !l.trim().is_empty()) {
                let parts: Vec<&str> = line.split('|').collect();
                if parts.len() >= 4 {
                    results.push(Container {
                        runtime: "Docker".to_string(),
                        id: parts[0].to_string(),
                        image: parts[1].to_string(),
                        status: parts[2].to_string(),
                        name: parts[3].to_string(),
                        namespace: None,
                    });
                }
            }
        }
        // Exit 127 usually means command not found; ignore.
        // Other errors might indicate permission issues or daemon down.
        Ok((status, _)) if status.code() == Some(127) => {}
        Ok((status, err_out)) => eprintln!("Docker check failed ({}): {}", status, err_out.trim()),
        Err(e) => eprintln!("Failed to run docker check: {e}"),
    }

    // --- Check Podman ---
    match qx("podman ps --format '{{.ID}}|{{.Image}}|{{.Status}}|{{.Names}}' --no-trunc") {
        Ok((status, output)) if status.success() => {
            for line in output.lines().filter(|l| !l.trim().is_empty()) {
                let parts: Vec<&str> = line.split('|').collect();
                if parts.len() >= 4 {
                    results.push(Container {
                        runtime: "Podman".to_string(),
                        id: parts[0].to_string(),
                        image: parts[1].to_string(),
                        status: parts[2].to_string(),
                        name: parts[3].to_string(),
                        namespace: None,
                    });
                }
            }
        }
        Ok((status, _)) if status.code() == Some(127) => {}
        Ok((status, err_out)) => eprintln!("Podman check failed ({}): {}", status, err_out.trim()),
        Err(e) => eprintln!("Failed to run podman check: {e}"),
    }

    // --- Check LXC ---
    // Format: NAME,STATE,IPV4
    match qx("lxc list --format csv -c n,s,4") {
        Ok((status, output)) if status.success() => {
            for line in output.lines().filter(|l| !l.trim().is_empty()) {
                let parts: Vec<&str> = line.split(',').collect();
                if parts.len() >= 2 {
                    results.push(Container {
                        runtime: "LXC".to_string(),
                        id: "N/A".to_string(),
                        image: "N/A".to_string(),
                        name: parts[0].to_string(),
                        status: parts[1].to_string(), // State (RUNNING/STOPPED)
                        namespace: None,
                    });
                }
            }
        }
        Ok((status, _)) if status.code() == Some(127) => {}
        Ok((status, err_out)) => eprintln!("LXC check failed ({}): {}", status, err_out.trim()),
        Err(e) => eprintln!("Failed to run LXC check: {e}"),
    }

    // --- Check Containerd (ctr) ---
    // 1. Get Namespaces
    let mut namespaces = Vec::new();
    match qx("ctr namespaces list -q") {
        Ok((status, output)) if status.success() => {
            for line in output.lines().filter(|l| !l.trim().is_empty()) {
                namespaces.push(line.trim().to_string());
            }
        }
        Ok((status, _)) if status.code() == Some(127) => {}
        Ok((status, err_out)) => {
            eprintln!("Containerd check failed ({}): {}", status, err_out.trim());
        }
        Err(e) => eprintln!("Failed to run containerd check: {e}"),
    }

    // 2. Iterate Namespaces
    for ns in namespaces {
        match qx(&format!("ctr -n {ns} containers ls")) {
            Ok((status, output)) if status.success() => {
                for line in output.lines().skip(1).filter(|l| !l.trim().is_empty()) {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 2 {
                        results.push(Container {
                            runtime: "Containerd".to_string(),
                            id: parts[0].to_string(),      // Container ID
                            image: parts[1].to_string(),   // Image Ref
                            status: "Unknown".to_string(), // 'ctr c ls' doesn't always show up/down status clearly without 'tasks'
                            name: parts[0].to_string(),
                            namespace: Some(ns.clone()),
                        });
                    }
                }
            }
            Ok((status, err_out)) => eprintln!(
                "Containerd list for ns {ns} failed ({}): {}",
                status,
                err_out.trim()
            ),
            Err(e) => eprintln!("Failed to run containerd list for ns {ns}: {e}"),
        }
    }

    results
}

/// Discovers docker-compose.yml or compose.yaml files
pub fn find_compose_files() -> Vec<String> {
    let mut found = Vec::new();
    let search_paths = ["/opt", "/var/www", "/etc/docker", "/home"];

    for root in &search_paths {
        for entry in WalkDir::new(root).max_depth(4) {
            match entry {
                Ok(entry) => {
                    let name = entry.file_name().to_string_lossy();
                    if name == "docker-compose.yml"
                        || name == "docker-compose.yaml"
                        || name == "compose.yaml"
                    {
                        found.push(entry.path().to_string_lossy().to_string());
                    }
                }
                Err(e) => eprintln!("Could not access entry in {root}: {e}"),
            }
        }
    }
    found
}
