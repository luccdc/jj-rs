//! Utilities for summarizing container runtimes like Docker, Podman, and LXC

use crate::utils::qx;
use walkdir::WalkDir;

/// Unified structure for any container found on the system
pub struct Container {
    pub runtime: String,   // e.g., "Docker", "Podman", "Containerd (default)"
    pub id: String,
    pub image: String,
    pub status: String,    // e.g., "Up 2 hours", "Created"
    pub name: String,      // Container name or extra info
    pub namespace: Option<String>, // Specifically for containerd namespaces
}

/// Discovers running containers across Docker, Podman, LXC, and Containerd
pub fn get_containers() -> Vec<Container> {
    let mut results = Vec::new();

    // --- Check Docker ---
    // Format: ID|Image|Status|Names
    if let Ok((status, output)) =
        qx("docker ps --format '{{.ID}}|{{.Image}}|{{.Status}}|{{.Names}}' --no-trunc")
        && status.success()
    {
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

    // --- Check Podman ---
    if let Ok((status, output)) =
        qx("podman ps --format '{{.ID}}|{{.Image}}|{{.Status}}|{{.Names}}' --no-trunc")
        && status.success()
    {
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

    // --- Check LXC ---
    // Format: NAME,STATE,IPV4
    if let Ok((status, output)) = qx("lxc list --format csv -c n,s,4")
        && status.success()
    {
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

    // --- Check Containerd (ctr) ---
    // 1. Get Namespaces
    let mut namespaces = Vec::new();
    if let Ok((status, output)) = qx("ctr namespaces list -q")
        && status.success()
    {
        for line in output.lines().filter(|l| !l.trim().is_empty()) {
            namespaces.push(line.trim().to_string());
        }
    }

    // 2. Iterate Namespaces
    for ns in namespaces {
        // "ctr -n <ns> container ls" output usually: CONTAINER IMAGE RUNTIME
        // We skip header line (1st line)
        if let Ok((status, output)) = qx(&format!("ctr -n {ns} containers ls")) 
            && status.success() 
        {
            for line in output.lines().skip(1).filter(|l| !l.trim().is_empty()) {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 {
                    results.push(Container {
                        runtime: "Containerd".to_string(),
                        id: parts[0].to_string(),    // Container ID
                        image: parts[1].to_string(), // Image Ref
                        status: "Unknown".to_string(), // 'ctr c ls' doesn't always show up/down status clearly without 'tasks'
                        name: parts[0].to_string(),
                        namespace: Some(ns.clone()),
                    });
                }
            }
        }
    }

    results
}

/// Discovers docker-compose.yml or compose.yaml files
pub fn find_compose_files() -> Vec<String> {
    let mut found = Vec::new();
    let search_paths = ["/opt", "/var/www", "/etc/docker", "/home"];

    for root in &search_paths {
        for entry in WalkDir::new(root)
            .max_depth(4)
            .into_iter()
            .filter_map(Result::ok)
        {
            let name = entry.file_name().to_string_lossy();
            if name == "docker-compose.yml"
                || name == "docker-compose.yaml"
                || name == "compose.yaml"
            {
                found.push(entry.path().to_string_lossy().to_string());
            }
        }
    }
    found
}
