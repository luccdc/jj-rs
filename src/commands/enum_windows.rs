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
    #[arg(short, long)]
    pub output: Option<String>,
    
    /// Search for DLLs, BATs, and PS1s in addition to EXEs
    #[arg(short = 'd', long)]
    pub detailed: bool,

    /// Perform an extended scan (e.g., read file contents for web shells)
    #[arg(short = 'e', long)]
    pub extended: bool,

    /// Print active IIS log directory and files
    #[arg(long)]
    pub printlog: bool,

    #[command(subcommand)]
    pub subcommand: Option<EnumSubcommands>,
}

#[derive(Subcommand, Debug)]
pub enum EnumSubcommands {
    /// Current network ports and listening services
    #[command(visible_alias("p"))]
    Ports(super::ports::Ports),
    /// Check WSL and Docker status
    WslDocker,
    /// Enumerate IIS sites and scan for potential web shells
    IisSites {
        /// Perform an extended content scan for web shells
        #[arg(short = 'e', long)]
        extended: bool,
        /// Print active IIS log directory and files
        #[arg(long)]
        printlog: bool,
    },
    /// Check for python web servers
    PythonSites,
    /// Enumerate FTP servers (IIS and FileZilla)
    FtpSites,
    /// Enumerate suspicious startup items
    Autoruns,
    /// Enumerate suspicious or unsigned files in System32
    System32Unsigned {
        /// Search for DLLs, BATs, and PS1s in addition to EXEs
        #[arg(short = 'd', long)]
        detailed: bool,
    },
    Winrm,
    /// Enumerate local administrators and privileged local accounts
    LocalAdmins,
}

impl super::Command for Enum {
    fn execute(self) -> eyre::Result<()> {
        let mut ob = pager::get_pager_output(true);

        enum_hostname(&mut ob)?;

        match self.subcommand {
            Some(EnumSubcommands::Ports(ports)) => enum_ports(&mut ob, ports)?,
            Some(EnumSubcommands::WslDocker) => enum_wsl_docker(&mut ob)?,
            
            Some(EnumSubcommands::IisSites { extended, printlog }) => {
                enum_iis_sites(&mut ob, self.extended || extended, self.printlog || printlog)?
            }
            
            Some(EnumSubcommands::PythonSites) => enum_python_sites(&mut ob)?,
            Some(EnumSubcommands::FtpSites) => enum_ftp_sites(&mut ob)?,
            Some(EnumSubcommands::Autoruns) => enum_startup_items(&mut ob)?,
            Some(EnumSubcommands::System32Unsigned { detailed }) => {
                enum_system32_unsigned(&mut ob, self.detailed || detailed)?
            }
            Some(EnumSubcommands::Winrm) => enum_winrm(&mut ob)?,
            Some(EnumSubcommands::LocalAdmins) => enum_local_admins(&mut ob)?,
            
            None => {
                enum_ports(&mut ob, super::ports::Ports::default())?; 
                
                enum_wsl_docker(&mut ob)?;
                
                enum_iis_sites(&mut ob, self.extended, self.printlog)?;
                
                enum_python_sites(&mut ob)?;
                enum_ftp_sites(&mut ob)?;
                
                enum_startup_items(&mut ob)?;
                enum_system32_unsigned(&mut ob, self.detailed)?;

                enum_winrm(&mut ob)?;
                enum_local_admins(&mut ob)?;
            }
        }

        Ok(())
    }
}

// Enumerate ports and associated PID's on the device
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

// Check if a tool exists in the user's path
fn tool_exists(tool: &str) -> bool {
    if let Ok(path) = std::env::var("PATH") {
        for p in std::env::split_paths(&path) {
            let p_str = p.join(format!("{}.exe", tool));
            if p_str.exists() {
                return true;
            }
        }
    }
    false
}

// Enumerate if WSL or docker is in the user's path
fn enum_wsl_docker(out: &mut impl PagerOutput) -> eyre::Result<()> {
    writeln!(out, "\n==== WSL / DOCKER")?;

    if std::path::Path::new(r#"C:\Windows\System32\wsl.exe"#).exists() {
        writeln!(out, "WSL Feature is installed")?;
    } else {
        writeln!(out, "WSL not found or is not in your PATH")?;
    }

    if tool_exists("docker") {
        writeln!(out, "Docker is installed")?;
    } else {
        writeln!(out, "Docker not detected or not in your PATH")?;
    }

    Ok(())
}

fn extract_xml_attr(tag: &str, attr: &str) -> Option<String> {
    let key = format!("{}=\"", attr);
    if let Some(pos) = tag.find(&key) {
        let rest = &tag[pos + key.len()..];
        if let Some(end) = rest.find('"') {
            return Some(rest[..end].to_string());
        }
    }
    let key_single = format!("{}='", attr);
    if let Some(pos) = tag.find(&key_single) {
        let rest = &tag[pos + key_single.len()..];
        if let Some(end) = rest.find('\'') {
            return Some(rest[..end].to_string());
        }
    }
    None
}

fn expand_iis_env_vars(s: &str) -> String {
    let mut result = s.to_string();
    if let Ok(sys_drive) = std::env::var("SystemDrive") {
        result = result.replace("%SystemDrive%", &sys_drive);
    } else {
        result = result.replace("%SystemDrive%", "C:");
    }
    if let Ok(windir) = std::env::var("windir") {
        result = result.replace("%windir%", &windir);
        result = result.replace("%SystemRoot%", &windir);
    } else if let Ok(sys_root) = std::env::var("SystemRoot") {
        result = result.replace("%windir%", &sys_root);
        result = result.replace("%SystemRoot%", &sys_root);
    } else {
        result = result.replace("%windir%", r"C:\Windows");
        result = result.replace("%SystemRoot%", r"C:\Windows");
    }
    result
}

// Enumerate IIS sites, listing out where they are being hosted and ports
fn enum_iis_sites(out: &mut impl PagerOutput, extended_scan: bool, printlog: bool) -> eyre::Result<()> {
    writeln!(out, "\n==== IIS SITES")?;

    let config_path = std::path::Path::new(r"C:\Windows\System32\inetsrv\config\applicationHost.config");
    if !config_path.exists() {
        writeln!(out, "IIS (WebAdministration) is not installed or available.")?;
        return Ok(());
    }

    let content = match std::fs::read_to_string(config_path) {
        Ok(c) => c,
        Err(e) => {
            writeln!(out, "Error reading IIS config: {}", e)?;
            return Ok(());
        }
    };

    // 1. App Pools
    let mut pool_identities: std::collections::HashMap<String, (String, String)> = std::collections::HashMap::new();
    let mut default_pool_id = "ApplicationPoolIdentity".to_string();
    let mut default_pool_user = "".to_string();

    if let Some(app_pools_start) = content.find("<applicationPools>") {
        if let Some(app_pools_end) = content[app_pools_start..].find("</applicationPools>") {
            let section = &content[app_pools_start..app_pools_start + app_pools_end];
            if let Some(apd_pos) = section.find("<applicationPoolDefaults") {
                let apd_rest = &section[apd_pos..];
                if let Some(pm_pos) = apd_rest.find("<processModel ") {
                    let pm_rest = &apd_rest[pm_pos..];
                    if let Some(pm_end) = pm_rest.find('>') {
                        let pm_tag = &pm_rest[..pm_end];
                        if let Some(t) = extract_xml_attr(pm_tag, "identityType") {
                            default_pool_id = t;
                        }
                        if let Some(u) = extract_xml_attr(pm_tag, "userName") {
                            default_pool_user = u;
                        }
                    }
                }
            }

            for block in section.split("<add ") {
                if let Some(tag_end) = block.find('>') {
                    let tag = &block[..tag_end];
                    if let Some(name) = extract_xml_attr(tag, "name") {
                        let mut id_type = default_pool_id.clone();
                        let mut user_name = default_pool_user.clone();
                        if let Some(pm_pos) = block.find("<processModel ") {
                            let pm_rest = &block[pm_pos..];
                            if let Some(pm_end) = pm_rest.find('>') {
                                let pm_tag = &pm_rest[..pm_end];
                                if let Some(t) = extract_xml_attr(pm_tag, "identityType") {
                                    id_type = t;
                                }
                                if let Some(u) = extract_xml_attr(pm_tag, "userName") {
                                    user_name = u;
                                }
                            }
                        }
                        pool_identities.insert(name, (id_type, user_name));
                    }
                }
            }
        }
    }

    let is_std_iis_path = |p: &str| -> bool {
        let p_low = p.to_lowercase();
        p_low.contains(r"\system32\inetsrv\")
            || p_low.ends_with(r"\system32\wsmsvc.dll")
            || p_low.contains(r"\microsoft.net\")
    };

    let mut paths_to_scan = Vec::new();
    let mut found_sites = 0;
    let mut winrm_active_in_iis = false;
    let mut winrm_details = Vec::new();
    let mut custom_modules = Vec::new();
    let mut managed_modules = Vec::new();
    let mut custom_handlers = Vec::new();
    let mut isapi_filters = Vec::new();

    // 2. Global Modules (native backdoors)
    let known_ms_modules = [
        "httploggingmodule", "uricachemodule", "filecachemodule", "tokencachemodule",
        "httpcachemodule", "staticcompressionmodule", "defaultdocumentmodule", "directorylistingmodule",
        "protocolsupportmodule", "staticfilesmodule", "staticfilemodule", "anonymousauthenticationmodule",
        "requestfilteringmodule", "customerrormodule", "isapimodule", "isapifiltermodule",
        "dynamiccompressionmodule", "windowsauthenticationmodule", "basicauthenticationmodule",
        "digestauthenticationmodule", "clientcertificatemappingauthenticationmodule",
        "iiscertificatemappingauthenticationmodule", "urlauthorizationmodule", "iprestrictionmodule",
        "httpredirectionmodule", "tracingmodule", "failedrequeststracingmodule",
        "requestmonitormodule", "customloggingmodule", "odbcloggingmodule", "cgimodule",
        "fastcgimodule", "websocketmodule", "warmupmodule", "appwarmupmodule",
    ];

    if let Some(mod_start) = content.find("<globalModules>") {
        if let Some(mod_end) = content[mod_start..].find("</globalModules>") {
            let section = &content[mod_start..mod_start + mod_end];
            for line in section.lines() {
                let trimmed = line.trim();
                if trimmed.starts_with("<add ") {
                    if let Some(name) = extract_xml_attr(trimmed, "name") {
                        let img = extract_xml_attr(trimmed, "image").unwrap_or_default();
                        let expanded = expand_iis_env_vars(&img);
                        let is_std = is_std_iis_path(&expanded);
                        let name_low = name.to_lowercase();

                        if name_low.contains("winrm") || name_low.contains("wsman") || expanded.to_lowercase().contains("wsmsvc.dll") {
                            winrm_active_in_iis = true;
                            winrm_details.push(("GlobalModule".to_string(), format!("{} ({})", name, img)));
                        }

                        if !is_std {
                            let reason = if !std::path::Path::new(&expanded).exists() {
                                format!("File Missing / Unresolvable ({})", expanded)
                            } else {
                                format!("Non-standard Directory ({})", expanded)
                            };
                            custom_modules.push((name, img, reason));
                        } else if !known_ms_modules.contains(&name_low.as_str()) {
                            custom_modules.push((name, img, format!("Non-standard IIS Module ({})", expanded)));
                        }
                    }
                }
            }
        }
    }

    // 3. Managed Modules
    if let Some(m_start) = content.find("<modules>") {
        if let Some(m_end) = content[m_start..].find("</modules>") {
            let section = &content[m_start..m_start + m_end];
            for line in section.lines() {
                let trimmed = line.trim();
                if trimmed.starts_with("<add ") {
                    if let Some(name) = extract_xml_attr(trimmed, "name") {
                        if let Some(m_type) = extract_xml_attr(trimmed, "type") {
                            let type_low = m_type.to_lowercase();
                            if !type_low.starts_with("system.web.")
                                && !type_low.starts_with("system.servicemodel.")
                                && !type_low.starts_with("system.identitymodel.")
                                && !type_low.starts_with("system.runtime.")
                                && !type_low.starts_with("microsoft.")
                            {
                                managed_modules.push((name, m_type));
                            }
                        }
                    }
                }
            }
        }
    }

    // 4. ISAPI Filters
    if let Some(f_start) = content.find("<isapiFilters") {
        if let Some(f_end) = content[f_start..].find("</isapiFilters>") {
            let section = &content[f_start..f_start + f_end];
            for line in section.lines() {
                let trimmed = line.trim();
                if trimmed.starts_with("<filter ") {
                    if let Some(name) = extract_xml_attr(trimmed, "name") {
                        let path = extract_xml_attr(trimmed, "path").unwrap_or_default();
                        let expanded = expand_iis_env_vars(&path);
                        let is_std = is_std_iis_path(&expanded);
                        if !is_std {
                            let reason = if !std::path::Path::new(&expanded).exists() {
                                format!("File Missing ({})", expanded)
                            } else {
                                format!("Non-standard Path ({})", expanded)
                            };
                            isapi_filters.push((name, path, reason));
                        }
                    }
                }
            }
        }
    }

    // 5. Handlers (Audit both global and site-level)
    let mut check_handler = |trimmed: &str, scope: &str| {
        if trimmed.starts_with("<add ") {
            if let Some(name) = extract_xml_attr(trimmed, "name") {
                let path = extract_xml_attr(trimmed, "path").unwrap_or_default();
                let verb = extract_xml_attr(trimmed, "verb").unwrap_or_default();
                let script = extract_xml_attr(trimmed, "scriptProcessor").unwrap_or_default();
                let h_type = extract_xml_attr(trimmed, "type").unwrap_or_default();

                if name.to_lowercase().contains("winrm")
                    || name.to_lowercase().contains("wsman")
                    || script.to_lowercase().contains("wsmsvc")
                {
                    winrm_active_in_iis = true;
                    winrm_details.push(("HandlerMapping".to_string(), format!("{} ({})", name, script)));
                }

                if !script.is_empty() {
                    let clean_script = script.split(" -").next().unwrap_or(&script).trim_matches('"');
                    let expanded = expand_iis_env_vars(clean_script);
                    let is_std = is_std_iis_path(&expanded);
                    if !is_std {
                        let reason = if !std::path::Path::new(&expanded).exists() {
                            format!("Missing Processor ({})", expanded)
                        } else {
                            format!("Non-standard Path ({})", expanded)
                        };
                        custom_handlers.push((
                            name,
                            path,
                            verb,
                            script,
                            reason,
                            scope.to_string(),
                        ));
                    }
                } else if !h_type.is_empty() {
                    let type_low = h_type.to_lowercase();
                    if !type_low.starts_with("system.") && !type_low.starts_with("microsoft.") {
                        custom_handlers.push((
                            name,
                            path,
                            verb,
                            h_type,
                            "Custom Managed Handler".to_string(),
                            scope.to_string(),
                        ));
                    }
                }
            }
        }
    };

    if let Some(h_start) = content.find("<handlers") {
        if let Some(h_end) = content[h_start..].find("</handlers>") {
            let section = &content[h_start..h_start + h_end];
            for line in section.lines() {
                check_handler(line.trim(), "Global");
            }
        }
    }

    // Check location blocks for site-specific handlers
    for loc_block in content.split("<location ") {
        if let Some(loc_tag_end) = loc_block.find('>') {
            let loc_tag = &loc_block[..loc_tag_end];
            if let Some(loc_path) = extract_xml_attr(loc_tag, "path") {
                let scope = format!("Site: {}", loc_path);
                if let Some(h_start) = loc_block.find("<handlers") {
                    if let Some(h_end) = loc_block[h_start..].find("</handlers>") {
                        let h_sec = &loc_block[h_start..h_start + h_end];
                        for line in h_sec.lines() {
                            check_handler(line.trim(), &scope);
                        }
                    }
                }
            }
        }
    }

    // 6. Sites
    if let Some(sites_start) = content.find("<sites>") {
        if let Some(sites_end) = content[sites_start..].find("</sites>") {
            let section = &content[sites_start..sites_start + sites_end];

            let mut default_log_format = "W3C".to_string();
            let mut default_log_dir = "C:\\inetpub\\logs\\LogFiles".to_string();
            let mut default_site_pool = "DefaultAppPool".to_string();

            if let Some(sd_pos) = section.find("<siteDefaults>") {
                let sd_rest = &section[sd_pos..];
                if let Some(log_pos) = sd_rest.find("<logFile ") {
                    let log_rest = &sd_rest[log_pos..];
                    if let Some(log_end) = log_rest.find('>') {
                        let log_tag = &log_rest[..log_end];
                        if let Some(fmt) = extract_xml_attr(log_tag, "logFormat") {
                            default_log_format = fmt;
                        }
                        if let Some(dir) = extract_xml_attr(log_tag, "directory") {
                            default_log_dir = expand_iis_env_vars(&dir);
                        }
                    }
                }
            }

            if let Some(ad_pos) = section.find("<applicationDefaults ") {
                let ad_rest = &section[ad_pos..];
                if let Some(ad_end) = ad_rest.find('>') {
                    let ad_tag = &ad_rest[..ad_end];
                    if let Some(p) = extract_xml_attr(ad_tag, "applicationPool") {
                        default_site_pool = p;
                    }
                }
            }

            for site_block in section.split("<site ") {
                if let Some(site_tag_end) = site_block.find('>') {
                    let site_tag = &site_block[..site_tag_end];
                    if let Some(site_name) = extract_xml_attr(site_tag, "name") {
                        found_sites += 1;
                        let site_id = extract_xml_attr(site_tag, "id").unwrap_or_else(|| found_sites.to_string());
                        let state = if site_tag.contains("serverAutoStart=\"false\"") {
                            "Stopped"
                        } else {
                            "Started"
                        };

                        // Bindings
                        let mut bindings = Vec::new();
                        if let Some(b_start) = site_block.find("<bindings>") {
                            if let Some(b_end) = site_block[b_start..].find("</bindings>") {
                                let b_sec = &site_block[b_start..b_start + b_end];
                                for b_line in b_sec.lines() {
                                    let trimmed = b_line.trim();
                                    if trimmed.starts_with("<binding ") {
                                        let proto = extract_xml_attr(trimmed, "protocol").unwrap_or_default();
                                        let info = extract_xml_attr(trimmed, "bindingInformation").unwrap_or_default();
                                        bindings.push(format!("{}://{}", proto, info));
                                    }
                                }
                            }
                        }
                        let bindings_str = bindings.join(", ");

                        // Application and Virtual Directories
                        let mut pool_name = default_site_pool.clone();
                        let mut phys_path = String::new();
                        let mut child_vdirs = Vec::new();

                        for app_block in site_block.split("<application ") {
                            if let Some(app_tag_end) = app_block.find('>') {
                                let app_tag = &app_block[..app_tag_end];
                                if let Some(p) = extract_xml_attr(app_tag, "applicationPool") {
                                    pool_name = p;
                                }
                                let app_path = extract_xml_attr(app_tag, "path").unwrap_or_default();

                                if app_path.to_lowercase().contains("wsman") || app_path.to_lowercase().contains("winrm") {
                                    winrm_active_in_iis = true;
                                    winrm_details.push(("Application".to_string(), format!("{}{} ()", site_name, app_path)));
                                }

                                for line in app_block.lines() {
                                    let trimmed = line.trim();
                                    if trimmed.starts_with("<virtualDirectory ") {
                                        let v_path = extract_xml_attr(trimmed, "path").unwrap_or_default();
                                        let v_phys = extract_xml_attr(trimmed, "physicalPath").unwrap_or_default();
                                        let v_phys_exp = expand_iis_env_vars(&v_phys);

                                        if v_path.to_lowercase().contains("wsman") || v_path.to_lowercase().contains("winrm") {
                                            winrm_active_in_iis = true;
                                            winrm_details.push(("VirtualDirectory".to_string(), format!("{}{}|{}", site_name, v_path, v_phys_exp)));
                                        }

                                        if v_path == "/" && phys_path.is_empty() {
                                            phys_path = v_phys_exp;
                                        } else if !v_phys_exp.is_empty() {
                                            child_vdirs.push((v_path, v_phys_exp));
                                        }
                                    }
                                }
                            }
                        }

                        // AppPool identity
                        let (id_type, user_name) = pool_identities
                            .get(&pool_name)
                            .cloned()
                            .unwrap_or_else(|| (default_pool_id.clone(), default_pool_user.clone()));

                        let effective_user = if id_type == "SpecificUser" && !user_name.is_empty() {
                            user_name.clone()
                        } else if id_type == "ApplicationPoolIdentity" {
                            format!(r"IIS AppPool\{}", pool_name)
                        } else {
                            id_type.clone()
                        };

                        let is_admin = effective_user.to_lowercase().contains("administrator")
                            || effective_user.to_lowercase() == "localsystem"
                            || id_type.to_lowercase() == "localsystem";

                        // Logging configuration
                        let mut log_enabled = "true".to_string();
                        let mut log_format = default_log_format.clone();
                        let mut log_dir = default_log_dir.clone();

                        if let Some(log_pos) = site_block.find("<logFile ") {
                            let log_rest = &site_block[log_pos..];
                            if let Some(log_end) = log_rest.find('>') {
                                let log_tag = &log_rest[..log_end];
                                if let Some(en) = extract_xml_attr(log_tag, "enabled") {
                                    log_enabled = en;
                                }
                                if let Some(fmt) = extract_xml_attr(log_tag, "logFormat") {
                                    log_format = fmt;
                                }
                                if let Some(dir) = extract_xml_attr(log_tag, "directory") {
                                    log_dir = expand_iis_env_vars(&dir);
                                }
                            }
                        }

                        // Display Site Info
                        writeln!(out, "\n[+] Site: {} (ID: {}, State: {})", site_name, site_id, state)?;
                        writeln!(out, "{}", format!("  Bindings: {}", bindings_str).green())?;
                        writeln!(out, "  AppPool: {}", pool_name)?;
                        if id_type.eq_ignore_ascii_case("applicationpoolidentity") {
                            writeln!(out, "  Identity: {} ({})", effective_user, id_type)?;
                        } else {
                            writeln!(
                                out,
                                "{}",
                                format!("  Identity: {} ({})", effective_user, id_type).yellow()
                            )?;
                        }
                        if is_admin {
                            writeln!(
                                out,
                                "{}",
                                format!("  !!! RUNNING AS ADMINISTRATOR: {} ({})", effective_user, id_type)
                                    .red()
                                    .bold()
                            )?;
                        }
                        writeln!(out, "{}", format!("  Physical Path: {}", phys_path).green())?;

                        for (v_path, v_phys) in &child_vdirs {
                            writeln!(out, "  [+] Virtual Directory: {} -> {}", v_path, v_phys)?;
                            if !v_phys.is_empty() && !paths_to_scan.contains(v_phys) {
                                paths_to_scan.push(v_phys.clone());
                            }
                        }

                        // Logging Audit
                        if log_enabled.eq_ignore_ascii_case("false") {
                            writeln!(
                                out,
                                "{}",
                                format!("  !!! LOGGING DISABLED for site '{}'", site_name)
                                    .red()
                                    .bold()
                            )?;
                        } else {
                            writeln!(out, "  Logging: Enabled (Format: {})", log_format)?;
                            if printlog && !log_dir.is_empty() {
                                writeln!(out, "  Log Directory: {}", log_dir)?;
                                let site_log_dir = std::path::Path::new(&log_dir).join(format!("W3SVC{}", site_id));
                                let target_dir = if site_log_dir.exists() {
                                    site_log_dir
                                } else {
                                    std::path::PathBuf::from(&log_dir)
                                };

                                if target_dir.exists() {
                                    if let Ok(entries) = std::fs::read_dir(&target_dir) {
                                        let mut files = Vec::new();
                                        for entry in entries.filter_map(|e| e.ok()) {
                                            let path = entry.path();
                                            if path.is_file() {
                                                let size = entry.metadata().map(|m| m.len()).unwrap_or(0);
                                                files.push((
                                                    path.file_name().unwrap_or_default().to_string_lossy().to_string(),
                                                    size,
                                                ));
                                            }
                                        }
                                        if files.is_empty() {
                                            writeln!(out, "    (No log files found in {})", target_dir.display())?;
                                        } else {
                                            writeln!(out, "    Log Files in {}:", target_dir.display())?;
                                            for (fname, size) in files {
                                                writeln!(out, "      - {} ({} bytes)", fname, size)?;
                                            }
                                        }
                                    }
                                } else {
                                    writeln!(out, "    (Log directory does not exist: {})", target_dir.display())?;
                                }
                            }
                        }

                        if !phys_path.is_empty() && !paths_to_scan.contains(&phys_path) {
                            paths_to_scan.push(phys_path);
                        }
                    }
                }
            }
        }
    }

    if found_sites == 0 {
        writeln!(out, "No IIS sites found.")?;
    }

    // WinRM IIS Extension
    let winrm_feat_installed = std::path::Path::new(r"C:\Windows\System32\wsmsvc.dll").exists();

    writeln!(out, "\n==== WINRM IIS EXTENSION")?;
    if winrm_active_in_iis {
        writeln!(
            out,
            "{}",
            "  !!! WINRM RUNNING THROUGH IIS (Remote WSMan / PowerShell endpoint active over IIS!)"
                .red()
                .bold()
        )?;
        for (kind, detail) in &winrm_details {
            writeln!(out, "{}", format!("    - [{}] {}", kind, detail).yellow())?;
        }
    } else if winrm_feat_installed {
        writeln!(
            out,
            "  [!] WinRM-IIS-Ext feature is installed, but no active endpoints configured in IIS."
        )?;
    } else {
        writeln!(out, "  [-] WinRM-IIS-Ext feature not installed.")?;
    }

    // IIS Modules
    writeln!(out, "\n==== IIS MODULES (BACKDOOR CHECK)")?;
    if custom_modules.is_empty() && managed_modules.is_empty() {
        writeln!(out, "  No custom or suspicious IIS modules detected.")?;
    } else {
        for (name, img, reason) in custom_modules {
            writeln!(
                out,
                "{}",
                format!("  !!! CUSTOM / SUSPICIOUS IIS MODULE: {} [Image: {}] ({})", name, img, reason)
                    .red()
                    .bold()
            )?;
        }
        for (name, mod_type) in managed_modules {
            writeln!(
                out,
                "{}",
                format!("  [!] Custom Managed Module: {} [Type: {}]", name, mod_type).yellow()
            )?;
        }
    }

    // ISAPI Filters
    writeln!(out, "\n==== IIS ISAPI FILTERS")?;
    if isapi_filters.is_empty() {
        writeln!(out, "  No custom or suspicious ISAPI filters detected.")?;
    } else {
        for (name, path, reason) in isapi_filters {
            writeln!(
                out,
                "{}",
                format!("  !!! SUSPICIOUS ISAPI FILTER: {} [Path: {}] ({})", name, path, reason)
                    .red()
                    .bold()
            )?;
        }
    }

    // Handler Mappings
    writeln!(out, "\n==== IIS HANDLER MAPPINGS")?;
    if custom_handlers.is_empty() {
        writeln!(out, "  No custom or suspicious IIS handler mappings detected.")?;
    } else {
        for (name, path, verb, script_or_type, reason, scope) in custom_handlers {
            writeln!(
                out,
                "{}",
                format!(
                    "  !!! SUSPICIOUS HANDLER MAPPING [{}]: {} [Path: {}, Verb: {}, Target: {}] ({})",
                    scope, name, path, verb, script_or_type, reason
                )
                .red()
                .bold()
            )?;
        }
    }

    // Scan site files for web shells and web.config tampering (Feature 5)
    if !paths_to_scan.is_empty() {
        writeln!(out, "\n==== IIS WEB SHELL & CONTENT SCAN")?;
        for path in paths_to_scan {
            scan_web_files(out, &path, extended_scan)?;
        }
    }

    Ok(())
}

use walkdir::WalkDir;
use colored::*;
use regex::Regex;
use std::fs;

pub fn scan_web_files(out: &mut impl PagerOutput, root: &str, extended_scan: bool) -> eyre::Result<()> {
    let clean_root = root.trim_matches(|c| c == '\"' || c == ' ');
    
    if !std::path::Path::new(clean_root).exists() {
        return Ok(());
    }

    writeln!(out, "Scanning directory: {}", clean_root)?;

    // 1. Config & Counters
    let danger_exts = ["php", "aspx", "asp", "jsp", "jspx", "cfm", "ashx", "asax", "html"];
    let pii_exts = ["csv", "txt", "xls", "xlsx"];
    let mut web_file_count = 0;
    let max_display = 5;
    const MAX_FILE_SIZE: u64 = 5 * 1024 * 1024; 

    // 2. Optimized Regex Patterns
    let shell_regex = Regex::new(r"(?i)(?:[s$][^a-zA-Z0-9]{0,2}[h][^a-zA-Z0-9]{0,2}[e3][^a-zA-Z0-9]{0,2}[l1][^a-zA-Z0-9]{0,2}[l1]|p[^a-zA-Z0-9]{0,2}[o0][^a-zA-Z0-9]{0,2}ny|b374k|c99|r57|backd[o0]{2}r)").unwrap();
    let webshell_combo_regex = Regex::new(r"(?i)(system|exec|shell_exec|passthru|popen|proc_open)\s*\([^)]*\$_(GET|POST|REQUEST|COOKIE|SERVER)").unwrap();
    let obfuscation_regex = Regex::new(r"(?i)(base64_decode\s*\(|gzinflate\s*\(|str_rot13\s*\(|eval\s*\()").unwrap();
    
    // 3. Execution
    for entry in WalkDir::new(clean_root).into_iter().filter_map(|e| e.ok()) {
        let path = entry.path();
        if !path.is_file() { continue; }

        let file_name = path.file_name().unwrap_or_default().to_string_lossy();
        let file_name_lower = file_name.to_lowercase();

        // FEATURE 5: Detect suspicious web.config files (subdirectories, overrides, execution policy)
        if file_name_lower == "web.config" {
            let is_subfolder = path.parent().map(|p| p != std::path::Path::new(clean_root)).unwrap_or(false);
            let mut sus_indicators = Vec::new();

            if is_subfolder {
                sus_indicators.push("Subdirectory override");
            }

            if let Ok(metadata) = fs::metadata(path) {
                if metadata.len() <= MAX_FILE_SIZE {
                    if let Ok(content) = fs::read_to_string(path) {
                        let c_low = content.to_lowercase();
                        if c_low.contains("accesspolicy") && (c_low.contains("execute") || c_low.contains("script")) {
                            sus_indicators.push("Execution accessPolicy enabled");
                        }
                        if c_low.contains("<handlers") || c_low.contains("<httphandlers") {
                            sus_indicators.push("Handler definitions");
                        }
                        if c_low.contains("<modules") || c_low.contains("<httpmodules") {
                            sus_indicators.push("Module definitions");
                        }
                        if c_low.contains("scriptprocessor") {
                            sus_indicators.push("Custom scriptProcessor");
                        }
                        if c_low.contains("<rewrite") || c_low.contains("<redirect") {
                            sus_indicators.push("URL Rewrite/Redirect");
                        }
                    }
                }
            }

            if is_subfolder {
                writeln!(
                    out,
                    "{}",
                    format!(
                        "  !!! SUSPICIOUS SUBDIRECTORY web.config: {} [{}]",
                        path.display(),
                        sus_indicators.join(", ")
                    )
                    .red()
                    .bold()
                )?;
            } else if sus_indicators.iter().any(|&i| i != "Subdirectory override") {
                writeln!(
                    out,
                    "{}",
                    format!(
                        "  [!] Root web.config with custom handlers/policies: {} [{}]",
                        path.display(),
                        sus_indicators.join(", ")
                    )
                    .yellow()
                )?;
            }
            continue;
        }
        
        if let Some(ext) = path.extension().and_then(|s| s.to_str()) {
            let ext_lower = ext.to_lowercase();
            
            // FEATURE: PII Check (Always Show)
            if pii_exts.contains(&ext_lower.as_str()) {
                writeln!(out, "{}", format!("  [$] Potential PII file: {}", path.display()).green())?;
                continue; 
            }

            if danger_exts.contains(&ext_lower.as_str()) {
                let mut is_sus = false;
                let mut reason = "";

                // Check Filename Pattern
                if shell_regex.is_match(&file_name) {
                    is_sus = true;
                    reason = "Suspicious Filename";
                }

                // Check Content (-e flag)
                if !is_sus && extended_scan {
                    if let Ok(metadata) = fs::metadata(path) {
                        if metadata.len() <= MAX_FILE_SIZE {
                            if let Ok(content) = fs::read_to_string(path) {
                                let c_low = content.to_lowercase();
                                if webshell_combo_regex.is_match(&c_low) {
                                    is_sus = true;
                                    reason = "Exploit Combo Pattern";
                                } else if obfuscation_regex.is_match(&c_low) {
                                    is_sus = true;
                                    reason = "Obfuscation Detected";
                                }
                            }
                        }
                    }
                }

                // Logic for printing
                if is_sus {
                    // Backdoors ALWAYS get printed
                    writeln!(out, "{}", format!("!!! POSSIBLE WEB SHELL: {} [{}]", path.display(), reason).red().bold())?;
                } else if ext_lower == "php" || ext_lower == "aspx" {
                    // Normal files obey the "Max 5" rule
                    web_file_count += 1;
                    if web_file_count <= max_display {
                        writeln!(out, "  [+] Web file: {}", path.display())?;
                    }
                }
            }
        }
    }

    // 4. Per-site Summary
    if web_file_count > max_display {
        writeln!(out, "  [...] and {} more web files in this directory.", web_file_count - max_display)?;
    }

    Ok(())
}

// Check for python web servers
fn enum_python_sites(out: &mut impl PagerOutput) -> eyre::Result<()> {

    writeln!(out, "\n==== PYTHON WEB SERVERS")?;

    let (_, ps) = qx("wmic process get CommandLine")?;

    for line in ps.lines() {

        if line.contains("flask")
            || line.contains("django")
            || line.contains("uvicorn")
            || line.contains("gunicorn")
            || line.contains("http.server")
        {
            writeln!(out, "Python web process: {}", ellipsize(200, line))?;
        }
    }

    Ok(())
}

// Check startup items, similar to autoruns. Ignore Microsoft ones
fn enum_startup_items(out: &mut impl PagerOutput) -> eyre::Result<()> {
    writeln!(out, "\n==== SUSPICIOUS STARTUP ITEMS (SIGNATURE CHECK)")?;
    let script = r#"
        $locations = @(
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
            "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
            "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
            "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache"
        )
        
        foreach ($loc in $locations) {
            $items = Get-ItemProperty $loc -ErrorAction SilentlyContinue
            if (-not $items) { continue }
            
            $items.PSObject.Properties | Where-Object { $_.Name -notin @("PSPath", "PSParentPath", "PSChildName", "PSDrive", "PSProvider") } | ForEach-Object {
                $name = $_.Name
                $val = $_.Value
                
                # Regex to extract the executable path from the command line string
                $path = ""
                if ($val -match '^"([^"]+)"') {
                    $path = $matches[1]
                } elseif ($val -match '^([^ ]+\.(exe|dll|bat|ps1|py|vbs))') {
                    $path = $matches[1]
                } else {
                    $path = $val -replace ' -.*','' # Rough fallback
                }

                if (Test-Path $path -PathType Leaf) {
                    $sig = Get-AuthenticodeSignature $path
                    if ($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notmatch 'O=Microsoft Corporation') {
                        "Registry ($loc): $name"
                        "  -> Value: $val"
                        "  -> Status: $($sig.Status) | Signer: $($sig.SignerCertificate.Subject)"
                        ""
                    }
                } elseif ($val -match '\.(exe|dll|bat|ps1|py)') {
                    # Path was either unresolvable or had complex args, but it looks like a binary/script
                    "Unresolved Registry Path ($loc): $name"
                    "  -> Value: $val"
                    ""
                }
            }
        }
        
        # Check Startup Folders
        $folders = @("$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp", "$env:AppData\Microsoft\Windows\Start Menu\Programs\Startup")
        foreach ($f in $folders) {
            Get-ChildItem $f -File -ErrorAction SilentlyContinue | ForEach-Object { 
                $path = $_.FullName
                $sig = Get-AuthenticodeSignature $path
                if ($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notmatch 'O=Microsoft Corporation') {
                    "Folder ($f): $($_.Name)"
                    "  -> Status: $($sig.Status) | Signer: $($sig.SignerCertificate.Subject)"
                    ""
                }
            }
        }
    "#;
    let output = std::process::Command::new("powershell.exe")
        .args(&["-NoProfile", "-Command", script])
        .output()?;
    
    let res = String::from_utf8_lossy(&output.stdout);
    if res.trim().is_empty() {
        writeln!(out, "No unsigned or non-Microsoft startup items found.")?;
    } else {
        writeln!(out, "{}", res.trim())?;
    }
    Ok(())
}

// Enumerate FTP sites
fn enum_ftp_sites(out: &mut impl PagerOutput) -> eyre::Result<()> {
    writeln!(out, "\n==== FTP SERVERS (IIS & FILEZILLA)")?;
    let mut found = false;

    // 1. IIS FTP Discovery
    let iis_config = std::path::Path::new(r"C:\Windows\System32\inetsrv\config\applicationHost.config");
    if iis_config.exists() {
        if let Ok(content) = std::fs::read_to_string(iis_config) {
            if let Some(sites_start) = content.find("<sites>") {
                if let Some(sites_end) = content[sites_start..].find("</sites>") {
                    let section = &content[sites_start..sites_start + sites_end];
                    for site_block in section.split("<site ") {
                        if let Some(site_tag_end) = site_block.find('>') {
                            let site_tag = &site_block[..site_tag_end];
                            if let Some(site_name) = extract_xml_attr(site_tag, "name") {
                                // Find root physical path
                                let mut phys_path = String::new();
                                for line in site_block.lines() {
                                    let trimmed = line.trim();
                                    if trimmed.starts_with("<virtualDirectory ") {
                                        let v_path = extract_xml_attr(trimmed, "path").unwrap_or_default();
                                        if v_path == "/" {
                                            phys_path = expand_iis_env_vars(&extract_xml_attr(trimmed, "physicalPath").unwrap_or_default());
                                            break;
                                        }
                                    }
                                }

                                // Check FTP bindings
                                if let Some(b_start) = site_block.find("<bindings>") {
                                    if let Some(b_end) = site_block[b_start..].find("</bindings>") {
                                        let b_sec = &site_block[b_start..b_start + b_end];
                                        for b_line in b_sec.lines() {
                                            let trimmed = b_line.trim();
                                            if trimmed.starts_with("<binding ") {
                                                let proto = extract_xml_attr(trimmed, "protocol").unwrap_or_default();
                                                if proto.eq_ignore_ascii_case("ftp") {
                                                    let info = extract_xml_attr(trimmed, "bindingInformation").unwrap_or_default();
                                                    writeln!(out, "[!] IIS FTP Site: {} | Listen: {} | Root: {}", site_name, info, phys_path)?;
                                                    found = true;
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // 2. FileZilla Discovery
    if let Ok(output) = std::process::Command::new("sc.exe").args(&["query", "FileZilla Server"]).output() {
        let sc_text = String::from_utf8_lossy(&output.stdout);
        if sc_text.contains("STATE") {
            let status = if sc_text.contains("RUNNING") {
                "Running"
            } else if sc_text.contains("STOPPED") {
                "Stopped"
            } else {
                "Installed"
            };
            writeln!(out, "[+] FileZilla Service is {}", status)?;
            found = true;

            let fz_paths = [
                r"C:\Program Files\FileZilla Server\FileZilla Server.xml",
                r"C:\Program Files (x86)\FileZilla Server\FileZilla Server.xml",
            ];
            for fz_path in fz_paths {
                if let Ok(fz_content) = std::fs::read_to_string(fz_path) {
                    for line in fz_content.lines() {
                        let trimmed = line.trim();
                        if trimmed.contains(r#"Name="Directory""#) || trimmed.contains(r#"name="Directory""#) {
                            if let Some(start) = trimmed.find('>') {
                                let rest = &trimmed[start + 1..];
                                if let Some(end) = rest.find('<') {
                                    let dir_path = rest[..end].trim();
                                    if !dir_path.is_empty() {
                                        writeln!(out, "[!] FileZilla FTP Root Found: {}", dir_path)?;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    if !found {
        writeln!(out, "No FTP servers detected.")?;
    }

    Ok(())
}

// Check System32 for unsigned dll's, exe's, or .ps1's. without -d just checks for .exe
fn enum_system32_unsigned(out: &mut impl PagerOutput, detailed: bool) -> eyre::Result<()> {
    writeln!(out, "\n==== SUSPICIOUS FILES IN SYSTEM32")?;

    let extensions = if detailed {
        "@('*.exe', '*.dll', '*.bat', '*.ps1')"
    } else {
        "@('*.exe')"
    };

    let script = format!(
        r#"
        $extensions = {extensions}
        Get-ChildItem -Path C:\Windows\System32\* -Include $extensions | ForEach-Object {{
            $path = $_.FullName
            if ($_.Extension -match '\.(bat|ps1)') {{
                "Script Found: $path"
            }} else {{
                $sig = Get-AuthenticodeSignature $path
                if ($sig.Status -ne 'Valid') {{
                    "Unsigned File: $path"
                }} elseif ($sig.SignerCertificate.Subject -notlike '*Microsoft*') {{
                    "Non-MS Signed: $path (Signed by: $($sig.SignerCertificate.Subject))"
                }}
            }}
        }}
        "#
    );

    let output = std::process::Command::new("powershell.exe")
        .args(&["-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", &script])
        .output()?;

    if output.status.success() {
        let result = String::from_utf8_lossy(&output.stdout);
        let trimmed = result.trim();
        if trimmed.is_empty() {
            writeln!(out, "No suspicious files found.")?;
        } else {
            writeln!(out, "{}", trimmed)?;
        }
    } else {
        writeln!(out, "PowerShell Error: {}", String::from_utf8_lossy(&output.stderr))?;
    }

    Ok(())
}

fn enum_winrm(out: &mut impl PagerOutput) -> eyre::Result<()> {
    writeln!(out, "\n==== WINRM LISTENERS")?;
    let output = std::process::Command::new("winrm.cmd")
        .args(&["enumerate", "winrm/config/listener"])
        .output();

    let mut listeners = Vec::new();
    if let Ok(out_cmd) = output {
        let text = String::from_utf8_lossy(&out_cmd.stdout);
        let mut cur_addr = String::new();
        let mut cur_transport = String::new();
        let mut cur_port = String::new();

        for line in text.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("Address = ") {
                cur_addr = trimmed.trim_start_matches("Address = ").trim().to_string();
            } else if trimmed.starts_with("Transport = ") {
                cur_transport = trimmed.trim_start_matches("Transport = ").trim().to_string();
            } else if trimmed.starts_with("Port = ") {
                cur_port = trimmed.trim_start_matches("Port = ").trim().to_string();
            } else if trimmed.is_empty() || trimmed == "Listener" {
                if !cur_transport.is_empty() {
                    listeners.push(format!("Address: {} | Transport: {} | Port: {}", cur_addr, cur_transport, cur_port));
                    cur_addr.clear();
                    cur_transport.clear();
                    cur_port.clear();
                }
            }
        }
        if !cur_transport.is_empty() {
            listeners.push(format!("Address: {} | Transport: {} | Port: {}", cur_addr, cur_transport, cur_port));
        }
    }

    if listeners.is_empty() {
        writeln!(out, "No WinRM listeners found or WinRM is not configured.")?;
    } else {
        for l in listeners {
            writeln!(out, "{}", l)?;
        }
    }
    Ok(())
}

// Enumerate Local Admins and Privileged Accounts
fn enum_local_admins(out: &mut impl PagerOutput) -> eyre::Result<()> {
    writeln!(out, "\n==== LOCAL ADMINS & PRIVILEGED ACCOUNTS")?;
    let groups = ["Administrators", "Remote Management Users", "Remote Desktop Users"];
    let mut total_found = 0;

    for group in groups {
        let output = std::process::Command::new("net.exe")
            .args(&["localgroup", group])
            .output();

        if let Ok(out_cmd) = output {
            let text = String::from_utf8_lossy(&out_cmd.stdout);
            let mut members = Vec::new();
            let mut in_members = false;

            for line in text.lines() {
                let trimmed = line.trim();
                if trimmed.starts_with("-------------------------------------------------------------------------------") {
                    in_members = true;
                    continue;
                }
                if in_members {
                    if trimmed.is_empty() {
                        continue;
                    }
                    if trimmed.eq_ignore_ascii_case("The command completed successfully.") {
                        break;
                    }
                    members.push(trimmed.to_string());
                }
            }

            if !members.is_empty() {
                writeln!(out, "Group: {}", group)?;
                for m in members {
                    writeln!(out, "  - {}", m)?;
                    total_found += 1;
                }
            }
        }
    }

    if total_found == 0 {
        writeln!(out, "No local privileged accounts found (or script ran without sufficient permissions).")?;
    }
    Ok(())
}

