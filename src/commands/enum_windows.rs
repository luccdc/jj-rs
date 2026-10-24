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
    /// Enumerate Microsoft SQL Server (MSSQL) instances, databases, logins, and security configuration
    #[command(visible_alias("sql"))]
    Mssql {
        /// Show all database tables including system database tables (master, msdb)
        #[arg(long)]
        all_tables: bool,

        /// Specify a target SQL Server instance name (e.g. BINGUS or MSSQLSERVER)
        #[arg(short, long)]
        instance: Option<String>,
    },
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
            Some(EnumSubcommands::Mssql { all_tables, instance }) => {
                enum_mssql(&mut ob, all_tables, instance.as_deref())?
            }
            
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
                enum_mssql(&mut ob, false, None)?;
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
    let output = crate::utils::run_powershell(script)?;
    
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

    let output = crate::utils::run_powershell(&script)?;

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

// =========================================================================
// Microsoft SQL Server (MSSQL) Enumeration
// =========================================================================

#[derive(Debug, Clone)]
struct MssqlInstance {
    instance_name: String,
    instance_id: String,
    service_name: String,
}

struct SqlDbInfo {
    name: String,
    database_id: String,
    state_desc: String,
    recovery_model: String,
    collation: String,
    is_trustworthy: bool,
    is_encrypted: bool,
    is_read_only: bool,
    is_auto_close: bool,
}

struct SqlFileInfo {
    db_name: String,
    logical_name: String,
    type_desc: String,
    physical_name: String,
    state_desc: String,
    size_mb: String,
}

struct SqlLoginInfo {
    name: String,
    type_desc: String,
    is_disabled: bool,
    is_sysadmin: bool,
    roles: String,
    default_db: String,
}

struct SqlTableInfo {
    db_name: String,
    schema: String,
    table_name: String,
    row_count: String,
}

fn enum_mssql(out: &mut impl PagerOutput, show_all_tables: bool, target_instance: Option<&str>) -> eyre::Result<()> {
    writeln!(out, "\n==== MICROSOFT SQL SERVER (MSSQL) ENUMERATION")?;

    let instances = find_mssql_instances();
    if instances.is_empty() {
        writeln!(
            out,
            "{}",
            "[-] Microsoft SQL Server is not installed or no instances detected.".yellow()
        )?;
        return Ok(());
    }

    let computer_name = std::env::var("COMPUTERNAME").unwrap_or_default();
    let mut audited = 0;

    for inst in &instances {
        if let Some(target) = target_instance {
            if !inst.instance_name.eq_ignore_ascii_case(target)
                && !inst.instance_id.eq_ignore_ascii_case(target)
                && !inst.service_name.eq_ignore_ascii_case(target)
            {
                continue;
            }
        }

        audited += 1;
        audit_mssql_instance(out, inst, &computer_name, show_all_tables)?;
    }

    if audited == 0 {
        if let Some(target) = target_instance {
            writeln!(
                out,
                "{}",
                format!("[-] Specified SQL instance '{}' was not found.", target).yellow()
            )?;
        }
    }

    Ok(())
}

fn find_mssql_instances() -> Vec<MssqlInstance> {
    let mut instances = Vec::new();

    // 1. Check registry: HKLM\SOFTWARE\Microsoft\Microsoft SQL Server\Instance Names\SQL
    let sql_inst_key = r"HKLM\SOFTWARE\Microsoft\Microsoft SQL Server\Instance Names\SQL";
    for line in reg_query_lines(sql_inst_key) {
        if let Some((name, _, val)) = parse_reg_value(&line) {
            let service_name = if name.eq_ignore_ascii_case("MSSQLSERVER") {
                "MSSQLSERVER".to_string()
            } else {
                format!("MSSQL${}", name)
            };
            instances.push(MssqlInstance {
                instance_name: name,
                instance_id: val,
                service_name,
            });
        }
    }

    // 2. Check InstalledInstances value under HKLM\SOFTWARE\Microsoft\Microsoft SQL Server
    if instances.is_empty() {
        if let Some(val) = reg_query_value(r"HKLM\SOFTWARE\Microsoft\Microsoft SQL Server", "InstalledInstances") {
            for inst_name in val.split('\0').chain(val.split_whitespace()) {
                let inst_name = inst_name.trim();
                if !inst_name.is_empty() && !instances.iter().any(|i| i.instance_name.eq_ignore_ascii_case(inst_name)) {
                    let service_name = if inst_name.eq_ignore_ascii_case("MSSQLSERVER") {
                        "MSSQLSERVER".to_string()
                    } else {
                        format!("MSSQL${}", inst_name)
                    };
                    instances.push(MssqlInstance {
                        instance_name: inst_name.to_string(),
                        instance_id: inst_name.to_string(),
                        service_name,
                    });
                }
            }
        }
    }

    // 3. Fallback: Check for running/registered Windows services
    if instances.is_empty() {
        if sc_query_service("MSSQLSERVER").is_some() {
            instances.push(MssqlInstance {
                instance_name: "MSSQLSERVER".to_string(),
                instance_id: "MSSQLSERVER".to_string(),
                service_name: "MSSQLSERVER".to_string(),
            });
        }
    }

    instances
}

fn audit_mssql_instance(
    out: &mut impl PagerOutput,
    inst: &MssqlInstance,
    computer_name: &str,
    show_all_tables: bool,
) -> eyre::Result<()> {
    writeln!(
        out,
        "\n{}",
        format!("[+] Instance: {} (ID: {})", inst.instance_name, inst.instance_id).bold()
    )?;

    // Setup and version metadata from registry
    let setup_key = format!(r"HKLM\SOFTWARE\Microsoft\Microsoft SQL Server\{}\Setup", inst.instance_id);
    let version = reg_query_value(&setup_key, "Version").unwrap_or_else(|| "Unknown".to_string());
    let edition = reg_query_value(&setup_key, "Edition").unwrap_or_else(|| "Unknown".to_string());
    let sql_data_root = reg_query_value(&setup_key, "SQLDataRoot").unwrap_or_default();
    let sql_bin_root = reg_query_value(&setup_key, "SQLBinRoot").unwrap_or_default();

    // Service inspection
    let svc_status = sc_query_service(&inst.service_name);
    let svc_qc = sc_qc_service(&inst.service_name);

    let display_name = svc_qc
        .get("DISPLAY_NAME")
        .cloned()
        .unwrap_or_else(|| format!("SQL Server ({})", inst.instance_name));
    let service_account = svc_qc
        .get("SERVICE_START_NAME")
        .cloned()
        .unwrap_or_else(|| "Unknown".to_string());
    let start_type = svc_qc.get("START_TYPE").cloned().unwrap_or_default();

    let (state_num, state_text) = svc_status.unwrap_or_else(|| ("0".to_string(), "NOT_FOUND".to_string()));
    let is_running = state_text.eq_ignore_ascii_case("RUNNING") || state_num == "4";

    writeln!(out, "    Display Name:    {}", display_name)?;
    writeln!(out, "    Edition:         {}", edition)?;
    writeln!(out, "    Version:         {}", version)?;
    writeln!(out, "    Service Name:    {}", inst.service_name)?;

    // Service Account security evaluation
    let is_sys_account = service_account.to_lowercase().contains("localsystem")
        || service_account.to_lowercase() == "system"
        || service_account.to_lowercase().contains("administrator");

    if is_sys_account {
        writeln!(
            out,
            "{}",
            format!(
                "    Service Account: {} [!] CRITICAL: Running as SYSTEM/Administrator! Any xp_cmdshell execution has full OS privilege!",
                service_account
            )
            .red()
            .bold()
        )?;
    } else if service_account.to_lowercase().starts_with("nt service\\") {
        writeln!(
            out,
            "{}",
            format!("    Service Account: {} [OK: Isolated Virtual Account]", service_account).green()
        )?;
    } else {
        writeln!(out, "    Service Account: {}", service_account)?;
    }

    if is_running {
        writeln!(
            out,
            "{}",
            format!("    Service Status:  RUNNING (State: {}, Start: {})", state_num, start_type).green()
        )?;
    } else {
        writeln!(
            out,
            "{}",
            format!("    Service Status:  {} (Start: {})", state_text, start_type).yellow()
        )?;
    }

    // Read PID from registry uptime_pid or live processes
    let mssql_key = format!(r"HKLM\SOFTWARE\Microsoft\Microsoft SQL Server\{}\MSSQLServer", inst.instance_id);
    let uptime_pid_hex = reg_query_value(&mssql_key, "uptime_pid");
    let active_pid: Option<u32> = uptime_pid_hex.and_then(|h| {
        let clean = h.trim().trim_start_matches("0x");
        u32::from_str_radix(clean, 16).ok()
    });

    if let Some(pid) = active_pid {
        writeln!(out, "    Process ID:      {}", pid)?;
    }

    // ---------------------------------------------------------------------
    // Network & Listening Endpoints
    // ---------------------------------------------------------------------
    writeln!(out, "\n  [Network & Listening Endpoints]")?;

    let super_sock_key = format!(r"{}\SuperSocketNetLib", mssql_key);
    let tcp_key = format!(r"{}\Tcp", super_sock_key);
    let tcp_enabled_val = reg_query_value(&tcp_key, "Enabled").unwrap_or_default();
    let tcp_enabled = tcp_enabled_val == "0x1" || tcp_enabled_val == "1";
    let listen_all_val = reg_query_value(&tcp_key, "ListenOnAllIPs").unwrap_or_default();
    let listen_all = listen_all_val == "0x1" || listen_all_val == "1";

    if tcp_enabled {
        writeln!(
            out,
            "{}",
            format!("    TCP/IP Protocol:  Enabled (ListenOnAllIPs: {})", listen_all).green()
        )?;
    } else {
        writeln!(out, "    TCP/IP Protocol:  Disabled in Configuration")?;
    }

    let ip_all_key = format!(r"{}\IPAll", tcp_key);
    let ip_all_port = reg_query_value(&ip_all_key, "TcpPort").unwrap_or_default();
    let ip_all_dyn = reg_query_value(&ip_all_key, "TcpDynamicPorts").unwrap_or_default();
    if !ip_all_port.is_empty() {
        writeln!(out, "    Configured Port:  Static {}", ip_all_port)?;
    }
    if !ip_all_dyn.is_empty() && ip_all_dyn != "0" {
        writeln!(out, "    Dynamic Port:     {}", ip_all_dyn)?;
    }

    // Dedicated Admin Connection (DAC)
    let dac_key = format!(r"{}\AdminConnection\Tcp", super_sock_key);
    let dac_port = reg_query_value(&dac_key, "TcpDynamicPorts").unwrap_or_default();
    if !dac_port.is_empty() {
        writeln!(out, "    Dedicated Admin:  Port {} (Local DAC)", dac_port)?;
    }

    // Shared Memory & Named Pipes
    let sm_val = reg_query_value(&format!(r"{}\Sm", super_sock_key), "Enabled").unwrap_or_default();
    let sm_enabled = sm_val == "0x1" || sm_val == "1";
    let np_val = reg_query_value(&format!(r"{}\Np", super_sock_key), "Enabled").unwrap_or_default();
    let np_enabled = np_val == "0x1" || np_val == "1";
    let np_pipe = reg_query_value(&format!(r"{}\Np", super_sock_key), "PipeName").unwrap_or_default();

    if sm_enabled {
        writeln!(out, "{}", "    Shared Memory:    Enabled [OK]".green())?;
    }
    if np_enabled {
        writeln!(
            out,
            "{}",
            format!("    Named Pipes:      Enabled (Pipe: {})", np_pipe).green()
        )?;
    } else {
        writeln!(out, "    Named Pipes:      Disabled")?;
    }

    // ForceEncryption & HideInstance
    let force_enc_val = reg_query_value(&super_sock_key, "ForceEncryption").unwrap_or_default();
    let force_enc = force_enc_val == "0x1" || force_enc_val == "1";
    if force_enc {
        writeln!(out, "{}", "    Network Traffic:  Encryption FORCED [OK]".green())?;
    } else {
        writeln!(
            out,
            "{}",
            "    Network Traffic:  [!] ForceEncryption is DISABLED (Traffic & credentials unencrypted on wire!)"
                .yellow()
        )?;
    }

    let hide_val = reg_query_value(&super_sock_key, "HideInstance").unwrap_or_default();
    let hide_inst = hide_val == "0x1" || hide_val == "1";
    if hide_inst {
        writeln!(out, "    Hide Instance:    Yes (Not responding to SQL Browser requests)")?;
    } else {
        writeln!(out, "    Hide Instance:    No (Instance visible to network scanners)")?;
    }

    // SQL Browser Service Check (UDP 1434)
    if let Some((_, b_state)) = sc_query_service("SQLBrowser") {
        if b_state.eq_ignore_ascii_case("RUNNING") {
            writeln!(
                out,
                "{}",
                "    SQL Browser Svc:  [!] RUNNING on UDP 1434 (Broadcasts instance names & dynamic ports to network!)"
                    .yellow()
            )?;
        } else {
            writeln!(out, "    SQL Browser Svc:  Stopped / Inactive")?;
        }
    }

    // Active OS Sockets via Win32 GetExtendedTcpTable/GetExtendedUdpTable
    if let Some(pid) = active_pid {
        let ports_res = crate::utils::ports::windows::list_ports();
        if let Ok(records) = ports_res {
            let listening: Vec<_> = records
                .into_iter()
                .filter(|r| r.pid == Some(pid) && r.state == crate::utils::ports::SocketState::Listen)
                .collect();

            if !listening.is_empty() {
                writeln!(out, "    Active OS Listening Sockets (PID {}):", pid)?;
                for s in listening {
                    let desc = if s.local_port == 1433 {
                        "Default SQL Port"
                    } else if !dac_port.is_empty() && s.local_port.to_string() == dac_port {
                        "Dedicated Admin Connection (DAC)"
                    } else {
                        "SQL Engine"
                    };
                    writeln!(
                        out,
                        "{}",
                        format!(
                            "      - {}:{} ({} Listen - {})",
                            s.local_address, s.local_port, s.socket_type, desc
                        )
                        .green()
                    )?;
                }
            }
        }
    }

    // ---------------------------------------------------------------------
    // Authentication & Storage Configuration
    // ---------------------------------------------------------------------
    writeln!(out, "\n  [Authentication & Storage Configuration]")?;

    let login_mode_val = reg_query_value(&mssql_key, "LoginMode").unwrap_or_default();
    if login_mode_val == "0x2" || login_mode_val == "2" {
        writeln!(
            out,
            "{}",
            "    Authentication:   [!] Mixed Mode (SQL Server & Windows Authentication) - SQL logins active & vulnerable to brute-force!"
                .yellow()
        )?;
    } else {
        writeln!(
            out,
            "{}",
            "    Authentication:   Windows Authentication Only [OK: Integrated Security Only]".green()
        )?;
    }

    // FILESTREAM Configuration
    let fs_key = format!(r"{}\Filestream", mssql_key);
    let fs_level = reg_query_value(&fs_key, "EnableLevel").unwrap_or_default();
    let fs_share = reg_query_value(&fs_key, "ShareName").unwrap_or_default();
    match fs_level.as_str() {
        "0x3" | "3" => {
            writeln!(
                out,
                "{}",
                format!(
                    "    FILESTREAM Level: [!] Level 3 (T-SQL, Local FS, and Remote Clients enabled via SMB share '\\\\{}\\{}')",
                    computer_name, fs_share
                )
                .yellow()
            )?;
        }
        "0x2" | "2" => {
            writeln!(out, "    FILESTREAM Level: Level 2 (T-SQL and Local File System)")?;
        }
        "0x1" | "1" => {
            writeln!(out, "    FILESTREAM Level: Level 1 (T-SQL only)")?;
        }
        _ => {
            writeln!(out, "{}", "    FILESTREAM Level: Disabled [OK]".green())?;
        }
    }

    let backup_dir = reg_query_value(&mssql_key, "BackupDirectory").unwrap_or_default();
    let err_log = reg_query_value(&format!(r"{}\Parameters", mssql_key), "SQLArg1")
        .map(|s| s.trim_start_matches("-e").to_string())
        .unwrap_or_default();

    if !sql_data_root.is_empty() {
        writeln!(out, "    SQL Data Root:    {}", sql_data_root)?;
    }
    if !sql_bin_root.is_empty() {
        writeln!(out, "    SQL Binary Root:  {}", sql_bin_root)?;
    }
    if !err_log.is_empty() {
        writeln!(out, "    Error Log Path:   {}", err_log)?;
    }
    if !backup_dir.is_empty() {
        writeln!(out, "    Backup Directory: {}", backup_dir)?;
    }

    // ---------------------------------------------------------------------
    // Live Database Engine Enumeration (Databases, Files, Tables, Logins, Security)
    // ---------------------------------------------------------------------
    if !is_running {
        writeln!(
            out,
            "\n  {}",
            format!(
                "  [!] Instance service '{}' is not running. Start service to query databases and logins.",
                inst.service_name
            )
            .yellow()
        )?;
        return Ok(());
    }

    let conn_target = if inst.instance_name.eq_ignore_ascii_case("MSSQLSERVER") {
        "localhost".to_string()
    } else {
        format!(r"localhost\{}", inst.instance_name)
    };

    let tsql_query = r#"
SET NOCOUNT ON;
SELECT 'SERVER_INFO', CAST(SERVERPROPERTY('ServerName') AS NVARCHAR(128)), CAST(SERVERPROPERTY('Edition') AS NVARCHAR(128)), CAST(SERVERPROPERTY('ProductVersion') AS NVARCHAR(128)), CAST(SERVERPROPERTY('ProductLevel') AS NVARCHAR(128)), CAST(SERVERPROPERTY('ProcessID') AS INT);
SELECT 'CONFIG', name, CAST(value AS INT), CAST(value_in_use AS INT) FROM sys.configurations WHERE name IN ('xp_cmdshell', 'Ole Automation Procedures', 'clr enabled', 'clr strict security', 'cross db ownership chaining', 'remote admin connections', 'Database Mail XPs', 'default trace enabled', 'scan for startup procs', 'remote access') ORDER BY name;
SELECT 'STARTUP_PROC', DB_NAME(), name FROM sys.procedures WHERE is_auto_executed = 1;
SELECT 'DB', name, database_id, state_desc, recovery_model_desc, ISNULL(collation_name, 'None'), is_trustworthy_on, is_encrypted, is_read_only, is_auto_close_on FROM sys.databases ORDER BY database_id;
SELECT 'FILE', DB_NAME(database_id), name, type_desc, physical_name, state_desc, size * 8 / 1024 FROM sys.master_files ORDER BY database_id, file_id;
SELECT 'LOGIN', p.name, p.type_desc, p.is_disabled, ISNULL(IS_SRVROLEMEMBER('sysadmin', p.name), 0), ISNULL(STRING_AGG(r.name, ', '), 'None'), ISNULL(p.default_database_name, 'master') FROM sys.server_principals p LEFT JOIN sys.server_role_members m ON p.principal_id = m.member_principal_id LEFT JOIN sys.server_principals r ON m.role_principal_id = r.principal_id WHERE p.type IN ('S', 'U', 'G') GROUP BY p.name, p.type_desc, p.is_disabled, p.default_database_name ORDER BY ISNULL(IS_SRVROLEMEMBER('sysadmin', p.name), 0) DESC, p.name;
SELECT 'SA_CHECK', name, is_disabled, is_policy_checked, is_expiration_checked, PWDCOMPARE('', password_hash) FROM sys.sql_logins WHERE name = 'sa';
EXEC sp_MSforeachdb 'USE [?]; SELECT ''TABLE'', DB_NAME(), s.name, t.name, SUM(p.rows) FROM sys.tables t JOIN sys.schemas s ON t.schema_id = s.schema_id JOIN sys.partitions p ON t.object_id = p.object_id AND p.index_id IN (0, 1) GROUP BY s.name, t.name';
EXEC sp_MSforeachdb 'USE [?]; IF DB_ID() > 4 SELECT ''GUEST_PERM'', DB_NAME(), dp.name, perm.permission_name, perm.state_desc FROM sys.database_permissions perm JOIN sys.database_principals dp ON perm.grantee_principal_id = dp.principal_id WHERE dp.name = ''guest'' AND perm.permission_name = ''CONNECT''';
"#;

    let query_result = run_sql_query(&conn_target, tsql_query);
    let sql_output = match query_result {
        Some(res) => res,
        None => {
            writeln!(
                out,
                "\n  {}",
                "  [!] Could not connect to database engine via Windows Authentication."
                    .yellow()
            )?;
            writeln!(
                out,
                "      Ensure current Windows user or BUILTIN\\Administrators is provisioned as sysadmin in SQL Server."
            )?;
            return Ok(());
        }
    };

    // Parse the output sections
    let mut configs: std::collections::HashMap<String, (String, String)> = std::collections::HashMap::new();
    let mut startup_procs: Vec<(String, String)> = Vec::new();
    let mut sa_check: Option<(bool, bool, bool, bool)> = None; // (is_disabled, policy_checked, expire_checked, is_blank)
    let mut guest_perms: Vec<(String, String, String, String)> = Vec::new();
    let mut dbs: Vec<SqlDbInfo> = Vec::new();
    let mut files: Vec<SqlFileInfo> = Vec::new();
    let mut logins: Vec<SqlLoginInfo> = Vec::new();
    let mut tables: Vec<SqlTableInfo> = Vec::new();

    for line in sql_output.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with("Msg ") || line.starts_with("(") {
            continue;
        }

        let parts: Vec<&str> = line.split('|').map(|s| s.trim()).collect();
        if parts.is_empty() {
            continue;
        }

        match parts[0] {
            "CONFIG" if parts.len() >= 4 => {
                configs.insert(parts[1].to_string(), (parts[2].to_string(), parts[3].to_string()));
            }
            "STARTUP_PROC" if parts.len() >= 3 => {
                startup_procs.push((parts[1].to_string(), parts[2].to_string()));
            }
            "SA_CHECK" if parts.len() >= 6 => {
                sa_check = Some((
                    parts[2] == "1",
                    parts[3] == "1",
                    parts[4] == "1",
                    parts[5] == "1",
                ));
            }
            "GUEST_PERM" if parts.len() >= 5 => {
                guest_perms.push((
                    parts[1].to_string(),
                    parts[2].to_string(),
                    parts[3].to_string(),
                    parts[4].to_string(),
                ));
            }
            "DB" if parts.len() >= 10 => {
                dbs.push(SqlDbInfo {
                    name: parts[1].to_string(),
                    database_id: parts[2].to_string(),
                    state_desc: parts[3].to_string(),
                    recovery_model: parts[4].to_string(),
                    collation: parts[5].to_string(),
                    is_trustworthy: parts[6] == "1",
                    is_encrypted: parts[7] == "1",
                    is_read_only: parts[8] == "1",
                    is_auto_close: parts[9] == "1",
                });
            }
            "FILE" if parts.len() >= 7 => {
                files.push(SqlFileInfo {
                    db_name: parts[1].to_string(),
                    logical_name: parts[2].to_string(),
                    type_desc: parts[3].to_string(),
                    physical_name: parts[4].to_string(),
                    state_desc: parts[5].to_string(),
                    size_mb: parts[6].to_string(),
                });
            }
            "LOGIN" if parts.len() >= 7 => {
                logins.push(SqlLoginInfo {
                    name: parts[1].to_string(),
                    type_desc: parts[2].to_string(),
                    is_disabled: parts[3] == "1",
                    is_sysadmin: parts[4] == "1",
                    roles: parts[5].to_string(),
                    default_db: parts[6].to_string(),
                });
            }
            "TABLE" if parts.len() >= 5 => {
                tables.push(SqlTableInfo {
                    db_name: parts[1].to_string(),
                    schema: parts[2].to_string(),
                    table_name: parts[3].to_string(),
                    row_count: parts[4].to_string(),
                });
            }
            _ => {}
        }
    }

    // ---------------------------------------------------------------------
    // Engine Security Posture & Threat Hunting Checks
    // ---------------------------------------------------------------------
    writeln!(out, "\n  [Engine Security Posture & Threat Hunting]")?;

    // 1. xp_cmdshell
    if let Some((_, in_use)) = configs.get("xp_cmdshell") {
        if in_use == "1" {
            writeln!(
                out,
                "{}",
                "    [!!!] CRITICAL: xp_cmdshell is ENABLED (Allows arbitrary OS command execution via SQL!)"
                    .red()
                    .bold()
            )?;
        } else {
            writeln!(out, "{}", "    xp_cmdshell:                 Disabled [OK]".green())?;
        }
    }

    // 2. OLE Automation Procedures (sp_OACreate)
    if let Some((_, in_use)) = configs.get("Ole Automation Procedures") {
        if in_use == "1" {
            writeln!(
                out,
                "{}",
                "    [!!!] CRITICAL: OLE Automation Procedures are ENABLED (sp_OACreate allows executing arbitrary binaries & COM objects!)"
                    .red()
                    .bold()
            )?;
        } else {
            writeln!(out, "{}", "    Ole Automation Procedures:   Disabled [OK]".green())?;
        }
    }

    // 3. CLR Integration & Strict Security
    if let Some((_, in_use)) = configs.get("clr enabled") {
        if in_use == "1" {
            writeln!(
                out,
                "{}",
                "    [!] CLR Integration is ENABLED (Allows executing .NET assemblies inside SQL Server process)"
                    .yellow()
            )?;
        } else {
            writeln!(out, "{}", "    CLR Integration:             Disabled [OK]".green())?;
        }
    }
    if let Some((_, in_use)) = configs.get("clr strict security") {
        if in_use == "0" {
            writeln!(
                out,
                "{}",
                "    [!!!] CLR Strict Security is DISABLED (Unsafe and unsigned assemblies allowed!)"
                    .red()
                    .bold()
            )?;
        } else {
            writeln!(out, "{}", "    CLR Strict Security:         Enabled [OK]".green())?;
        }
    }

    // 4. Cross-DB Ownership Chaining
    if let Some((_, in_use)) = configs.get("cross db ownership chaining") {
        if in_use == "1" {
            writeln!(
                out,
                "{}",
                "    [!] Cross-DB Ownership Chaining is ENABLED (Potential cross-database privilege escalation)"
                    .yellow()
            )?;
        } else {
            writeln!(out, "{}", "    Cross-DB Ownership Chaining: Disabled [OK]".green())?;
        }
    }

    // 5. Remote Admin Connections
    if let Some((_, in_use)) = configs.get("remote admin connections") {
        if in_use == "1" {
            writeln!(
                out,
                "{}",
                "    [!] Remote Dedicated Admin Connection (DAC) is ENABLED on port 1434".yellow()
            )?;
        } else {
            writeln!(out, "{}", "    Remote Admin Connections:    Disabled [OK]".green())?;
        }
    }

    // 6. Database Mail XPs
    if let Some((_, in_use)) = configs.get("Database Mail XPs") {
        if in_use == "1" {
            writeln!(
                out,
                "{}",
                "    [!] Database Mail XPs are ENABLED (Can be abused for exfiltration via email)".yellow()
            )?;
        } else {
            writeln!(out, "{}", "    Database Mail XPs:           Disabled [OK]".green())?;
        }
    }

    // 7. Default Trace Auditing
    if let Some((_, in_use)) = configs.get("default trace enabled") {
        if in_use == "0" {
            writeln!(
                out,
                "{}",
                "    [!] Default System Audit Trace is DISABLED (Activity is not being logged!)".yellow()
            )?;
        } else {
            writeln!(out, "{}", "    Default Trace Auditing:      Enabled [OK]".green())?;
        }
    }

    // 8. Startup Stored Procedures
    if startup_procs.is_empty() {
        writeln!(out, "{}", "    Startup Stored Procedures:   None [OK]".green())?;
    } else {
        for (db, proc_name) in &startup_procs {
            writeln!(
                out,
                "{}",
                format!(
                    "    [!!!] Startup Stored Procedure Detected: '{}.{}' (Persistence mechanism - executes on SQL Server restart!)",
                    db, proc_name
                )
                .red()
                .bold()
            )?;
        }
    }

    // ---------------------------------------------------------------------
    // Logins & Privileges
    // ---------------------------------------------------------------------
    writeln!(out, "\n  [Logins & Privileges]")?;

    let mut sysadmins = Vec::new();
    let mut other_logins = Vec::new();

    for l in logins {
        if l.is_sysadmin {
            sysadmins.push(l);
        } else {
            other_logins.push(l);
        }
    }

    writeln!(out, "    Sysadmin Accounts:")?;
    for l in &sysadmins {
        let class = classify_principal(&l.name, &l.type_desc, computer_name);
        let status_str = if l.is_disabled { " [Disabled]".yellow() } else { "".normal() };
        writeln!(
            out,
            "      - {} {} (Roles: {}) {}{}",
            l.name.bold(),
            class.cyan(),
            l.roles,
            "[SYSADMIN]".red().bold(),
            status_str
        )?;
    }

    if !other_logins.is_empty() {
        writeln!(out, "    Standard Logins:")?;
        for l in &other_logins {
            let class = classify_principal(&l.name, &l.type_desc, computer_name);
            let status_str = if l.is_disabled { " [Disabled]" } else { "" };
            let role_info = if l.roles == "None" {
                String::new()
            } else {
                format!(" (Roles: {})", l.roles)
            };
            writeln!(out, "      - {} {}{}{}", l.name, class, role_info, status_str)?;
        }
    }

    // SA Account Security Checks
    if let Some((is_disabled, pol_chk, exp_chk, is_blank)) = sa_check {
        if is_blank {
            writeln!(
                out,
                "{}",
                "    [!!!] CRITICAL: 'sa' (System Administrator) SQL Login has a BLANK PASSWORD!"
                    .red()
                    .bold()
            )?;
        }
        if !is_disabled {
            writeln!(
                out,
                "{}",
                "    [!] Default 'sa' (System Administrator) SQL Login is ENABLED!".yellow()
            )?;
        }
        if !pol_chk {
            writeln!(
                out,
                "{}",
                "    [!] 'sa' Password Policy Enforcement (complexity/lockout) is DISABLED".yellow()
            )?;
        }
        if !exp_chk {
            writeln!(out, "    'sa' Password Expiration: Disabled")?;
        }
    }

    // Guest / Anonymous Permissions
    for (db, _, perm, state) in &guest_perms {
        if perm == "CONNECT" && state == "GRANT" {
            writeln!(
                out,
                "{}",
                format!(
                    "    [!] ANONYMOUS/GUEST ACCESS: Database '{}' allows 'guest' user CONNECT access!",
                    db
                )
                .red()
                .bold()
            )?;
        }
    }

    // ---------------------------------------------------------------------
    // Databases & Files
    // ---------------------------------------------------------------------
    writeln!(out, "\n  [Databases & File Paths]")?;

    let mut files_by_db: std::collections::HashMap<String, Vec<&SqlFileInfo>> = std::collections::HashMap::new();
    for f in &files {
        files_by_db.entry(f.db_name.clone()).or_default().push(f);
    }

    for db in &dbs {
        let is_user_db = db.database_id.parse::<u32>().unwrap_or(0) > 4;
        let prefix = if is_user_db { "[User DB]".cyan() } else { "[System DB]".normal() };

        writeln!(
            out,
            "    {} Database: {} (ID: {}, State: {}, Recovery: {})",
            prefix,
            db.name.bold(),
            db.database_id,
            db.state_desc,
            db.recovery_model
        )?;

        if db.is_trustworthy && is_user_db {
            writeln!(
                out,
                "{}",
                format!(
                    "      [!!!] PRIVILEGE ESCALATION RISK: Database '{}' has TRUSTWORTHY = ON (Allows db_owner to elevate to sysadmin!)",
                    db.name
                )
                .red()
                .bold()
            )?;
        }

        if db.is_encrypted {
            writeln!(out, "      TDE Encryption: Enabled [OK]")?;
        }
        if db.is_auto_close {
            writeln!(
                out,
                "{}",
                format!("      [!] Auto-Close is ON for database '{}'", db.name).yellow()
            )?;
        }

        if let Some(db_files) = files_by_db.get(&db.name) {
            for f in db_files {
                let exists = std::path::Path::new(&f.physical_name).exists();
                let exists_str = if exists {
                    "Exists: Yes".green()
                } else {
                    "Exists: NO [!]".red().bold()
                };
                writeln!(
                    out,
                    "      - [{}] Logical: {} | Size: {} MB | {}",
                    f.type_desc, f.logical_name, f.size_mb, exists_str
                )?;
                writeln!(out, "        Windows Path: {}", f.physical_name)?;
            }
        }
    }

    // ---------------------------------------------------------------------
    // Database Tables
    // ---------------------------------------------------------------------
    writeln!(out, "\n  [Database Tables]")?;

    let mut tables_by_db: std::collections::HashMap<String, Vec<&SqlTableInfo>> = std::collections::HashMap::new();
    for t in &tables {
        tables_by_db.entry(t.db_name.clone()).or_default().push(t);
    }

    let user_db_names: Vec<String> = dbs
        .iter()
        .filter(|d| d.database_id.parse::<u32>().unwrap_or(0) > 4)
        .map(|d| d.name.clone())
        .collect();

    let mut user_tables_found = false;
    for db_name in &user_db_names {
        if let Some(t_list) = tables_by_db.get(db_name) {
            user_tables_found = true;
            writeln!(
                out,
                "    Database '{}' ({} tables):",
                db_name.bold(),
                t_list.len()
            )?;
            for t in t_list {
                writeln!(out, "      - {}.{} ({} rows)", t.schema, t.table_name, t.row_count)?;
            }
        } else {
            writeln!(out, "    Database '{}': (No user tables)", db_name)?;
        }
    }

    if !user_tables_found && user_db_names.is_empty() {
        writeln!(out, "    (No user databases exist on this instance)")?;
    }

    // System database table summary
    let sys_summary: Vec<String> = ["master", "msdb", "model", "tempdb"]
        .iter()
        .map(|sys_db| {
            let count = tables_by_db.get(*sys_db).map(|v| v.len()).unwrap_or(0);
            format!("{} ({} tables)", sys_db, count)
        })
        .collect();

    if show_all_tables {
        for sys_db in &["master", "msdb", "model", "tempdb"] {
            if let Some(t_list) = tables_by_db.get(*sys_db) {
                writeln!(out, "\n    System Database '{}' ({} tables):", sys_db, t_list.len())?;
                for t in t_list {
                    writeln!(out, "      - {}.{} ({} rows)", t.schema, t.table_name, t.row_count)?;
                }
            }
        }
    } else {
        writeln!(
            out,
            "    System Databases: {} (Use --all-tables to list all system tables)",
            sys_summary.join(", ")
        )?;
    }

    Ok(())
}

fn classify_principal(name: &str, type_desc: &str, computer_name: &str) -> String {
    let lower_name = name.to_lowercase();
    if type_desc == "SQL_LOGIN" {
        "[SQL Login]".to_string()
    } else if type_desc == "WINDOWS_GROUP" {
        if lower_name.starts_with("builtin")
            || lower_name.starts_with("nt authority")
            || lower_name.starts_with("nt service")
        {
            "[Local Windows Group]".to_string()
        } else if let Some((prefix, _)) = name.split_once('\\') {
            if prefix.eq_ignore_ascii_case(computer_name) {
                "[Local Windows Group]".to_string()
            } else {
                "[Active Directory Group]".to_string()
            }
        } else {
            "[Windows Group]".to_string()
        }
    } else if type_desc == "WINDOWS_LOGIN" {
        if lower_name.starts_with("nt service") {
            "[Virtual Service Account]".to_string()
        } else if lower_name.starts_with("nt authority") {
            "[Local System Account]".to_string()
        } else if let Some((prefix, _)) = name.split_once('\\') {
            if prefix.eq_ignore_ascii_case(computer_name) {
                "[Local Windows Login]".to_string()
            } else {
                "[Active Directory / Domain Login]".to_string()
            }
        } else {
            "[Windows Login]".to_string()
        }
    } else {
        format!("[{}]", type_desc)
    }
}

// -------------------------------------------------------------------------
// Registry & Native Tool Helpers (No PowerShell required)
// -------------------------------------------------------------------------

fn reg_query_lines(key: &str) -> Vec<String> {
    let output = std::process::Command::new("reg")
        .args(["query", key])
        .output();

    if let Ok(out) = output {
        if out.status.success() {
            return String::from_utf8_lossy(&out.stdout)
                .lines()
                .map(|s| s.trim_end().to_string())
                .collect();
        }
    }
    Vec::new()
}

fn parse_reg_value(line: &str) -> Option<(String, String, String)> {
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with("HKEY_") {
        return None;
    }

    let types = [
        "REG_SZ",
        "REG_DWORD",
        "REG_MULTI_SZ",
        "REG_EXPAND_SZ",
        "REG_BINARY",
        "REG_QWORD",
        "REG_NONE",
    ];

    for t in types {
        if let Some(idx) = trimmed.find(t) {
            let name = trimmed[..idx].trim().to_string();
            let val = trimmed[idx + t.len()..].trim().to_string();
            return Some((name, t.to_string(), val));
        }
    }
    None
}

fn reg_query_value(key: &str, val_name: &str) -> Option<String> {
    let output = std::process::Command::new("reg")
        .args(["query", key, "/v", val_name])
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        if let Some((name, _, val)) = parse_reg_value(line) {
            if name.eq_ignore_ascii_case(val_name) {
                return Some(val);
            }
        }
    }
    None
}

fn sc_query_service(service_name: &str) -> Option<(String, String)> {
    let output = std::process::Command::new("sc")
        .args(["query", service_name])
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("STATE") {
            if let Some(colon) = trimmed.find(':') {
                let rest = trimmed[colon + 1..].trim();
                let parts: Vec<&str> = rest.split_whitespace().collect();
                if parts.len() >= 2 {
                    return Some((parts[0].to_string(), parts[1].to_string()));
                } else if !parts.is_empty() {
                    return Some((parts[0].to_string(), parts[0].to_string()));
                }
            }
        }
    }
    None
}

fn sc_qc_service(service_name: &str) -> std::collections::HashMap<String, String> {
    let mut map = std::collections::HashMap::new();
    let output = std::process::Command::new("sc")
        .args(["qc", service_name])
        .output();

    if let Ok(out) = output {
        if out.status.success() {
            let stdout = String::from_utf8_lossy(&out.stdout);
            for line in stdout.lines() {
                let trimmed = line.trim();
                if let Some(colon) = trimmed.find(':') {
                    let key = trimmed[..colon].trim().to_string();
                    let val = trimmed[colon + 1..].trim().to_string();
                    map.insert(key, val);
                }
            }
        }
    }
    map
}

fn find_sqlcmd() -> Option<std::path::PathBuf> {
    // 1. Search PATH
    if let Ok(path) = std::env::var("PATH") {
        for p in std::env::split_paths(&path) {
            let exe = p.join("sqlcmd.exe");
            if exe.exists() {
                return Some(exe);
            }
            let osql = p.join("osql.exe");
            if osql.exists() {
                return Some(osql);
            }
        }
    }

    // 2. Search well-known SQL Server install directories
    let candidates = [
        r"C:\Program Files\Microsoft SQL Server\Client SDK\ODBC\170\Tools\Binn\sqlcmd.exe",
        r"C:\Program Files\Microsoft SQL Server\Client SDK\ODBC\180\Tools\Binn\sqlcmd.exe",
        r"C:\Program Files\Microsoft SQL Server\Client SDK\ODBC\130\Tools\Binn\sqlcmd.exe",
        r"C:\Program Files\Microsoft SQL Server\Client SDK\ODBC\110\Tools\Binn\sqlcmd.exe",
        r"C:\Program Files\Microsoft SQL Server\160\Tools\Binn\sqlcmd.exe",
        r"C:\Program Files\Microsoft SQL Server\150\Tools\Binn\sqlcmd.exe",
        r"C:\Program Files\Microsoft SQL Server\140\Tools\Binn\sqlcmd.exe",
        r"C:\Program Files\Microsoft SQL Server\130\Tools\Binn\sqlcmd.exe",
        r"C:\Program Files\Microsoft SQL Server\120\Tools\Binn\sqlcmd.exe",
        r"C:\Program Files\Microsoft SQL Server\110\Tools\Binn\sqlcmd.exe",
        r"C:\Program Files (x86)\Microsoft SQL Server\Client SDK\ODBC\170\Tools\Binn\sqlcmd.exe",
        r"C:\Program Files (x86)\Microsoft SQL Server\140\Tools\Binn\sqlcmd.exe",
        r"C:\Program Files (x86)\Microsoft SQL Server\130\Tools\Binn\sqlcmd.exe",
        r"C:\Program Files (x86)\Microsoft SQL Server\120\Tools\Binn\sqlcmd.exe",
        r"C:\Program Files (x86)\Microsoft SQL Server\110\Tools\Binn\sqlcmd.exe",
    ];

    for c in candidates {
        let p = std::path::PathBuf::from(c);
        if p.exists() {
            return Some(p);
        }
    }

    // Check wildcard instance directories
    if let Ok(entries) = std::fs::read_dir(r"C:\Program Files\Microsoft SQL Server") {
        for entry in entries.filter_map(|e| e.ok()) {
            let binn_sqlcmd = entry.path().join("MSSQL").join("Binn").join("sqlcmd.exe");
            if binn_sqlcmd.exists() {
                return Some(binn_sqlcmd);
            }
        }
    }

    None
}

fn run_sql_query(server: &str, query: &str) -> Option<String> {
    if let Some(sqlcmd_path) = find_sqlcmd() {
        let output = std::process::Command::new(sqlcmd_path)
            .args(["-E", "-S", server, "-h", "-1", "-W", "-s", "|", "-Q", query])
            .output();
        if let Ok(out) = output {
            if out.status.success() {
                let stdout = String::from_utf8_lossy(&out.stdout).to_string();
                if !stdout.trim().is_empty() {
                    return Some(stdout);
                }
            }
        }
    }

    None
}
