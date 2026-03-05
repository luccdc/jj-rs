use std::{env::current_dir, fs::read_dir, io::Write, path::PathBuf};

fn main() -> std::io::Result<()> {
    // bundle ELK dashboards
    {
        let mut dashboard_dir = current_dir()?;
        dashboard_dir.push("src/commands/elk/dashboards");

        let include_macros = read_dir(&dashboard_dir)?
            .filter_map(Result::ok)
            .map(|d| {
                let mut dashboard_file = dashboard_dir.clone();
                dashboard_file.push(d.path());
                format!(r#"include_bytes!("{}")"#, dashboard_file.display())
            })
            .collect::<Vec<_>>();

        std::fs::write(
            format!(
                "{}/kibana_dashboards.rs",
                std::env::var("OUT_DIR").expect("could not find OUT_DIR variable")
            ),
            format!(
                "const KIBANA_DASHBOARDS: &[&[u8]] = &[{}];",
                include_macros.join(",")
            ),
        )?;

        println!("cargo:rerun-if-changed=src/commands/elk/dashboards");
    }

    // bundle OWASP ModSecurity Core Ruleset
    {
        let mut rules_dir = PathBuf::from(
            std::env::var("CORE_RULESET").expect("Could not find CORE_RULESET variable"),
        );
        rules_dir.push("rules");

        let file_list = read_dir(&rules_dir)?
            .filter_map(Result::ok)
            .collect::<Vec<_>>();

        let conf_files = file_list
            .iter()
            .filter(|entry| entry.path().extension() == Some(&*std::ffi::OsString::from("conf")))
            .collect::<Vec<_>>();

        let data_files = file_list
            .iter()
            .filter(|entry| entry.path().extension() == Some(&*std::ffi::OsString::from("data")));

        for file in &conf_files {
            let mut output_file_path =
                PathBuf::from(std::env::var("OUT_DIR").expect("could not find OUT_DIR variable"));
            output_file_path.push(file.file_name());
            let mut output_file = std::io::BufWriter::new(
                std::fs::OpenOptions::new()
                    .truncate(true)
                    .write(true)
                    .create(true)
                    .open(output_file_path)?,
            );
            let conf = std::fs::read_to_string(file.path())?;

            for line in conf.split('\n') {
                if line.starts_with('#') {
                    output_file.write_all(line.as_bytes())?;
                    output_file.write_all("\n".as_bytes())?;
                    continue;
                }

                let mut current_line = line.to_string();

                current_line = current_line
                    .replace("@pmf ", "@pm @rules_dir")
                    .replace("@pmFromFile ", "@pmFromFile @rules_dir");

                output_file.write_all(current_line.as_bytes())?;
                output_file.write_all("\n".as_bytes())?;
            }

            output_file.flush()?;
        }

        let file_mappings = data_files
            .filter_map(|file| {
                file.path()
                    .file_name()
                    .and_then(|file_name| file_name.to_str())
                    .map(|file_name| {
                        format!(
                            r#"("{0}", include_str!("{1}"))"#,
                            file_name,
                            file.path().display()
                        )
                    })
            })
            .chain(conf_files.into_iter().filter_map(|file| {
                file.path()
                    .file_name()
                    .and_then(|file_name| file_name.to_str())
                    .map(|file_name| {
                        format!(
                            r#"("{0}", include_str!("{1}/{0}"))"#,
                            file_name,
                            std::env::var("OUT_DIR").expect("could not find OUT_DIR variable")
                        )
                    })
            }))
            .collect::<Vec<_>>()
            .join(",");

        std::fs::write(
            &format!(
                "{}/crs_data.rs",
                std::env::var("OUT_DIR").expect("could not find OUT_DIR variable")
            ),
            format!(
                r#"pub const CRS_DATA_FILES: &'static [(&'static str, &'static str)] = &[{file_mappings}];"#
            ),
        )?;
    }

    // bindgen for libcurl
    {
        let bindings = bindgen::Builder::default()
            .clang_arg(format!(
                "-I{}/include",
                std::env::var("LIBC_PATH").expect("Could not get LIBCURL_PATH"),
            ))
            .clang_arg(format!(
                "-I{}/include",
                std::env::var("LIBCURL_PATH").expect("Could not get LIBCURL_PATH"),
            ))
            .header("src/utils/curl.h")
            .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
            .generate()
            .expect("Unable to generate bindings");

        let out_path =
            PathBuf::from(std::env::var("OUT_DIR").expect("Could not get OUT_DIR variable"));
        bindings
            .write_to_file(out_path.join("curl_bindings.rs"))
            .expect("Could not write bindings");
    }

    // Link modsecurity, curl, and their dependencies
    {
        let target_os = std::env::var("CARGO_CFG_TARGET_OS");
        let target_os = target_os.as_deref();

        if target_os == Ok("windows") {
            println!("cargo:rustc-link-arg=-static");
            println!("cargo:rustc-link-arg=-static-libgcc");
            println!("cargo:rustc-link-arg=-static-libstdc++");
            println!("cargo:rustc-link-arg=-Wl,-Bstatic");
            println!("cargo:rustc-link-arg=-lmodsecurity");
            println!("cargo:rustc-link-arg=-lcurl");
            println!("cargo:rustc-link-arg=-lstdc++");
            println!("cargo:rustc-link-arg=-lmcfgthread");
            println!("cargo:rustc-link-arg=-lpcre");
            println!("cargo:rustc-link-arg=-lxml2");
            println!("cargo:rustc-link-arg=-lidn2");
            println!("cargo:rustc-link-arg=-lunistring");
            println!("cargo:rustc-link-arg=-lssl");
            println!("cargo:rustc-link-arg=-lcrypto");
            println!("cargo:rustc-link-arg=-lws2_32");
            println!("cargo:rustc-link-arg=-lpsl");
            println!("cargo:rustc-link-arg=-lidn2");
            println!("cargo:rustc-link-arg=-liconv");
            println!("cargo:rustc-link-arg=-lunistring");
            println!("cargo:rustc-link-arg=-lpthread");
            println!("cargo:rustc-link-arg=-lwinpthread");
            println!("cargo:rustc-link-arg=-lcrypt32");
            println!("cargo:rustc-link-arg=-lgcc");
            println!("cargo:rustc-link-arg=-Wl,-Bdynamic");
            println!("cargo:rustc-link-arg=-Wl,--start-group");
            println!("cargo:rustc-link-arg=-lmingwex");
            println!("cargo:rustc-link-arg=-lmingw32");
            println!("cargo:rustc-link-arg=-lmsvcrt");
            println!("cargo:rustc-link-arg=-Wl,--end-group");
            println!("cargo:rustc-link-arg=-luser32");
            println!("cargo:rustc-link-arg=-lkernel32");
            println!("cargo:rustc-link-arg=-ladvapi32");
            println!("cargo:rustc-link-arg=-lntdll");
            println!("cargo:rustc-link-arg=-liphlpapi");
        } else if target_os == Ok("linux") {
            println!("cargo:rustc-link-arg=-lcurl");
            println!("cargo:rustc-link-arg=-lpcre");
            println!("cargo:rustc-link-arg=-lxml2");
            println!("cargo:rustc-link-arg=-lyajl");
            println!("cargo:rustc-link-arg=-lc++");
            println!("cargo:rustc-link-arg=-lssl");
            println!("cargo:rustc-link-arg=-lcrypto");
            println!("cargo:rustc-link-arg=-lpsl");
            println!("cargo:rustc-link-arg=-lz");
            println!("cargo:rustc-link-arg=-lidn2");
            println!("cargo:rustc-link-arg=-lunistring");
        }
    }

    Ok(())
}
