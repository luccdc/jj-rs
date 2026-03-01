use std::{env::current_dir, fs::read_dir};

fn main() -> std::io::Result<()> {
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

    let target_os = std::env::var("CARGO_CFG_TARGET_OS");
    let target_os = target_os.as_deref();

    if target_os == Ok("windows") {
        println!("cargo:rustc-link-arg=-Wl,-Bstatic");
        println!("cargo:rustc-link-arg=-static");
        println!("cargo:rustc-link-arg=-static-libgcc");
        println!("cargo:rustc-link-arg=-static-libstdc++");
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
    } else if target_os == Ok("linux") {
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

    Ok(())
}
