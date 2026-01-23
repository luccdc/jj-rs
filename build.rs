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

    if std::env::var("CARGO_CFG_TARGET_OS").unwrap() == "freebsd" {
        let freebsd_libs = std::env::var("FREEBSD_LIBS").unwrap();
        println!("cargo:rustc-link-arg=--sysroot={freebsd_libs}");
        println!("cargo:rustc-link-arg=-L{freebsd_libs}/lib");
        println!("cargo:rustc-link-arg=-L{freebsd_libs}/usr/lib");
    }

    Ok(())
}
