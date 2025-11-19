# jiujitsu-rs

## Getting set up

1. You will need a Linux shell; WSL2 will work great
2. Install and configure [git lfs](https://git-lfs.com/):
   1. Use a package manager to install git lfs, e.g. `sudo apt install git-lfs`
   2. Run `git lfs install`
3. From a Linux system, install the [Nix package manager](https://nixos.org/download/).
4. Enable [Flake support](https://nixos.wiki/wiki/Flakes), usually by adding `experimental-features = nix-command flakes` to either `~/.config/nix/nix.conf` or `/etc/nix/nix.conf` and restarting the `nix` daemon
5. Run `nix develop` in this folder (should take about 4 or 5 minutes the first time as it downloads dependencies, and 5-10 seconds afterwards)

## Building and testing

To make a development build of this project, run `cargo build` from the `nix develop` shell. This is what will be available when running either a Vagrant box or a Docker container.

Given the nature of this project, it is inadvisable to test directly on your own system. However, the code can be built and tested using either Vagrant or Docker.

### Using Vagrant

This project has a Vagrantfile with `rocky9`, `ubuntu24.04`, `debian12`, and `alpine`. Just run `vagrant up $BOX_NAME` followed by `vagrant ssh $BOX_NAME` and then you can run `jj-rs` from inside the machine. To run it with `sudo`, sometimes you may want to use:

``` sh
sudo `which jj-rs`
```

### Using Docker

To use Docker to test a command, run one of the following:

- `docker compose run rocky9`
- `docker compose run debian12`
- `docker compose run ubuntu22.04`
- `docker compose run alpine`

Inside the docker container, you will be able to run `jj-rs` as root

## Programming in Rust

If you do not know the Rust programming language, a couple of great starting resources are: 
- The Rust book: [https://doc.rust-lang.org/book/](https://doc.rust-lang.org/book/)
- Rustlings: [https://github.com/rust-lang/rustlings](https://github.com/rust-lang/rustlings)

## How to contribute changes to this repository

All changes made to the main branch should be done via branching and pull request

## Adding a command

To add a barebones CLI utility, create a new file in `src/commands` such as `example.rs` with the following content:

``` rust
use std::{net::Ipv4Addr, path::PathBuf};

use clap::Parser;

use crate::utils::{qx, system};

/// Documentation for your command here; it shows up in the help menu!
#[derive(Parser)]
pub struct Example {
    /// A path to perform a task with
    #[arg(short, long, default = "/")]
    path_arg: PathBuf

    /// An IP to target with a scan
    #[arg(short, long)]
    target_ip: Ipv4Addr
}

impl super::Command for Example {
    fn execute(self) -> anyhow::Result<()> {
        system("systemctl status ssh")?;
        
        let state = qx("systemctl is-active ssh")?.1;
    }
}
```

Then, register it in `src/commands/mod.rs`:

``` rust
pub mod example; // should match the filename you used for your command
```

Finally, add it to `src/main.rs`:

``` rust
// somewhere after line 16, after the other commands
Example, ex => commands::example::Example
```

## Adding a package

To add a package, run `cargo add PACKAGE_NAME`. Then, verify that everything still builds with `nix build`. If there are issues, review the feature flags to identify a way to include a package that makes use of pure Rust.

As an example, `reqwest`. Under the [feature flags](https://docs.rs/crate/reqwest/latest/features), it mentions having `default-tls` selected, so in `Cargo.toml` the `reqwest` dependency was modified to include `default-features = false` and then adding the `rustls-tls` feature

## Error management

Rust is very specific about how to handle errors. For this project, there are two rules for handling errors:

1. If you are writing a command or a check (anything that goes in `src/commands` or `src/checks`), just use `?` and bubble it up. See the example command above, how after `system` and `qx` it just uses `?`
2. If you are writing a utility, include `use anyhow::Context;` at the top of your file and use `.context("Add an additional error message here")?` with code that returns a result.

For situation 2, consider the following example in `src/utils/made_up_util.rs`:

``` rust
use anyhow::Context;

fn do_the_thing() -> anyhow::Result<()> {
    crate::utils::system("iptables -A OUTPUT DROP")                 // Function returns Result
        .context("Could not run iptables to drop firewall rules")?; // Context added before using `?`
}
```

## Async vs sync Rust

Asynchronous rust should not be used as a first choice. It will be used in the following cases:
1. Programming commands or utilities that are web servers or clients, since the web ecosystem is heavily intertwined with async Rust (e.g., `jj-rs serve`: [./src/commands/serve.rs](./src/commands/serve.rs))
2. Programming a utility that needs a timeout but does not provide such a function in synchronous Rust, but does provide a selectable asynchronous API (e.g., `PassiveTcpdumpCheck::run_check`: [./src/utils/checks/check_fns.rs](./src/utils/checks/check_fns.rs))

## Documentation

All functions in `src/utils` and macros in `src/macros.rs` should be documented. To view and search this documentation, run `cargo doc` from the `nix develop` shell, and then go to `target/x86_64-unknown-linux-musl/doc/jj_rs/index.html` in a web browser.

Standard library documentation can be found online: https://doc.rust-lang.org/std/

Documentation for libraries can be found at: https://docs.rs/

Documentation for libraries frequently used:
- regex: https://docs.rs/regex/latest/regex/
- reqwest (blocking): https://docs.rs/reqwest/latest/reqwest/blocking/index.html
- serde: https://docs.rs/serde/latest/serde/
- serde_json: https://docs.rs/serde_json/latest/serde_json/
- clap: https://docs.rs/clap/latest/clap/

## Kibana dashboards

To contribute Kibana dashboards, just add them to `src/commands/elk/dashboards`. It will be included the next time the project is built
