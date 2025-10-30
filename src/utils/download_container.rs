use std::{net::Ipv4Addr, os::fd::OwnedFd, process::Stdio};

use anyhow::{Context, anyhow, bail};
use nix::{
    fcntl::{OFlag, open},
    sched::{CloneFlags, setns},
    sys::{
        signal::{Signal::SIGTERM, kill},
        stat::Mode,
        wait::waitpid,
    },
    unistd::{ForkResult, Pid, fork, geteuid, getpid},
};

use crate::{
    pcre,
    utils::{busybox::Busybox, nft::Nft},
};

const IP_ADDR_REGEX: &'static str = concat!(
    "(?:[0-9]{1,2}|1[0-9]{2}|2[0-4][0-9]|25[0-5])",
    r"\.",
    "(?:[0-9]{1,2}|1[0-9]{2}|2[0-4][0-9]|25[0-5])",
    r"\.",
    "(?:[0-9]{1,2}|1[0-9]{2}|2[0-4][0-9]|25[0-5])",
    r"\.",
    "(?:[0-9]{1,2}|1[0-9]{2}|2[0-4][0-9]|25[0-5])"
);

pub struct DownloadContainer {
    ns_name: String,
    child: Pid,
    original_ns: OwnedFd,
    child_ns: OwnedFd,
    nft: Nft,
}

impl DownloadContainer {
    pub fn new(name: Option<String>, sneaky_ip: Option<Ipv4Addr>) -> anyhow::Result<Self> {
        if !geteuid().is_root() {
            bail!("You must be root to make use of download container capabilities");
        }

        let ns_name = name.unwrap_or_else(|| format!("jjsh{}", getpid()));

        let bb = Busybox::new().context("Could not prepare busybox for download container")?;

        if pcre!((&bb.execute(&["ip", "link"])?) =~ qr{r"^[0-9]+:\s+" ns_name ".0:"}xms) {
            bail!("There is already a download shell with that name");
        }

        bb.execute(&[
            "ip",
            "link",
            "add",
            &format!("{ns_name}.0"),
            "type",
            "veth",
            "peer",
            "name",
            &format!("{ns_name}.1"),
        ])
        .context("Could not add veth pair")?;
        let child = get_namespace(&bb)?;

        let original_ns = open(
            &*format!("/proc/{}/ns/net", getpid()),
            OFlag::O_RDONLY,
            Mode::empty(),
        )
        .context("Could not open parent net namespace")?;
        let child_ns = open(
            &*format!("/proc/{}/ns/net", child),
            OFlag::O_RDONLY,
            Mode::empty(),
        )
        .context("Could not open child net namespace")?;

        bb.execute(&["ip", "link", "set", &format!("{ns_name}.0"), "up"])
            .context("Could not set host link up")?;

        // BUG: `busybox ip` does not properly set the name of the peer device
        // This has been known about since 2022...
        // https://lists.debian.org/debian-boot/2022/01/msg00091.html
        {
            let links = bb
                .execute(&["ip", "link"])
                .context("Could not query links")?;
            let peer_name = pcre!(&links =~ m{r"^[0-9]+:\s+" ns_name r"\.0@([^:]+):"}xms)
                .get(0)
                .ok_or(anyhow!(
                    "Could not find peer name for interface in download container"
                ))?
                .extract::<1>()
                .1[0];
            bb.execute(&[
                "ip",
                "link",
                "set",
                peer_name,
                "name",
                &format!("{ns_name}.1"),
            ])
            .context("Could not rename link")?;
        }

        bb.execute(&[
            "ip",
            "link",
            "set",
            &format!("{ns_name}.1"),
            "netns",
            &format!("{child}"),
        ])
        .context("Could not move interface to child namespace")?;

        let tunnel_net = find_tunnel_net(&bb)?;

        let wan_ip = Ipv4Addr::from(u32::from(tunnel_net) + 1);
        let lan_ip = Ipv4Addr::from(u32::from(tunnel_net) + 2);

        bb.execute(&[
            "ip",
            "addr",
            "add",
            &format!("{wan_ip}/30"),
            "dev",
            &format!("{ns_name}.0"),
        ])
        .context("Could not add IP address to WAN interface")?;

        setns(&child_ns, CloneFlags::empty())
            .context("Could not change to child namespace to set up local networking")?;

        bb.execute(&["ip", "link", "set", "lo", "up"])
            .context("Could not bring up localhost in container")?;

        bb.execute(&["ip", "link", "set", &format!("{ns_name}.1"), "up"])
            .context("Could not bring up interface in container")?;

        bb.execute(&[
            "ip",
            "addr",
            "add",
            &format!("{lan_ip}/30"),
            "dev",
            &format!("{ns_name}.1"),
        ])
        .context("Could not assign interface IP in container")?;

        bb.execute(&["ip", "route", "add", "default", "via", &format!("{wan_ip}")])
            .context("Could not create default route in container")?;

        setns(&original_ns, CloneFlags::empty())
            .context("Could not change back to host namespace")?;

        let routes = bb
            .execute(&["ip", "route"])
            .context("Could not query host routes")?;

        let public_if = pcre!(&routes =~ m/r"default[^\n]*dev\s+([^\s]+)"/xms)
            .get(0)
            .ok_or(anyhow!("Could not find default route!"))?
            .extract::<1>()
            .1[0];

        std::fs::write("/proc/sys/net/ipv4/ip_forward", "1")
            .context("Could not enable IP forwarding")?;

        let nft = Nft::new()?;

        nft.exec(format!("delete table inet {ns_name}"), Stdio::null())
            .context("Could not delete previous sneaky table")?;
        nft.exec(format!("add table inet {ns_name}"), None)
            .context("Could not add new sneaky table")?;
        nft.exec(format!("add chain inet {ns_name} postrouting {{ type nat hook postrouting priority srcnat; policy accept; }}"), None)
            .context("Could not add sneaky chain")?;

        match &sneaky_ip {
            Some(ip) => {
                nft.exec(
                    format!("add rule {ns_name} postrouting ip saddr {lan_ip} snat to {ip}"),
                    None,
                )
                .context("Could not add rule to snat to sneaky IP")?;

                std::fs::write("/proc/sys/net/ipv4/conf/all/proxy_arp", "1")
                    .context("Could not enable proxy arp")?;
                std::fs::write(
                    format!("/proc/sys/net/ipv4/conf/{public_if}/proxy_arp"),
                    "1",
                )
                .context("Could not enable proxy arp")?;
            }
            None => nft
                .exec(
                    format!(
                        "add rule inet {ns_name} postrouting oifname \"{public_if}\" masquerade"
                    ),
                    None,
                )
                .context("Could not add rule to masquerade traffic")?,
        }

        Ok(DownloadContainer {
            child,
            nft,
            ns_name,
            child_ns,
            original_ns,
        })
    }

    pub fn run<T, F: FnOnce() -> T>(&self, f: F) -> anyhow::Result<T> {
        setns(&self.child_ns, CloneFlags::empty())
            .context("Could not change to child namespace to set up local networking")?;

        let v = f();

        setns(&self.original_ns, CloneFlags::empty())
            .context("Could not change back to host namespace")?;

        Ok(v)
    }

    pub fn name(&self) -> &str {
        &self.ns_name
    }
}

impl Drop for DownloadContainer {
    fn drop(&mut self) {
        if let Err(e) = kill(self.child, SIGTERM) {
            return eprintln!(
                "Could not kill download container child with pid {}: {}",
                self.child, e
            );
        }

        if let Err(e) = waitpid(self.child, None) {
            return eprintln!(
                "Could not wait for download container child with pid {} to die: {}",
                self.child, e
            );
        }

        if let Err(e) = self
            .nft
            .exec(format!("delete table inet {}", self.ns_name), None)
        {
            return eprintln!("Could not delete nftables namespace: {e}");
        }
    }
}

/// `busybox ip` doesn't actually support netns and creation of namespaces that
/// persist longer than processes
/// Instead, you can specify a pid of a process and move the link to their namespace
/// So, a process that just sleeps repeatedly until killed, allowing us to repeatedly
/// enter their namespace based on the /proc/pid/ns/net file
fn get_namespace(bb: &Busybox) -> anyhow::Result<Pid> {
    use libc::sem_t;

    struct Sync {
        semaphore: sem_t,
        err: nix::Result<()>,
    }

    const SYNC_SIZE: usize = std::mem::size_of::<Sync>();

    unsafe {
        let sync: *mut Sync = libc::mmap(
            std::ptr::null_mut(),
            SYNC_SIZE,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_ANONYMOUS | libc::MAP_SHARED,
            0,
            0,
        ) as *mut _;
        let semaphore = &mut (*sync).semaphore as *mut _;

        libc::sem_init(semaphore, 1, 0);

        match fork()? {
            ForkResult::Child => {
                (*sync).err = nix::sched::unshare(CloneFlags::CLONE_NEWNET);

                libc::msync(sync as *mut _, SYNC_SIZE, libc::MS_SYNC);
                libc::sem_post(semaphore);

                let _ = bb.execv(&["sleep", "infinity"]);
                loop {}
            }
            ForkResult::Parent { child } => {
                libc::sem_wait(semaphore);
                libc::sem_destroy(semaphore);

                (*sync).err?;

                libc::munmap(semaphore as *mut _, SYNC_SIZE);

                Ok(child)
            }
        }
    }
}

fn find_tunnel_net(bb: &Busybox) -> anyhow::Result<Ipv4Addr> {
    let mut start_ip = 0xAC_20_00_00u32;

    let subnets = {
        let addrs = bb
            .execute(&["ip", "addr"])
            .context("Could not list current addresses")?;

        pcre!(&addrs =~ m{r"inet\s+(" IP_ADDR_REGEX r")/([0-9]+)"}xms)
            .into_iter()
            .map(|c| c.extract::<2>().1)
            .map(|[ip, sn]| {
                ip.parse::<Ipv4Addr>()
                    .context("could not parse IP provided by ip addr")
                    .and_then(|ip| {
                        sn.parse::<u32>()
                            .context("could not parse subnet mask from ip addr")
                            .map(|sn| {
                                (
                                    u32::from(ip),
                                    0xFFFFFFFFu32
                                        .overflowing_shr(32 - sn)
                                        .0
                                        .overflowing_shl(32 - sn)
                                        .0,
                                )
                            })
                    })
            })
            .collect::<Result<Vec<_>, _>>()?
    };

    'tunnel_ip_loop: loop {
        start_ip -= 4;

        for (sn_ip, sn_mask) in &subnets {
            if (start_ip & sn_mask) == (sn_ip & sn_mask) {
                continue 'tunnel_ip_loop;
            }
        }

        if (start_ip & 0xFFF00000) != 0xAC100000 {
            bail!(
                "IP address exhaustion when trying to find an IP address for download container!"
            );
        }

        return Ok(start_ip.into());
    }
}
