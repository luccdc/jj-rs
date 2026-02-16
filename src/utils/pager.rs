use std::{
    io::{IsTerminal, Write},
    ops::Deref,
};

#[cfg(unix)]
use std::process::{Child, ChildStdin, Stdio};

#[cfg(unix)]
use crate::utils::busybox::Busybox;

#[cfg(unix)]
struct Pager {
    child: Child,
    stdin: Option<ChildStdin>,
}

pub trait PagerOutput: Write {
    fn is_terminal(&self) -> bool;
}

impl PagerOutput for std::io::Stdout {
    fn is_terminal(&self) -> bool {
        <Self as IsTerminal>::is_terminal(self)
    }
}

#[cfg(unix)]
impl PagerOutput for Pager {
    fn is_terminal(&self) -> bool {
        false
    }
}

impl PagerOutput for Box<dyn PagerOutput> {
    fn is_terminal(&self) -> bool {
        self.deref().is_terminal()
    }
}

#[cfg(unix)]
impl Drop for Pager {
    fn drop(&mut self) {
        let _ = crossterm::terminal::enable_raw_mode();

        if let Some(s) = self.stdin.take() {
            drop(s);
        }

        if let Err(e) = self.child.wait() {
            eprintln!("Could not wait for pager to die! {e}");
        }

        let _ = crossterm::terminal::disable_raw_mode();
    }
}

#[cfg(unix)]
impl Write for Pager {
    fn flush(&mut self) -> std::io::Result<()> {
        match &mut self.stdin {
            Some(v) => v.flush(),
            None => Ok(()),
        }
    }

    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match &mut self.stdin {
            Some(v) => v.write(buf),
            None => Ok(0),
        }
    }

    fn write_all(&mut self, buf: &[u8]) -> std::io::Result<()> {
        match &mut self.stdin {
            Some(v) => v.write_all(buf),
            None => Ok(()),
        }
    }

    fn write_fmt(&mut self, args: std::fmt::Arguments<'_>) -> std::io::Result<()> {
        match &mut self.stdin {
            Some(v) => v.write_fmt(args),
            None => Ok(()),
        }
    }

    fn write_vectored(&mut self, bufs: &[std::io::IoSlice<'_>]) -> std::io::Result<usize> {
        match &mut self.stdin {
            Some(v) => v.write_vectored(bufs),
            None => Ok(0),
        }
    }
}

#[cfg(unix)]
pub fn get_pager_output(no_pager: bool) -> impl PagerOutput {
    let stdout = std::io::stdout();

    if !IsTerminal::is_terminal(&stdout) || no_pager {
        return Box::new(stdout) as Box<dyn PagerOutput>;
    }

    let Ok(bb) = Busybox::new() else {
        eprintln!("Could not spawn less (Busybox build error)!");
        return Box::new(stdout);
    };

    let Ok(mut child) = bb
        .command("less")
        .args(["-F", "-R", "-X"])
        .stdin(Stdio::piped())
        .spawn()
    else {
        eprintln!("Could not spawn less!");
        return Box::new(stdout);
    };

    let Some(stdin) = child.stdin.take() else {
        eprintln!("Could not spawn less and take standard in!");
        return Box::new(stdout);
    };

    Box::new(Pager {
        child,
        stdin: Some(stdin),
    })
}

#[cfg(windows)]
pub fn get_pager_output(_no_pager: bool) -> impl PagerOutput {
    std::io::stdout()
}
