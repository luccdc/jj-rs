use std::io::{IsTerminal, Write};

#[cfg(unix)]
use std::process::{Child, ChildStdin, Stdio};

use crate::utils::busybox::Busybox;

#[cfg(unix)]
struct Pager {
    child: Child,
    stdin: Option<ChildStdin>,
}

#[cfg(unix)]
impl Drop for Pager {
    fn drop(&mut self) {
        if let Some(s) = self.stdin.take() {
            drop(s);
        }

        if let Err(e) = self.child.wait() {
            eprintln!("Could not wait for pager to die! {e}");
        }
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
pub fn get_pager_output(no_pager: bool) -> impl Write {
    let stdout = std::io::stdout();

    if !stdout.is_terminal() || no_pager {
        return Box::new(stdout) as Box<dyn Write>;
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
pub fn get_pager_output(_no_pager: bool) -> impl Write {
    let stdout = std::io::stdout();
    Box::new(stdout) as _
}
