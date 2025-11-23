//! Utilities for reading passwd entries
//!
//! Makes use of getent to also query for domain user information, if available

use crate::utils::qx;

/// Matches the structure of man 5 passwd
#[allow(dead_code)]
pub struct Passwd {
    pub user: String,
    pub password: String,
    pub uid: u32,
    pub gid: u32,
    pub gecos: String,
    pub home: String,
    pub shell: String,
}

/// Read passwd database entries
///
/// Allows specifying a user filter. Particularly useful if looking for the database
/// entry for a specific user
///
/// ```
/// # use jj_rs::utils::passwd::load_users;
/// # fn test_load_users() -> anyhow::Result<()> {
/// // load all users
/// let users = load_users::<_, &str>(None)?;
/// for user in users {
///     println!("Found user {}: {}", user.uid, &user.user);
/// }
/// # Ok(())
/// # }
/// # test_load_users().expect("could not load root");
/// ```
///
/// ```
/// # use jj_rs::utils::passwd::load_users;
/// # fn test_load_users() -> anyhow::Result<()> {
/// // load a specific user
/// let root = &load_users("root")?[0];
/// assert_eq!(&root.user, "root");
/// assert_eq!(root.uid, 0);
/// let root = &load_users("root")?[0];
/// assert_eq!(&root.user, "root");
/// assert_eq!(root.uid, 0);
/// # Ok(())
/// # }
/// # test_load_users().expect("could not load root");
/// ```
pub fn load_users<I: Into<Option<S>>, S: AsRef<str>>(uid: I) -> anyhow::Result<Vec<Passwd>> {
    // getent passwd works better for domain joined systems and systems with weird
    // /etc/nsswitch.conf, but fall back to directly reading from /etc/passwd
    let cmd = match uid.into() {
        Some(a) => {
            format!("getent passwd {}", a.as_ref())
        }
        None => "getent passwd".to_string(),
    };

    let passwd = match qx(&cmd) {
        Ok((e, s)) if e.success() && !s.is_empty() => s.trim().to_string(),
        _ => String::from_utf8_lossy(&std::fs::read("/etc/passwd")?).to_string(),
    };

    Ok(passwd
        .split('\n')
        .filter_map(|row| -> Option<Passwd> {
            let mut options = row.split(':');
            let user = options.next()?.to_string();
            let password = options.next()?.to_string();
            let uid = options.next()?.parse::<u32>().ok()?;
            let gid = options.next()?.parse::<u32>().ok()?;
            let gecos = options.next()?.to_string();
            let home = options.next()?.to_string();
            let shell = options.next()?.to_string();

            Some(Passwd {
                user,
                password,
                uid,
                gid,
                gecos,
                home,
                shell,
            })
        })
        .collect())
}
