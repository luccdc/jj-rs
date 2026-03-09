use std::{
    ffi::{CStr, CString},
    path::Path,
};

use eyre::Context;

include!(concat!(env!("OUT_DIR"), "/crs_data.rs"));

mod ffi {
    use core::marker::{PhantomData, PhantomPinned};

    use std::ffi::{c_char, c_int, c_uchar, c_void};

    #[repr(C)]
    pub struct ModSecurity {
        _data: (),
        _marker: PhantomData<(*mut u8, PhantomPinned)>,
    }

    #[repr(C)]
    pub struct RulesSet {
        _data: (),
        _marker: PhantomData<(*mut u8, PhantomPinned)>,
    }

    #[repr(C)]
    pub struct Transaction {
        _data: (),
        _marker: PhantomData<(*mut u8, PhantomPinned)>,
    }

    #[repr(C)]
    pub struct Intervention {
        pub status: c_int,
        pub pause: c_int,
        pub url: *const c_char,
        pub log: *const c_char,
        pub disruptive: c_int,
    }

    #[link(name = "modsecurity")]
    unsafe extern "C" {
        pub fn msc_init() -> *mut ModSecurity;
        pub fn msc_set_connector_info(msc: *mut ModSecurity, connector: *const c_char);
        pub fn msc_set_log_cb(
            msc: *mut ModSecurity,
            cb: Option<extern "C" fn(*mut c_void, *const c_void)>,
        );
        pub fn msc_cleanup(msc: *mut ModSecurity);
        pub fn msc_create_rules_set() -> *mut RulesSet;
        pub fn msc_rules_cleanup(rs: *mut RulesSet);
        pub fn msc_new_transaction(
            msc: *mut ModSecurity,
            rs: *mut RulesSet,
            cb_data: *mut c_void,
        ) -> *mut Transaction;
        pub fn msc_transaction_cleanup(tx: *mut Transaction);
        pub fn msc_rules_add_file(
            rules: *mut RulesSet,
            file: *const c_char,
            error: *mut *const c_char,
        ) -> c_int;
        pub fn msc_rules_add(
            rules: *mut RulesSet,
            plain_rules: *const c_char,
            error: *mut *const c_char,
        ) -> c_int;
        pub fn msc_rules_dump(rules: *mut RulesSet);
        pub fn msc_intervention(tx: *mut Transaction, it: *mut Intervention) -> c_int;
        pub fn msc_process_connection(
            tx: *mut Transaction,
            client: *const c_char,
            cPort: c_int,
            server: *const c_char,
            sPort: c_int,
        ) -> c_int;
        pub fn msc_process_uri(
            tx: *mut Transaction,
            uri: *const c_char,
            protocol: *const c_char,
            http_version: *const c_char,
        ) -> c_int;
        pub fn msc_add_request_header(
            tx: *mut Transaction,
            key: *const c_uchar,
            value: *const c_uchar,
        ) -> c_int;
        pub fn msc_process_request_headers(tx: *mut Transaction) -> c_int;
        pub fn msc_append_request_body(
            tx: *mut Transaction,
            body: *const c_uchar,
            len: usize,
        ) -> c_int;
        pub fn msc_process_request_body(tx: *mut Transaction) -> c_int;
        pub fn msc_add_response_header(
            tx: *mut Transaction,
            key: *const c_uchar,
            value: *const c_uchar,
        ) -> c_int;
        pub fn msc_process_response_headers(
            tx: *mut Transaction,
            code: c_int,
            protocol: *const c_char,
        ) -> c_int;
        pub fn msc_append_response_body(
            tx: *mut Transaction,
            body: *const c_uchar,
            len: usize,
        ) -> c_int;
        pub fn msc_process_response_body(tx: *mut Transaction) -> c_int;
        pub fn msc_process_logging(tx: *mut Transaction) -> c_int;
    }
}

fn parse_msc_err<T>(null_err: &str, err: *const std::ffi::c_char) -> eyre::Result<T> {
    if err.is_null() {
        Err(eyre::eyre!("{null_err}"))
    } else {
        let err = unsafe { CStr::from_ptr(err) };
        let err = err.to_str().context("Could not parse ModSecurity error")?;
        Err(eyre::eyre!("{err}"))
    }
}

/// Managed handle around the ModSecurity library
#[derive(Clone)]
pub struct ModSecurity {
    inner: *mut ffi::ModSecurity,
}
// ModSecurity APIs are thread safe once rules are loaded
unsafe impl Send for ModSecurity {}
unsafe impl Sync for ModSecurity {}

impl ModSecurity {
    pub fn new(connector: &str) -> Option<Self> {
        Some(ModSecurity {
            inner: unsafe { ffi::msc_init() },
        })
        .filter(|msc| !msc.inner.is_null())
        .inspect(|msc| {
            let Ok(connector) = CString::new(connector) else {
                return;
            };

            unsafe {
                ffi::msc_set_connector_info(msc.inner, connector.as_ptr());
                ffi::msc_set_log_cb(msc.inner, None);
            }
        })
    }

    pub fn new_transaction(&self, rules: &RulesSet) -> Option<Transaction> {
        Some(Transaction {
            inner: unsafe {
                ffi::msc_new_transaction(self.inner, rules.inner, std::ptr::null_mut())
            },
        })
        .filter(|tx| !tx.inner.is_null())
    }

    pub fn set_log_callback(
        &mut self,
        callback: Option<extern "C" fn(*mut std::ffi::c_void, *const std::ffi::c_void)>,
    ) {
        unsafe {
            ffi::msc_set_log_cb(self.inner, callback);
        }
    }
}

impl Drop for ModSecurity {
    fn drop(&mut self) {
        unsafe {
            ffi::msc_cleanup(self.inner);
        }
    }
}

/// Managed handle around a RulesSet
pub struct RulesSet {
    inner: *mut ffi::RulesSet,
}
// ModSecurity APIs are thread safe once rules are loaded
unsafe impl Send for RulesSet {}
unsafe impl Sync for RulesSet {}

impl RulesSet {
    pub fn new() -> Option<Self> {
        Some(RulesSet {
            inner: unsafe { ffi::msc_create_rules_set() },
        })
        .filter(|rs| !rs.inner.is_null())
    }

    pub fn add_file<P: AsRef<Path>>(&mut self, file_path: P) -> eyre::Result<()> {
        let path_ptr = file_path
            .as_ref()
            .to_str()
            .ok_or(eyre::eyre!("Path is not valid UTF-8"))?;
        let path_ptr = CString::new(path_ptr)?;

        let mut err = std::ptr::null();

        if unsafe { ffi::msc_rules_add_file(self.inner, path_ptr.as_ptr(), &mut err) } < 0 {
            parse_msc_err(
                "Error loading rules, but no error message was provided",
                err,
            )?;
        }

        Ok(())
    }

    pub fn add_rules(&mut self, rules: &str) -> eyre::Result<()> {
        let rules = CString::new(rules)?;

        let mut err = std::ptr::null();

        if unsafe { ffi::msc_rules_add(self.inner, rules.as_ptr(), &mut err) } < 0 {
            parse_msc_err("Error loading rule, but no error message was provided", err)?;
        }

        Ok(())
    }

    pub fn dump_rules(&self) {
        unsafe {
            ffi::msc_rules_dump(self.inner);
        }
    }
}

impl Drop for RulesSet {
    fn drop(&mut self) {
        unsafe {
            ffi::msc_rules_cleanup(self.inner);
        }
    }
}

#[derive(Debug)]
pub struct Intervention {
    pub status: std::ffi::c_int,
    pub pause: std::ffi::c_int,
    pub url: Option<CString>,
    pub log: Option<CString>,
    pub disruptive: std::ffi::c_int,
}

/// Managed handle around a ModSecurity transaction
pub struct Transaction {
    inner: *mut ffi::Transaction,
}

impl Transaction {
    pub fn intervention(&mut self) -> Option<Intervention> {
        let mut it: ffi::Intervention = unsafe { std::mem::zeroed() };
        it.status = 200;

        if unsafe { ffi::msc_intervention(self.inner, &mut it) } == 0 {
            return None;
        }

        let url = (!it.url.is_null()).then(|| unsafe { CStr::from_ptr(it.url as _).to_owned() });
        let log = (!it.log.is_null()).then(|| unsafe { CStr::from_ptr(it.log as _).to_owned() });

        unsafe {
            libc::free(it.url as _);
            libc::free(it.log as _);
        }

        Some(Intervention {
            status: it.status,
            pause: it.pause,
            url,
            log,
            disruptive: it.disruptive,
        })
    }

    pub fn process_connection(
        &mut self,
        client: &str,
        client_port: u16,
        server: &str,
        server_port: u16,
    ) {
        let Ok(client) = CString::new(client) else {
            return;
        };
        let Ok(server) = CString::new(server) else {
            return;
        };

        unsafe {
            ffi::msc_process_connection(
                self.inner,
                client.as_ptr(),
                client_port.into(),
                server.as_ptr(),
                server_port.into(),
            );
        }
    }

    pub fn process_uri(&mut self, uri: &str, protocol: &str, http_version: &str) {
        let Ok(uri) = CString::new(uri) else {
            return;
        };
        let Ok(protocol) = CString::new(protocol) else {
            return;
        };

        let http_version = http_version.split('/').last().unwrap_or(http_version);
        let Ok(http_version) = CString::new(http_version) else {
            return;
        };

        unsafe {
            ffi::msc_process_uri(
                self.inner,
                uri.as_ptr(),
                protocol.as_ptr(),
                http_version.as_ptr(),
            );
        }
    }

    pub fn add_request_header(&mut self, key: &[u8], value: &[u8]) {
        let mut key = key.to_owned();
        key.push(0);
        let mut value = value.to_owned();
        value.push(0);
        unsafe {
            ffi::msc_add_request_header(self.inner, key.as_ptr(), value.as_ptr());
        }
    }

    pub fn process_request_headers(&mut self) {
        unsafe {
            ffi::msc_process_request_headers(self.inner);
        }
    }

    pub fn append_request_body(&mut self, body: &[u8]) {
        unsafe {
            ffi::msc_append_request_body(self.inner, body.as_ptr(), body.len());
        }
    }

    pub fn process_request_body(&mut self) {
        unsafe {
            ffi::msc_process_request_body(self.inner);
        }
    }

    pub fn add_response_header(&mut self, key: &[u8], value: &[u8]) {
        let mut key = key.to_owned();
        key.push(0);
        let mut value = value.to_owned();
        value.push(0);
        unsafe {
            ffi::msc_add_response_header(self.inner, key.as_ptr(), value.as_ptr());
        }
    }

    pub fn process_response_headers(&mut self, code: u16, protocol: &str) {
        let Ok(protocol) = CString::new(protocol) else {
            return;
        };

        unsafe {
            ffi::msc_process_response_headers(self.inner, code.into(), protocol.as_ptr());
        }
    }

    pub fn append_response_body(&mut self, body: &[u8]) {
        unsafe {
            ffi::msc_append_response_body(self.inner, body.as_ptr(), body.len());
        }
    }

    pub fn process_response_body(&mut self) {
        unsafe {
            ffi::msc_process_response_body(self.inner);
        }
    }

    pub fn process_logging(&mut self) {
        unsafe {
            ffi::msc_process_logging(self.inner);
        }
    }
}

impl Drop for Transaction {
    fn drop(&mut self) {
        unsafe {
            ffi::msc_transaction_cleanup(self.inner);
        }
    }
}
unsafe impl Send for Transaction {}
