#[repr(C)]
struct FfiModSecurity {
    _data: (),
    _marker: core::marker::PhantomData<(*mut u8, core::marker::PhantomPinned)>,
}

#[repr(C)]
struct FfiRulesSet {
    _data: (),
    _marker: core::marker::PhantomData<(*mut u8, core::marker::PhantomPinned)>,
}

#[repr(C)]
struct FfiTransaction {
    _data: (),
    _marker: core::marker::PhantomData<(*mut u8, core::marker::PhantomPinned)>,
}

include!(concat!(env!("OUT_DIR"), "/crs_data.rs"));

#[link(name = "modsecurity")]
unsafe extern "C" {
    fn msc_init() -> *mut FfiModSecurity;
    fn msc_cleanup(msc: *mut FfiModSecurity);
}

/// Managed handle around the ModSecurity library
pub struct ModSecurity {
    inner: *mut FfiModSecurity,
}

impl ModSecurity {
    pub fn new() -> Option<Self> {
        Some(ModSecurity {
            inner: unsafe { msc_init() },
        })
        .filter(|msc| !msc.inner.is_null())
    }
}

impl Drop for ModSecurity {
    fn drop(&mut self) {
        unsafe {
            msc_cleanup(self.inner);
        }
    }
}

/// Managed handle around a RulesSet
pub struct RulesSet {
    inner: *mut FfiRulesSet,
}

/// Managed handle around a ModSecurity transaction
pub struct Transaction {
    inner: *mut FfiTransaction,
}
