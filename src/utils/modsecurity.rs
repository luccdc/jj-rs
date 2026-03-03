#[repr(C)]
pub struct ModSecurity {
    _data: (),
    _marker: core::marker::PhantomData<(*mut u8, core::marker::PhantomPinned)>,
}

include!(concat!(env!("OUT_DIR"), "/crs_data.rs"));

#[link(name = "modsecurity")]
unsafe extern "C" {
    pub fn msc_init() -> *mut ModSecurity;
}
