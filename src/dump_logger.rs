use std::{
    os::raw::{c_char, c_int, c_void},
    sync::Mutex,
};

lazy_static::lazy_static! {
    pub static ref DUMP_CALLBACK: Mutex<Option<DumpCallback>> = Mutex::new(None);
}

/// # Safety
///
/// set dump log info callback.
#[no_mangle]
pub unsafe extern "C" fn overtls_set_log_callback(
    callback: Option<unsafe extern "C" fn(c_int, *const c_char, *mut c_void)>,
    ctx: *mut c_void,
) {
    *DUMP_CALLBACK.lock().unwrap() = Some(DumpCallback(callback, ctx));
}

#[derive(Clone)]
pub struct DumpCallback(Option<unsafe extern "C" fn(c_int, *const c_char, *mut c_void)>, *mut c_void);

impl DumpCallback {
    unsafe fn call(self, dump_level: c_int, info: *const c_char) {
        if let Some(cb) = self.0 {
            cb(dump_level, info, self.1);
        }
    }
}

unsafe impl Send for DumpCallback {}
unsafe impl Sync for DumpCallback {}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DumpLogger {}

impl log::Log for DumpLogger {
    fn enabled(&self, metadata: &log::Metadata) -> bool {
        metadata.level() <= log::Level::Trace
    }

    fn log(&self, record: &log::Record) {
        if self.enabled(record.metadata()) {
            let current_crate_name = env!("CARGO_CRATE_NAME");
            if record.module_path().unwrap_or("").starts_with(current_crate_name) {
                self.do_dump_log(record);
            }
        }
    }

    fn flush(&self) {}
}

impl DumpLogger {
    fn do_dump_log(&self, record: &log::Record) {
        let timestamp: chrono::DateTime<chrono::Local> = chrono::Local::now();
        let msg = format!(
            "[{} {:<5} {}] - {}",
            timestamp.format("%Y-%m-%d %H:%M:%S"),
            record.level(),
            record.module_path().unwrap_or(""),
            record.args()
        );
        let c_msg = std::ffi::CString::new(msg).unwrap();
        let ptr = c_msg.as_ptr();
        if let Some(cb) = DUMP_CALLBACK.lock().unwrap().clone() {
            unsafe {
                cb.call(record.level() as c_int, ptr);
            }
        }
    }
}
