use crate::BoxError;
use std::{
    os::raw::{c_char, c_void},
    sync::Mutex,
};

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LogLevel {
    Off,
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

impl From<LogLevel> for log::LevelFilter {
    fn from(level: LogLevel) -> Self {
        match level {
            LogLevel::Off => Self::Off,
            LogLevel::Error => Self::Error,
            LogLevel::Warn => Self::Warn,
            LogLevel::Info => Self::Info,
            LogLevel::Debug => Self::Debug,
            LogLevel::Trace => Self::Trace,
        }
    }
}

impl From<log::LevelFilter> for LogLevel {
    fn from(level: log::LevelFilter) -> Self {
        match level {
            log::LevelFilter::Off => Self::Off,
            log::LevelFilter::Error => Self::Error,
            log::LevelFilter::Warn => Self::Warn,
            log::LevelFilter::Info => Self::Info,
            log::LevelFilter::Debug => Self::Debug,
            log::LevelFilter::Trace => Self::Trace,
        }
    }
}

static DUMP_CALLBACK: Mutex<Option<DumpCallback>> = Mutex::new(None);
static LOGGER_SETTED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

pub(crate) fn check_logger() -> bool {
    LOGGER_SETTED.load(std::sync::atomic::Ordering::SeqCst)
}

/// # Safety
///
/// set dump log info callback.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn overtls_set_log_callback(
    set_logger: bool,
    callback: Option<unsafe extern "C" fn(LogLevel, *const c_char, *mut c_void)>,
    ctx: *mut c_void,
) {
    if set_logger {
        LOGGER_SETTED.store(true, std::sync::atomic::Ordering::Relaxed);
        log::set_max_level(log::LevelFilter::Trace);
        if let Err(err) = log::set_boxed_logger(Box::<DumpLogger>::default()) {
            log::warn!("{} -- failed to set logger, error={err:?}", method_name::method_name_unstable!());
        }
    }

    if let Ok(mut cb) = DUMP_CALLBACK.lock() {
        *cb = Some(DumpCallback(callback, ctx));
    } else {
        log::error!("{} -- set log callback failed", method_name::method_name_unstable!());
    }
}

#[derive(Clone)]
struct DumpCallback(Option<unsafe extern "C" fn(LogLevel, *const c_char, *mut c_void)>, *mut c_void);

impl DumpCallback {
    unsafe fn call(self, dump_level: LogLevel, info: *const c_char) {
        if let Some(cb) = self.0 {
            unsafe { cb(dump_level, info, self.1) };
        }
    }
}

unsafe impl Send for DumpCallback {}
unsafe impl Sync for DumpCallback {}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct DumpLogger;

impl log::Log for DumpLogger {
    fn enabled(&self, metadata: &log::Metadata) -> bool {
        metadata.level() <= log::Level::Trace
    }

    fn log(&self, record: &log::Record) {
        #[cfg(not(target_os = "ios"))]
        if self.enabled(record.metadata()) {
            let current_crate_name = env!("CARGO_CRATE_NAME");
            if record.module_path().unwrap_or("").starts_with(current_crate_name)
                && let Err(err) = self.do_dump_log(record)
            {
                eprint!("failed to dump log, error={err:?}");
            }
        }
        #[cfg(target_os = "ios")]
        if self.enabled(record.metadata()) {
            let module = record.module_path().unwrap_or("");
            if module.starts_with("rustls") || module.starts_with("tungstenite") || module.starts_with("tokio_tungstenite") {
                return;
            }
            if let Err(err) = self.do_dump_log(record) {
                eprint!("failed to dump log, error={err:?}");
            }
        }
    }

    fn flush(&self) {}
}

impl DumpLogger {
    fn do_dump_log(&self, record: &log::Record) -> Result<(), BoxError> {
        let _timestamp: chrono::DateTime<chrono::Local> = chrono::Local::now();
        #[cfg(not(target_os = "ios"))]
        let msg = format!(
            "[{} {:<5} {}] - {}",
            _timestamp.format("%Y-%m-%d %H:%M:%S"),
            record.level(),
            record.module_path().unwrap_or(""),
            record.args()
        );
        #[cfg(target_os = "ios")]
        let msg = format!("[{:<5} {}] - {}", record.level(), record.module_path().unwrap_or(""), record.args());
        let c_msg = std::ffi::CString::new(msg)?;
        let ptr = c_msg.as_ptr();
        if let Ok(cb) = DUMP_CALLBACK.lock()
            && let Some(cb) = cb.clone()
        {
            unsafe { cb.call(record.level().to_level_filter().into(), ptr) };
        }
        Ok(())
    }
}
