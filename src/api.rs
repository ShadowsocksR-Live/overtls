use crate::{
    config::Config,
    error::{Error, Result},
    ArgVerbosity,
};
use std::{
    net::SocketAddr,
    os::raw::{c_char, c_int, c_void},
};

#[derive(Clone)]
struct CCallback(Option<unsafe extern "C" fn(c_int, *mut c_void)>, *mut c_void);

impl CCallback {
    unsafe fn call(self, arg: c_int) {
        if let Some(cb) = self.0 {
            cb(arg, self.1);
        }
    }
}

unsafe impl Send for CCallback {}
unsafe impl Sync for CCallback {}

static EXITING_FLAG: std::sync::Mutex<Option<crate::CancellationToken>> = std::sync::Mutex::new(None);

/// # Safety
///
/// Run the overtls client with config file.
/// The callback function will be called when the client is listening on a port.
/// It should be thread-safe and will be called with the port number and should be called only once.
///
#[no_mangle]
pub unsafe extern "C" fn over_tls_client_run(
    config_path: *const c_char,
    verbosity: ArgVerbosity,
    callback: Option<unsafe extern "C" fn(c_int, *mut c_void)>,
    ctx: *mut c_void,
) -> c_int {
    log::set_max_level(verbosity.into());
    if !crate::dump_logger::check_logger() {
        if let Err(err) = log::set_boxed_logger(Box::<crate::dump_logger::DumpLogger>::default()) {
            log::warn!("failed to set logger, error={:?}", err);
        }
    }
    let result = || {
        if config_path.is_null() {
            return Err("config_path is null".into());
        }
        let config_path = std::ffi::CStr::from_ptr(config_path).to_str()?;
        let mut config = Config::from_config_file(config_path)?;
        config.check_correctness(false)?;
        _over_tls_client_run(config, callback, ctx)
    };
    match result() {
        Ok(_) => 0,
        Err(err) => {
            log::error!("failed to run client, error={:?}", err);
            -1
        }
    }
}

/// # Safety
///
/// Run the overtls client with SSR URL.
/// Parameters:
/// - `url`: SSR style URL string of the server node, e.g. "ssr://server:port:protocol:method:obfs:password_base64/?params_base64".
/// - `listen_addr`: The address to listen on, in the format of "ip:port".
/// - `verbosity`: The verbosity level of the logger.
/// - `callback`: The callback function to be called when the client is listening on a port.
///               It should be thread-safe and will be called with the port number and should be called only once.
/// - `ctx`: The context pointer to be passed to the callback function.
///
#[no_mangle]
pub unsafe extern "C" fn over_tls_client_run_with_ssr_url(
    url: *const c_char,
    listen_addr: *const c_char,
    verbosity: ArgVerbosity,
    callback: Option<unsafe extern "C" fn(c_int, *mut c_void)>,
    ctx: *mut c_void,
) -> c_int {
    log::set_max_level(verbosity.into());
    if !crate::dump_logger::check_logger() {
        if let Err(err) = log::set_boxed_logger(Box::<crate::dump_logger::DumpLogger>::default()) {
            log::warn!("failed to set logger, error={:?}", err);
        }
    }

    let result = || {
        let url = std::ffi::CStr::from_ptr(url).to_str()?;
        let listen_addr = if listen_addr.is_null() {
            std::net::SocketAddr::from(([127, 0, 0, 1], 1080))
        } else {
            std::ffi::CStr::from_ptr(listen_addr).to_str()?.parse()?
        };

        let mut config = Config::from_ssr_url(url)?;
        config.set_listen_addr(listen_addr);
        config.check_correctness(false)?;
        _over_tls_client_run(config, callback, ctx)
    };

    match result() {
        Ok(_) => 0,
        Err(err) => {
            log::error!("failed to run client, error={:?}", err);
            -1
        }
    }
}

fn _over_tls_client_run(config: Config, callback: Option<unsafe extern "C" fn(c_int, *mut c_void)>, ctx: *mut c_void) -> Result<()> {
    let shutdown_token = crate::CancellationToken::new();
    if let Ok(mut lock) = EXITING_FLAG.lock() {
        if lock.is_some() {
            return Err("tun2proxy already started".into());
        }
        *lock = Some(shutdown_token.clone());
    }

    let ccb = CCallback(callback, ctx);

    let cb = |addr: SocketAddr| unsafe {
        ccb.call(addr.port() as _);
    };

    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;
    rt.block_on(async {
        crate::client::run_client(&config, shutdown_token, Some(cb)).await?;
        Ok::<(), Error>(())
    })?;
    Ok(())
}

/// # Safety
///
/// Shutdown the client.
#[no_mangle]
pub unsafe extern "C" fn over_tls_client_stop() -> c_int {
    if let Ok(mut token) = EXITING_FLAG.lock() {
        if let Some(token) = token.take() {
            token.cancel();
        }
    }
    0
}

/// # Safety
///
/// Create a SSR URL from the config file.
#[no_mangle]
pub unsafe extern "C" fn overtls_generate_url(cfg_path: *const c_char) -> *mut c_char {
    let cfg_path = std::ffi::CStr::from_ptr(cfg_path);
    let cfg_path = match cfg_path.to_str() {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };
    let url = match crate::config::generate_ssr_url(cfg_path) {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };
    let url = match std::ffi::CString::new(url) {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };
    url.into_raw()
}

/// # Safety
///
/// Free the string returned by `overtls_generate_url`.
#[no_mangle]
pub unsafe extern "C" fn overtls_free_string(s: *mut c_char) {
    if s.is_null() {
        return;
    }
    drop(std::ffi::CString::from_raw(s));
}
