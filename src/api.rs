#![cfg(not(target_os = "android"))]

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
    if let Err(err) = log::set_boxed_logger(Box::<crate::dump_logger::DumpLogger>::default()) {
        log::info!("failed to set logger, error={:?}", err);
    }
    let config_path = std::ffi::CStr::from_ptr(config_path).to_str();
    if let Err(err) = config_path {
        log::error!("invalid config path, error={:?}", err);
        return -1;
    }
    let config_path = config_path.unwrap();

    let config = Config::from_config_file(config_path);
    if let Err(err) = config {
        log::error!("failed to load config, error={:?}", err);
        return -2;
    }
    let mut config = config.unwrap();

    if let Err(err) = config.check_correctness(false) {
        log::error!("invalid config, error={:?}", err);
        return -3;
    }
    if let Err(err) = _over_tls_client_run(config, callback, ctx) {
        log::error!("failed to run client, error={:?}", err);
        return -4;
    }
    0
}

/// # Safety
///
/// Run the overtls client with SSR URL.
/// The callback function will be called when the client is listening on a port.
/// It should be thread-safe and will be called with the port number and should be called only once.
///
#[no_mangle]
pub unsafe extern "C" fn over_tls_client_run_with_ssr_url(
    url: *const c_char,
    verbosity: ArgVerbosity,
    callback: Option<unsafe extern "C" fn(c_int, *mut c_void)>,
    ctx: *mut c_void,
) -> c_int {
    log::set_max_level(verbosity.into());
    if let Err(err) = log::set_boxed_logger(Box::<crate::dump_logger::DumpLogger>::default()) {
        log::info!("failed to set logger, error={:?}", err);
    }
    let url = std::ffi::CStr::from_ptr(url).to_str();
    if let Err(err) = url {
        log::error!("invalid config path, error={:?}", err);
        return -1;
    }
    let url = url.unwrap();

    let config = Config::from_ssr_url(url);
    if let Err(err) = config {
        log::error!("failed to load config, error={:?}", err);
        return -2;
    }
    let mut config = config.unwrap();

    if let Err(err) = config.check_correctness(false) {
        log::error!("invalid config, error={:?}", err);
        return -3;
    }
    if let Err(err) = _over_tls_client_run(config, callback, ctx) {
        log::error!("failed to run client, error={:?}", err);
        return -4;
    }
    0
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
