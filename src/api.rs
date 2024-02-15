#![cfg(not(target_os = "android"))]

use crate::{
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
#[no_mangle]
pub unsafe extern "C" fn over_tls_client_run(
    config_path: *const c_char,
    verbosity: ArgVerbosity,
    callback: Option<unsafe extern "C" fn(c_int, *mut c_void)>,
    ctx: *mut c_void,
) -> c_int {
    log::set_max_level(verbosity.into());
    log::set_boxed_logger(Box::<crate::dump_logger::DumpLogger>::default()).unwrap();

    _over_tls_client_run(config_path, callback, ctx)
}

unsafe fn _over_tls_client_run(
    config_path: *const c_char,
    callback: Option<unsafe extern "C" fn(c_int, *mut c_void)>,
    ctx: *mut c_void,
) -> c_int {
    let shutdown_token = crate::CancellationToken::new();
    {
        let mut lock = EXITING_FLAG.lock().unwrap();
        if lock.is_some() {
            log::error!("tun2proxy already started");
            return -1;
        }
        *lock = Some(shutdown_token.clone());
    }

    let ccb = CCallback(callback, ctx);

    let block = || -> Result<()> {
        let config_path = std::ffi::CStr::from_ptr(config_path).to_str()?;

        let cb = |addr: SocketAddr| {
            log::trace!("Listening on {}", addr);
            let port = addr.port();
            unsafe {
                ccb.call(port as c_int);
            }
        };

        let mut config = crate::config::Config::from_config_file(config_path)?;
        config.check_correctness(false)?;
        let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;
        rt.block_on(async {
            crate::client::run_client(&config, shutdown_token, Some(cb)).await?;
            Ok::<(), Error>(())
        })
    };
    if let Err(error) = block() {
        log::error!("failed to run client, error={:?}", error);
        return -1;
    }
    0
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
