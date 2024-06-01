#![cfg(target_os = "android")]

use crate::{ArgVerbosity, Error, Result};
use jni::{
    objects::{GlobalRef, JClass, JObject, JString, JValue},
    signature::{Primitive, ReturnType},
    sys::jint,
    JNIEnv, JavaVM,
};
use std::sync::RwLock;

static EXITING_FLAG: std::sync::Mutex<Option<crate::CancellationToken>> = std::sync::Mutex::new(None);

/// # Safety
///
/// Run the overtls client with config file.
#[no_mangle]
pub unsafe extern "C" fn Java_com_github_shadowsocks_bg_OverTlsWrapper_runClient(
    mut env: JNIEnv,
    _: JClass,
    vpn_service: JObject,
    config_path: JString,
    stat_path: JString,
    verbosity: jint,
) -> jint {
    let block = || -> Result<()> {
        let log_level = ArgVerbosity::try_from(verbosity).unwrap_or_default().to_string();
        let root = module_path!().split("::").next().unwrap_or("overtls");
        let filter_str = &format!("off,{root}={log_level}");
        let filter = android_logger::FilterBuilder::new().parse(filter_str).build();
        android_logger::init_once(
            android_logger::Config::default()
                .with_tag("overtls")
                .with_max_level(log::LevelFilter::Trace)
                .with_filter(filter),
        );

        log::info!("Starting overtls client on Android");

        let shutdown_token = crate::CancellationToken::new();
        {
            let mut lock = EXITING_FLAG.lock().map_err(|e| Error::from(e.to_string()))?;
            if lock.is_some() {
                return Err(Error::from("overtls already started"));
            }
            *lock = Some(shutdown_token.clone());
        }

        JAVA_VM.lock().map_err(|e| Error::from(e.to_string()))?.replace(env.get_java_vm()?);
        VPN_SERVICE
            .lock()
            .map_err(|e| Error::from(e.to_string()))?
            .replace(env.new_global_ref(vpn_service)?);

        if let Ok(stat_path) = get_java_string(&mut env, &stat_path) {
            let mut stat = STAT_PATH.write().map_err(|e| Error::from(e.to_string()))?;
            *stat = stat_path;
        }
        let config_path = get_java_string(&mut env, &config_path)?.to_owned();
        set_panic_handler();

        let callback = |addr| {
            log::trace!("Listening on {}", addr);
        };

        let mut config = crate::config::Config::from_config_file(config_path)?;
        config.check_correctness(false)?;

        let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;
        rt.block_on(async {
            crate::client::run_client(&config, shutdown_token, Some(callback)).await?;
            Ok::<(), Error>(())
        })
    };
    if let Err(error) = block() {
        log::error!("failed to run client, error={:?}", error);
    }
    0
}

fn get_java_string(env: &mut JNIEnv, string: &JString) -> Result<String> {
    Ok(env.get_string(string)?.into())
}

static JAVA_VM: std::sync::Mutex<Option<JavaVM>> = std::sync::Mutex::new(None);
static VPN_SERVICE: std::sync::Mutex<Option<GlobalRef>> = std::sync::Mutex::new(None);

pub fn protect_socket(socket: i32) -> Result<bool> {
    let vm = JAVA_VM.lock().map_err(|e| Error::from(e.to_string()))?;
    let vm = vm.as_ref().ok_or_else(|| Error::from("java vm is not initialized"))?;
    let mut env = vm.attach_current_thread_permanently()?;
    let vpn_service = VPN_SERVICE.lock().map_err(|e| Error::from(e.to_string()))?;
    let vpn_service = vpn_service.as_ref().ok_or_else(|| Error::from("vpn service is not initialized"))?;
    let vpn_service = vpn_service.as_obj();
    _protect_socket(&mut env, vpn_service, socket)
}

// android::net::VPNService.protect(int)
fn _protect_socket(env: &mut JNIEnv, vpn_service: &JObject, socket: i32) -> Result<bool> {
    if socket <= 0 {
        return Err(Error::from(format!("invalid socket {:?}", socket)));
    }
    let class = env.find_class("android/net/VpnService")?;
    let method_id = env.get_method_id(class, "protect", "(I)Z")?;

    let return_type = ReturnType::Primitive(Primitive::Boolean);
    let arguments = [JValue::Int(socket).as_jni()];
    let value = unsafe { env.call_method_unchecked(vpn_service, method_id, return_type, &arguments[..])? };
    log::trace!("protected socket, result={:?}", value);
    Ok(value.z()?)
}

/// # Safety
///
/// Shutdown the client.
#[no_mangle]
pub unsafe extern "C" fn Java_com_github_shadowsocks_bg_OverTlsWrapper_stopClient(_: JNIEnv, _: JClass) -> jint {
    if let Ok(mut token) = EXITING_FLAG.lock() {
        if let Some(token) = token.take() {
            token.cancel();
        }
    }
    remove_panic_handler();
    log::trace!("remove_panic_handler");
    0
}

fn set_panic_handler() {
    std::panic::set_hook(Box::new(|panic_info| {
        log::error!("*** PANIC [{:?}]", panic_info);
    }));
}

fn remove_panic_handler() {
    let _ = std::panic::take_hook();
}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
struct TrafficStatus {
    tx: u64,
    rx: u64,
}

lazy_static::lazy_static! {
    static ref TRAFFIC_STATUS: RwLock<TrafficStatus> = RwLock::new(TrafficStatus::default());
    static ref STAT_PATH: RwLock<String> = RwLock::new(String::new());
    static ref TIME_STAMP: RwLock<std::time::Instant> = RwLock::new(std::time::Instant::now());
}

pub(crate) fn traffic_status_update(delta_tx: usize, delta_rx: usize) -> Result<()> {
    {
        let mut traffic_status = TRAFFIC_STATUS.write().map_err(|e| Error::from(e.to_string()))?;
        traffic_status.tx += delta_tx as u64;
        traffic_status.rx += delta_rx as u64;
    }
    let old_time = { *TIME_STAMP.read().map_err(|e| Error::from(e.to_string()))? };
    if std::time::Instant::now().duration_since(old_time).as_secs() >= 1 {
        send_traffic_stat()?;
        let mut time_stamp = TIME_STAMP.write().map_err(|e| Error::from(e.to_string()))?;
        *time_stamp = std::time::Instant::now();
    }
    Ok(())
}

fn send_traffic_stat() -> Result<()> {
    use std::io::{Read, Write};
    let stat_path = { (*STAT_PATH.read().map_err(|e| Error::from(e.to_string()))?).clone() };
    if stat_path.is_empty() {
        return Ok(());
    }
    let mut stream = std::os::unix::net::UnixStream::connect(&stat_path)?;
    stream.set_write_timeout(Some(std::time::Duration::new(1, 0)))?;
    stream.set_read_timeout(Some(std::time::Duration::new(1, 0)))?;
    let buf = {
        let traffic_status = TRAFFIC_STATUS.read().map_err(|e| Error::from(e.to_string()))?;
        unsafe { std::mem::transmute::<TrafficStatus, [u8; std::mem::size_of::<TrafficStatus>()]>(*traffic_status) }
    };
    stream.write_all(&buf)?;

    let mut response = String::new();
    stream.read_to_string(&mut response)?;

    Ok(())
}
