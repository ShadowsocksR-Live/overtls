#![cfg(target_os = "android")]

use crate::traffic_status::{TrafficStatus, overtls_set_traffic_status_callback};
use crate::{ArgVerbosity, Error, Result};
use jni::{
    Env, EnvUnowned, JavaVM,
    objects::{Global, JClass, JObject, JString, JValue},
    signature::{JavaType, MethodSignature, Primitive, ReturnType},
    strings::JNIString,
    sys::jint,
};
use std::os::raw::c_void;

static EXITING_FLAG: std::sync::Mutex<Option<crate::CancellationToken>> = std::sync::Mutex::new(None);

/// # Safety
///
/// Run the overtls client with config file.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn Java_com_github_shadowsocks_bg_OverTlsWrapper_runClient(
    mut env: EnvUnowned<'_>,
    _: JClass<'_>,
    vpn_service: JObject<'_>,
    config_path: JString<'_>,
    stat_path: JString<'_>,
    verbosity: jint,
) -> jint {
    env.with_env(|env: &mut Env| -> Result<jint> {
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

        // store JavaVM and global VPN service reference
        JAVA_VM.lock().map_err(|e| Error::from(e.to_string()))?.replace(env.get_java_vm()?);
        VPN_SERVICE
            .lock()
            .map_err(|e| Error::from(e.to_string()))?
            .replace(env.new_global_ref(vpn_service)?);

        if let Ok(stat_path) = get_java_string(env, &stat_path) {
            let mut stat = STAT_PATH.lock().map_err(|e| Error::from(e.to_string()))?;
            *stat = Some(stat_path);

            unsafe { overtls_set_traffic_status_callback(1, Some(send_traffic_stat), std::ptr::null_mut()) };
        }
        let config_path = get_java_string(env, &config_path)?.to_owned();
        set_panic_handler();

        let callback = |addr| {
            log::trace!("Listening on {}", addr);
        };

        let mut config = crate::config::Config::from_config_file(config_path)?;
        config.check_correctness(false)?;

        let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;
        rt.block_on(async {
            crate::client::run_client(&config, shutdown_token, Some(callback)).await?;
            Ok::<jint, Error>(0)
        })
    })
    .resolve::<jni::errors::LogErrorAndDefault>()
}

fn get_java_string(env: &Env, string: &JString<'_>) -> Result<String> {
    string.try_to_string(env).map_err(|e| e.into())
}

static JAVA_VM: std::sync::Mutex<Option<JavaVM>> = std::sync::Mutex::new(None);
static VPN_SERVICE: std::sync::Mutex<Option<Global<JObject<'static>>>> = std::sync::Mutex::new(None);

pub fn protect_socket(socket: i32) -> Result<bool> {
    let vm_guard = JAVA_VM.lock().map_err(|e| Error::from(e.to_string()))?;
    let vm = vm_guard.as_ref().ok_or_else(|| Error::from("java vm is not initialized"))?;

    vm.attach_current_thread(|env: &mut Env| {
        let guard = VPN_SERVICE.lock().map_err(|e| Error::from(e.to_string()))?;
        let g = guard.as_ref().ok_or_else(|| Error::from("vpn service is not initialized"))?;
        _protect_socket(env, g.as_obj(), socket)
    })
}

// android::net::VPNService.protect(int)
fn _protect_socket(env: &mut Env, vpn_service: &JObject<'_>, socket: i32) -> Result<bool> {
    if socket <= 0 {
        return Err(Error::from(format!("invalid socket {:?}", socket)));
    }
    // use JNIString so we satisfy AsRef<JNIStr>
    let class = env.find_class(JNIString::from("android/net/VpnService"))?;

    // build a MethodSignature for (I)Z
    let sig_jni = JNIString::from("(I)Z");
    let sig = unsafe {
        MethodSignature::from_raw_parts(
            sig_jni.as_ref(),
            &[JavaType::Primitive(Primitive::Int)],
            ReturnType::Primitive(Primitive::Boolean),
        )
    };
    let method_id = env.get_method_id(class, JNIString::from("protect"), sig)?;

    let return_type = ReturnType::Primitive(Primitive::Boolean);
    let arguments = [JValue::Int(socket).as_jni()];
    let value = unsafe { env.call_method_unchecked(vpn_service, method_id, return_type, &arguments[..])? };
    log::trace!("protected socket, result={:?}", value);
    Ok(value.z()?)
}

/// # Safety
///
/// Shutdown the client.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn Java_com_github_shadowsocks_bg_OverTlsWrapper_stopClient(_: EnvUnowned<'_>, _: JClass<'_>) -> jint {
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

static STAT_PATH: std::sync::Mutex<Option<String>> = std::sync::Mutex::new(None);

unsafe extern "C" fn send_traffic_stat(traffic_status: *const TrafficStatus, _ctx: *mut c_void) {
    let traffic_status = unsafe { *traffic_status };
    if let Err(e) = _send_traffic_stat(&traffic_status) {
        log::error!("failed to send traffic stat, error={:?}", e);
    }
}

fn _send_traffic_stat(traffic_status: &TrafficStatus) -> Result<()> {
    use std::io::{Read, Write};
    let stat_path = {
        let stat_path = STAT_PATH.lock().map_err(|e| Error::from(e.to_string()))?;
        stat_path.clone().ok_or_else(|| Error::from("stat path is not initialized"))?
    };
    let mut stream = std::os::unix::net::UnixStream::connect(&stat_path)?;
    stream.set_write_timeout(Some(std::time::Duration::new(1, 0)))?;
    stream.set_read_timeout(Some(std::time::Duration::new(1, 0)))?;
    let buf = unsafe { std::mem::transmute::<TrafficStatus, [u8; std::mem::size_of::<TrafficStatus>()]>(*traffic_status) };
    stream.write_all(&buf)?;

    let mut response = String::new();
    stream.read_to_string(&mut response)?;

    Ok(())
}
