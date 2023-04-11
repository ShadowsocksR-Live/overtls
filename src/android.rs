#![cfg(target_os = "android")]

pub mod native {

    use crate::error::{Error, Result};
    use crossbeam::channel::{unbounded, Receiver, Sender};
    use jni::{
        objects::{GlobalRef, JClass, JMethodID, JObject, JString, JValue},
        signature::{Primitive, ReturnType},
        sys::{jboolean, jint},
        JNIEnv, JavaVM,
    };
    use std::{
        net::{IpAddr, Ipv4Addr, SocketAddr},
        sync::{
            atomic::{AtomicBool, Ordering},
            Arc, Mutex, RwLock,
        },
        thread::JoinHandle,
    };

    lazy_static::lazy_static! {
        pub static ref SOCKET_PROTECTOR: Mutex<Option<SocketProtector>> = Mutex::new(None);
    }

    macro_rules! socket_protector {
        () => {
            crate::android::native::SOCKET_PROTECTOR
                .lock()
                .unwrap()
                .as_mut()
                .unwrap()
        };
    }

    lazy_static::lazy_static! {
        pub static ref JNI: Mutex<Option<Jni>> = Mutex::new(None);
    }

    macro_rules! jni_object {
        () => {
            crate::android::native::JNI.lock().unwrap().as_mut().unwrap()
        };
    }

    type SenderChannel = Sender<(i32, Sender<bool>)>;
    type ReceiverChannel = Receiver<(i32, Sender<bool>)>;
    type ChannelPair = (SenderChannel, ReceiverChannel);

    pub struct SocketProtector {
        is_thread_running: Arc<AtomicBool>,
        thread_join_handle: Option<JoinHandle<()>>,
        channel: ChannelPair,
    }

    impl SocketProtector {
        pub fn init() {
            let mut socket_protector = SOCKET_PROTECTOR.lock().unwrap();
            *socket_protector = Some(SocketProtector {
                is_thread_running: Arc::new(AtomicBool::new(false)),
                thread_join_handle: None,
                channel: unbounded(),
            });
        }

        pub fn release() {
            let mut socket_protector = SOCKET_PROTECTOR.lock().unwrap();
            *socket_protector = None;
        }

        pub fn start(&mut self) {
            log::trace!("starting socket protecting thread");
            self.is_thread_running.store(true, Ordering::SeqCst);
            let is_thread_running = self.is_thread_running.clone();
            let receiver_channel = self.channel.1.clone();
            self.thread_join_handle = Some(std::thread::spawn(move || {
                log::trace!("socket protecting thread is started");
                if let Some(mut jni_context) = jni_object!().new_context() {
                    while is_thread_running.load(Ordering::SeqCst) {
                        SocketProtector::handle_protect_socket_request(&receiver_channel, &mut jni_context);
                    }
                }
                log::trace!("socket protecting thread is stopping");
            }));
            log::trace!("successfully started socket protecting thread");
        }

        pub fn stop(&mut self) {
            self.is_thread_running.store(false, Ordering::SeqCst);
            //
            // solely used for unblocking thread responsible for protecting sockets.
            //
            self.protect_socket(-1);
            self.thread_join_handle.take().unwrap().join().unwrap();
        }

        fn handle_protect_socket_request(receiver: &ReceiverChannel, jni_context: &mut JniContext<'_>) {
            let (socket, reply_sender) = receiver.recv().unwrap();
            let is_socket_protected = if socket <= 0 {
                log::trace!("found invalid socket, socket={:?}", socket);
                false
            } else if jni_context.protect_socket(socket) {
                log::trace!("finished protecting socket, socket={:?}", socket);
                true
            } else {
                log::error!("failed to protect socket, socket={:?}", socket);
                false
            };
            match reply_sender.send(is_socket_protected) {
                Ok(_) => {
                    log::trace!("finished sending result, socket={:?}", socket)
                }
                Err(error) => {
                    log::error!("failed to send result, socket={:?} error={:?}", socket, error);
                }
            }
        }

        pub fn protect_socket(&self, socket: i32) -> bool {
            let (sender, receiver) = unbounded::<bool>();
            match self.channel.0.send((socket, sender)) {
                Ok(_) => {
                    let result = receiver.recv();
                    match result {
                        Ok(is_socket_protected) => {
                            if is_socket_protected {
                                log::trace!("successfully protected socket, socket={:?}", socket);
                            } else {
                                log::error!("failed to protect socket, socket={:?}", socket);
                            }
                            return is_socket_protected;
                        }
                        Err(error) => {
                            log::error!("failed to protect socket, error={:?}", error);
                        }
                    }
                }
                Err(error) => {
                    log::error!("failed to protect socket, socket={:?} error={:?}", socket, error);
                }
            }
            false
        }
    }

    lazy_static::lazy_static! {
        pub static ref EXITING_FLAG: Arc<AtomicBool> = Arc::new(AtomicBool::new(false));
        pub static ref LISTEN_ADDR: Arc<Mutex<SocketAddr>> = Arc::new(Mutex::new(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080)));
    }

    /// # Safety
    ///
    /// Run the overtls client with config file.
    #[no_mangle]
    pub unsafe extern "C" fn Java_com_github_shadowsocks_bg_OverTlsWrapper_runClient(
        env: JNIEnv,
        class: JClass,
        vpn_service: JObject,
        config_path: JString,
        stat_path: JString,
        verbose: jboolean,
    ) -> jint {
        let mut env = env;

        let log_level = if verbose != 0 { "trace" } else { "info" };
        let filter_str = &format!("off,overtls={log_level}");
        let filter = android_logger::FilterBuilder::new().parse(filter_str).build();
        android_logger::init_once(
            android_logger::Config::default()
                .with_tag("overtls")
                .with_max_level(log::LevelFilter::Trace)
                .with_filter(filter),
        );

        let block = || -> Result<()> {
            if let Ok(stat_path) = get_java_string(&mut env, &stat_path) {
                let mut stat = STAT_PATH.write().unwrap();
                *stat = stat_path.to_owned();
            }
            let config_path = get_java_string(&mut env, &config_path)?.to_owned();
            set_panic_handler();
            Jni::init(env, class, vpn_service);
            SocketProtector::init();

            start_protect_socket();

            let config = crate::config::Config::load_from_ssrdroid_settings(config_path)?;
            let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;
            rt.block_on(async {
                EXITING_FLAG.store(false, Ordering::SeqCst);
                *LISTEN_ADDR.lock().unwrap() = config.listen_addr()?;
                crate::client::run_client(&config, Some(EXITING_FLAG.clone())).await?;
                Ok::<(), Error>(())
            })
        };
        if let Err(error) = block() {
            log::error!("failed to run client, error={:?}", error);
        }
        0
    }

    unsafe fn get_java_string<'a>(env: &'a mut JNIEnv, string: &'a JString) -> Result<&'a str> {
        let str_ptr = env.get_string(string)?.as_ptr();
        let s: &str = std::ffi::CStr::from_ptr(str_ptr).to_str()?;
        Ok(s)
    }

    /// # Safety
    ///
    /// Shutdown the client.
    #[no_mangle]
    pub unsafe extern "C" fn Java_com_github_shadowsocks_bg_OverTlsWrapper_stopClient(_: JNIEnv, _: JClass) -> jint {
        stop_protect_socket();

        EXITING_FLAG.store(true, Ordering::SeqCst);

        let listen_addr = *LISTEN_ADDR.lock().unwrap();
        let addr = if listen_addr.is_ipv6() { "::1" } else { "127.0.0.1" };
        let _ = std::net::TcpStream::connect((addr, listen_addr.port()));
        log::trace!("stopClient on listen address {listen_addr}");

        SocketProtector::release();
        Jni::release();
        remove_panic_handler();
        log::trace!("remove_panic_handler");
        0
    }

    fn start_protect_socket() {
        crate::android::tun_callbacks::set_socket_created_callback(Some(on_socket_created));
        socket_protector!().start();
    }

    fn stop_protect_socket() {
        socket_protector!().stop();
        crate::android::tun_callbacks::set_socket_created_callback(None);
    }

    fn set_panic_handler() {
        std::panic::set_hook(Box::new(|panic_info| {
            log::error!("*** PANIC [{:?}]", panic_info);
        }));
    }

    fn remove_panic_handler() {
        let _ = std::panic::take_hook();
    }

    fn on_socket_created(socket: i32) {
        socket_protector!().protect_socket(socket);
    }

    pub struct JniContext<'a> {
        pub(super) jni_env: JNIEnv<'a>,
        pub(super) vpn_service: &'a JObject<'a>,
        pub(super) protect_method_id: JMethodID,
    }

    impl<'a> JniContext<'a> {
        // execute android.net.VpnService.protect(int socket) method.
        pub fn protect_socket(&mut self, socket: i32) -> bool {
            if socket <= 0 {
                log::error!("invalid socket, socket={:?}", socket);
                return false;
            }
            let return_type = ReturnType::Primitive(Primitive::Boolean);
            let arguments = [JValue::Int(socket).as_jni()];
            let result = unsafe {
                self.jni_env.call_method_unchecked(
                    self.vpn_service,
                    self.protect_method_id,
                    return_type,
                    &arguments[..],
                )
            };
            match result {
                Ok(value) => {
                    log::trace!("protected socket, result={:?}", value);
                    value.z().unwrap()
                }
                Err(error_code) => {
                    log::error!("failed to protect socket, error={:?}", error_code);
                    false
                }
            }
        }
    }

    pub struct Jni {
        java_vm: Arc<JavaVM>,
        vpn_service: GlobalRef,
    }

    impl Jni {
        pub fn init(env: JNIEnv, _: JClass, vpn_service: JObject) {
            let mut jni = JNI.lock().unwrap();
            let java_vm = Arc::new(env.get_java_vm().unwrap());
            let vpn_service = env.new_global_ref(vpn_service).unwrap();
            *jni = Some(Jni { java_vm, vpn_service });
        }

        pub fn release() {
            let mut jni = JNI.lock().unwrap();
            *jni = None;
        }

        pub fn new_context(&self) -> Option<JniContext> {
            match self.java_vm.attach_current_thread_permanently() {
                Ok(jni_env) => match Jni::get_protect_method_id(unsafe { jni_env.unsafe_clone() }) {
                    Some(protect_method_id) => {
                        let vpn_service = self.vpn_service.as_obj();
                        return Some(JniContext {
                            jni_env,
                            vpn_service,
                            protect_method_id,
                        });
                    }
                    None => {
                        log::error!("failed to get protect method id");
                    }
                },
                Err(error) => {
                    log::error!("failed to attach to current thread, error={:?}", error);
                }
            }
            None
        }

        fn get_protect_method_id(mut jni_env: JNIEnv) -> Option<JMethodID> {
            match jni_env.find_class("android/net/VpnService") {
                Ok(class) => match jni_env.get_method_id(class, "protect", "(I)Z") {
                    Ok(method_id) => {
                        return Some(method_id);
                    }
                    Err(error) => {
                        log::error!("failed to get protect method id, error={:?}", error);
                    }
                },
                Err(error) => {
                    log::error!("failed to find vpn service class, error={:?}", error);
                }
            }
            None
        }
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
            let mut traffic_status = TRAFFIC_STATUS.write().unwrap();
            traffic_status.tx += delta_tx as u64;
            traffic_status.rx += delta_rx as u64;
        }
        let old_time = { *TIME_STAMP.read().unwrap() };
        if std::time::Instant::now().duration_since(old_time).as_secs() >= 1 {
            send_traffic_stat()?;
            let mut time_stamp = TIME_STAMP.write().unwrap();
            *time_stamp = std::time::Instant::now();
        }
        Ok(())
    }

    fn send_traffic_stat() -> Result<()> {
        use std::io::{Read, Write};
        let stat_path = { (*STAT_PATH.read().unwrap()).clone() };
        if stat_path.is_empty() {
            return Ok(());
        }
        let mut stream = std::os::unix::net::UnixStream::connect(&stat_path)?;
        stream.set_write_timeout(Some(std::time::Duration::new(1, 0)))?;
        stream.set_read_timeout(Some(std::time::Duration::new(1, 0)))?;
        let buf = {
            let traffic_status = TRAFFIC_STATUS.read().unwrap();
            unsafe { std::mem::transmute::<TrafficStatus, [u8; std::mem::size_of::<TrafficStatus>()]>(*traffic_status) }
        };
        stream.write_all(&buf)?;

        let mut response = String::new();
        stream.read_to_string(&mut response)?;

        Ok(())
    }
}

pub mod tun_callbacks {

    use std::sync::RwLock;

    lazy_static::lazy_static! {
        static ref CALLBACK: RwLock<fn(i32)> = RwLock::new(on_socket_created_stub);
    }

    pub fn set_socket_created_callback(callback: Option<fn(i32)>) {
        let mut current_callback = CALLBACK.write().unwrap();
        match callback {
            Some(callback) => *current_callback = callback,
            None => *current_callback = on_socket_created_stub,
        }
    }

    pub fn on_socket_created(socket: i32) {
        let callback = CALLBACK.read().unwrap();
        callback(socket);
    }

    fn on_socket_created_stub(_socket: i32) {}
}
