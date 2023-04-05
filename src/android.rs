pub mod native {

    use crossbeam::channel::unbounded;
    use crossbeam::channel::{Receiver, Sender};
    use jni::objects::{GlobalRef, JClass, JMethodID, JObject, JValue};
    use jni::signature::{Primitive, ReturnType};
    use jni::{JNIEnv, JavaVM};
    use std::process;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::sync::Mutex;
    use std::thread::JoinHandle;
    // use core::tun;

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

    /// # Safety
    ///
    /// This function should only be used in jni context.
    #[no_mangle]
    pub unsafe extern "C" fn Java_com_github_shadowsocks_bg_OverTlsWrapper_onCreateNative(
        env: JNIEnv,
        class: JClass,
        vpn_service: JObject,
    ) {
        android_logger::init_once(
            android_logger::Config::default()
                .with_tag("overtlsVpn")
                .with_max_level(log::LevelFilter::Trace),
        );
        log::trace!("onCreateNative");
        set_panic_handler();
        Jni::init(env, class, vpn_service);
        SocketProtector::init();
        // tun::create();
    }

    /// # Safety
    ///
    /// This function should only be used in jni context.
    #[no_mangle]
    pub unsafe extern "C" fn Java_com_github_shadowsocks_bg_OverTlsWrapper_onDestroyNative(_: JNIEnv, _: JClass) {
        log::trace!("onDestroyNative");
        // tun::destroy();
        SocketProtector::release();
        Jni::release();
        remove_panic_handler();
    }

    /// # Safety
    ///
    /// This function should only be used in jni context.
    #[no_mangle]
    pub unsafe extern "C" fn Java_com_github_shadowsocks_bg_OverTlsWrapper_onStartVpn(
        _: JNIEnv,
        _: JClass,
        file_descriptor: i32,
    ) {
        log::trace!("onStartVpn, pid={}, fd={}", process::id(), file_descriptor);
        crate::android::tun_callbacks::set_socket_created_callback(Some(on_socket_created));
        socket_protector!().start();
        // tun::start(file_descriptor);
    }

    /// # Safety
    ///
    /// This function should only be used in jni context.
    #[no_mangle]
    pub unsafe extern "C" fn Java_com_github_shadowsocks_bg_OverTlsWrapper_onStopVpn(_: JNIEnv, _: JClass) {
        log::trace!("onStopVpn, pid={}", process::id());
        // tun::stop();
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
