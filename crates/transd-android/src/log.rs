#[cfg(target_os = "android")]
unsafe extern "C" {
    fn __android_log_print(prio: i32, tag: *const std::ffi::c_char, fmt: *const std::ffi::c_char, ...) -> i32;
}

pub fn android_log_info(msg: &str) {
    #[cfg(target_os = "android")]
    {
        let tag = b"TransdEngine\0";
        let cmsg = format!("{}\0", msg);
        unsafe {
            __android_log_print(
                4, /* ANDROID_LOG_INFO */
                tag.as_ptr() as *const std::ffi::c_char,
                b"%s\0".as_ptr() as *const std::ffi::c_char,
                cmsg.as_ptr() as *const std::ffi::c_char,
            );
        }
    }
    #[cfg(not(target_os = "android"))]
    {
        eprintln!("{}", msg);
    }
}

pub fn android_log_error(msg: &str) {
    #[cfg(target_os = "android")]
    {
        let tag = b"TransdEngine\0";
        let cmsg = format!("{}\0", msg);
        unsafe {
            __android_log_print(
                6, /* ANDROID_LOG_ERROR */
                tag.as_ptr() as *const std::ffi::c_char,
                b"%s\0".as_ptr() as *const std::ffi::c_char,
                cmsg.as_ptr() as *const std::ffi::c_char,
            );
        }
    }
    #[cfg(not(target_os = "android"))]
    {
        eprintln!("{}", msg);
    }
}

#[macro_export]
macro_rules! log_i {
    ($($arg:tt)*) => {
        $crate::log::android_log_info(&format!($($arg)*))
    };
}

#[macro_export]
macro_rules! log_e {
    ($($arg:tt)*) => {
        $crate::log::android_log_error(&format!($($arg)*))
    };
}
