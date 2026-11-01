pub mod bionic;
pub mod gles;
pub mod host;
pub mod jni;
pub mod trampoline;

pub use bionic::{BionicBridge, BionicFuncId, LogMessage, ThreadDescriptor};
pub use gles::{
    DrawCallRecord, GlesBridge, GlesFuncId, GL_COLOR_BUFFER_BIT, GL_DEPTH_BUFFER_BIT,
    GL_EXTENSIONS, GL_RENDERER, GL_SHADING_LANGUAGE_VERSION, GL_TRIANGLES, GL_VENDOR, GL_VERSION,
};
pub use host::{ArgMarshaller, HostBridge, RawFnPtr};
pub use jni::{jni_idx, vm_idx, JniBridge, RegisteredNativeMethod, JNI_OK, JNI_VERSION_1_6};
pub use trampoline::{
    invoke_guest, invoke_guest_full, invoke_jni_method, invoke_jni_onload, SENTINEL_RETURN_ADDR,
};
