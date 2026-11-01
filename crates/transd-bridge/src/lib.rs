pub mod audio;
pub mod audio_resample;
pub mod audio_ring;
pub mod bionic;
pub mod gles;
pub mod host;
pub mod jni;
pub mod jni_thunk;
pub mod surface;
pub mod trampoline;
pub mod vulkan;

pub use audio::{
    AudioBridge, AudioBuffer, AudioFormat, AudioFuncId, AUDIO_SVC_MAGIC,
    SL_PLAYSTATE_PAUSED, SL_PLAYSTATE_PLAYING, SL_PLAYSTATE_STOPPED,
    SL_RESULT_PARAMETER_INVALID, SL_RESULT_SUCCESS,
};
pub use audio_resample::AudioResampler;
pub use audio_ring::AudioRingBuffer;
pub use bionic::{BionicBridge, BionicFuncId, LogMessage, ThreadDescriptor};
pub use gles::{
    DrawCallRecord, GlesBridge, GlesFuncId, GL_COLOR_BUFFER_BIT, GL_DEPTH_BUFFER_BIT,
    GL_EXTENSIONS, GL_RENDERER, GL_SHADING_LANGUAGE_VERSION, GL_TRIANGLES, GL_VENDOR, GL_VERSION,
};
pub use host::{ArgMarshaller, HostBridge, RawFnPtr};
pub use jni::{
    jni_idx, vm_idx, JniBridge, RegisteredNativeMethod, JNI_ERR, JNI_OK, JNI_SVC_MAGIC,
    JNI_VERSION_1_1, JNI_VERSION_1_2, JNI_VERSION_1_4, JNI_VERSION_1_6,
};
pub use jni_thunk::{JniThunk, JniThunkGenerator};
pub use surface::{KeyEvent, SurfaceBridge, TouchEvent, GUEST_SURFACE_HANDLE};
pub use trampoline::{
    invoke_guest, invoke_guest_extended, invoke_guest_full, invoke_jni_method, invoke_jni_onload,
    SENTINEL_RETURN_ADDR,
};
pub use vulkan::{
    VkApplicationInfo32, VkDeviceCreateInfo32, VkInstanceCreateInfo32, VkSubmitInfo32, VulkanBridge,
    VK_ERROR_INITIALIZATION_FAILED, VK_SUCCESS,
};
