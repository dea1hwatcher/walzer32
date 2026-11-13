#![allow(clippy::too_many_arguments, clippy::collapsible_if, clippy::type_complexity)]
pub mod asset;
pub mod audio;
pub mod audio_resample;
pub mod audio_ring;
pub mod bionic;
pub mod bionic_regex;
pub mod gles;
pub mod hardware_buffer;
pub mod host;
pub mod jni;
pub mod jni_thunk;
pub mod property;
pub mod surface;
pub mod trampoline;
pub mod vulkan;

pub use property::{PropertyStore, PROP_NAME_MAX, PROP_VALUE_MAX, PROP_INFO_SIZE};

pub use asset::{AssetBridge, AssetFuncId, OpenAsset, OpenAssetDir, ASSET_SVC_MAGIC};
pub use hardware_buffer::{
    HardwareBufferBridge, HardwareBufferEntry, HardwareBufferFuncId, HARDWARE_BUFFER_SVC_MAGIC,
    AHARDWAREBUFFER_FORMAT_R16G16B16A16_FLOAT, AHARDWAREBUFFER_FORMAT_R5G6B5_UNORM,
    AHARDWAREBUFFER_FORMAT_R8G8B8A8_UNORM, AHARDWAREBUFFER_FORMAT_R8G8B8X8_UNORM,
    AHARDWAREBUFFER_FORMAT_R8G8B8_UNORM, AHARDWAREBUFFER_FORMAT_RGBA_8888,
    AHARDWAREBUFFER_USAGE_CPU_READ_NEVER, AHARDWAREBUFFER_USAGE_CPU_READ_OFTEN,
    AHARDWAREBUFFER_USAGE_CPU_READ_RARELY, AHARDWAREBUFFER_USAGE_CPU_WRITE_NEVER,
    AHARDWAREBUFFER_USAGE_CPU_WRITE_OFTEN, AHARDWAREBUFFER_USAGE_CPU_WRITE_RARELY,
    AHARDWAREBUFFER_USAGE_GPU_COLOR_OUTPUT, AHARDWAREBUFFER_USAGE_GPU_SAMPLED_IMAGE,
};
pub use audio::{
    AudioBridge, AudioBuffer, AudioFormat, AudioFuncId, AUDIO_SVC_MAGIC,
    SL_PLAYSTATE_PAUSED, SL_PLAYSTATE_PLAYING, SL_PLAYSTATE_STOPPED,
    SL_RESULT_PARAMETER_INVALID, SL_RESULT_SUCCESS,
};
pub use audio_resample::AudioResampler;
pub use audio_ring::AudioRingBuffer;
pub use bionic::{
    atomic_rmw_u32, futex_cond_signal, futex_mutex_lock, futex_mutex_unlock, BionicBridge,
    BionicFuncId, BlockingBionicOp, LogMessage, PendingDlopen, PendingThreadSpawn,
    ThreadDescriptor, ThreadExitCoordinator, BIONIC_SVC_MAGIC,
};
pub use gles::{
    BufferState, DrawCallRecord, EglContextState, EglSurfaceState, GlesBridge, GlesFuncId,
    GLES_SVC_MAGIC, ShareGroup, SurfaceKind, SyncFenceState, TextureState, ThreadEglBinding,
    EGL_BAD_PARAMETER, EGL_CONDITION_SATISFIED_KHR, EGL_CONTEXT_CLIENT_VERSION, EGL_DRAW,
    EGL_FALSE, EGL_HEIGHT, EGL_NONE, EGL_NO_CONTEXT, EGL_NO_DISPLAY, EGL_NO_SURFACE, EGL_READ,
    EGL_SIGNALED_KHR, EGL_SUCCESS, EGL_SYNC_FENCE_KHR, EGL_SYNC_STATUS_KHR,
    EGL_TIMEOUT_EXPIRED_KHR, EGL_TRUE, EGL_UNSIGNALED_KHR, EGL_WIDTH, GL_COLOR_ATTACHMENT0,
    GL_COLOR_BUFFER_BIT, GL_DEPTH_ATTACHMENT, GL_DEPTH_BUFFER_BIT, GL_EXTENSIONS, GL_FRAMEBUFFER,
    GL_FRAMEBUFFER_COMPLETE, GL_LINEAR, GL_NEAREST, GL_RENDERER, GL_REPEAT, GL_RGB, GL_RGBA,
    GL_SHADING_LANGUAGE_VERSION, GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_TEXTURE_MIN_FILTER,
    GL_TEXTURE_WRAP_S, GL_TEXTURE_WRAP_T, GL_TRIANGLES, GL_UNSIGNED_BYTE, GL_VENDOR, GL_VERSION,
};
pub use host::{ArgMarshaller, HostBridge, RawFnPtr};
pub use jni::{
    jni_idx, vm_idx, DirectBufferInfo, FieldDescriptor, JniBridge, JniValue, MethodDescriptor,
    PendingNativeRegistration, RegisteredNativeMethod, JNI_ERR, JNI_FALSE, JNI_OK, JNI_SVC_MAGIC,
    JNI_TRUE, JNI_VERSION_1_1, JNI_VERSION_1_2, JNI_VERSION_1_4, JNI_VERSION_1_6,
};
pub use jni_thunk::{
    marshal_host_jni_frame_to_aapcs32, unpack_guest_return_to_host_u64, HostJniCallFrame,
    JniSignature, JniThunk, JniThunkGenerator, JniType,
};
pub use surface::{KeyEvent, SurfaceBridge, TouchEvent, GUEST_SURFACE_HANDLE};
pub use trampoline::{
    check_fastmem_fault, dispatch_bridge_svc, flush_pending_mt_actions,
    handle_mt_syscall_and_spawns, invoke_guest, invoke_guest_all, invoke_guest_extended,
    invoke_guest_full, invoke_guest_mt, invoke_jni_method, invoke_jni_onload, prepare_guest_call,
    run_guest_mt_loop, spawn_worker_engine, SharedGuestRuntime, SENTINEL_RETURN_ADDR,
};
pub use vulkan::{
    VkApplicationInfo32, VkDeviceCreateInfo32, VkInstanceCreateInfo32, VkSubmitInfo32, VulkanBridge,
    VulkanFuncId, VK_ERROR_INITIALIZATION_FAILED, VK_SUCCESS, VULKAN_SVC_MAGIC,
};
