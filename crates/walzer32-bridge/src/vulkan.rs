/// Vulkan 1.0/1.1/1.2 Passthrough Bridge for Walzer32 DBT.
///
/// Handles structural impedance matching between 32-bit ARM guest and 64-bit host:
///   1. 32-bit Vulkan structures have 4-byte pointer alignment and 4-byte pointers.
///   2. 64-bit Vulkan structures have 8-byte pointer alignment and 8-byte pointers.
///   3. Dispatchable and non-dispatchable Vulkan handles (VkInstance, VkDevice, etc.)
///      are 64-bit on host; Walzer32 maintains a bidirectional 32-bit handle map.

use std::collections::HashMap;
#[cfg(target_os = "android")]
use std::ffi::{c_char, c_void, CString};
use walzer32_core::{CpuState, GuestAddr, Memory, MemoryError, Reg};
use walzer32_elf::SymbolResolver;

#[cfg(target_os = "android")]
use crate::host::HostBridge;

pub const VULKAN_SVC_MAGIC: u32 = 0x560000; // 'V' << 16

pub const VK_SUCCESS: i32 = 0;
pub const VK_NOT_READY: i32 = 1;
pub const VK_TIMEOUT: i32 = 2;
pub const VK_ERROR_OUT_OF_HOST_MEMORY: i32 = -1;
pub const VK_ERROR_INITIALIZATION_FAILED: i32 = -3;
pub const VK_ERROR_DEVICE_LOST: i32 = -4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum VulkanFuncId {
    VkCreateInstance = 1,
    VkDestroyInstance = 2,
    VkEnumeratePhysicalDevices = 3,
    VkGetPhysicalDeviceProperties = 4,
    VkGetPhysicalDeviceQueueFamilyProperties = 5,
    VkCreateDevice = 6,
    VkDestroyDevice = 7,
    VkGetDeviceQueue = 8,
    VkQueueSubmit = 9,
    VkQueueWaitIdle = 10,
    VkDeviceWaitIdle = 11,
    VkCreateAndroidSurfaceKHR = 12,
    VkDestroySurfaceKHR = 13,
    VkGetPhysicalDeviceSurfaceSupportKHR = 14,
    VkGetPhysicalDeviceSurfaceCapabilitiesKHR = 15,
    VkCreateSwapchainKHR = 16,
    VkDestroySwapchainKHR = 17,
    VkGetSwapchainImagesKHR = 18,
    VkAcquireNextImageKHR = 19,
    VkQueuePresentKHR = 20,
    VkCmdDraw = 21,
    VkGetInstanceProcAddr = 22,
    VkGetDeviceProcAddr = 23,
    VkEnumerateInstanceExtensionProperties = 24,
}

impl VulkanFuncId {
    pub fn from_u32(val: u32) -> Option<Self> {
        match val {
            1 => Some(Self::VkCreateInstance),
            2 => Some(Self::VkDestroyInstance),
            3 => Some(Self::VkEnumeratePhysicalDevices),
            4 => Some(Self::VkGetPhysicalDeviceProperties),
            5 => Some(Self::VkGetPhysicalDeviceQueueFamilyProperties),
            6 => Some(Self::VkCreateDevice),
            7 => Some(Self::VkDestroyDevice),
            8 => Some(Self::VkGetDeviceQueue),
            9 => Some(Self::VkQueueSubmit),
            10 => Some(Self::VkQueueWaitIdle),
            11 => Some(Self::VkDeviceWaitIdle),
            12 => Some(Self::VkCreateAndroidSurfaceKHR),
            13 => Some(Self::VkDestroySurfaceKHR),
            14 => Some(Self::VkGetPhysicalDeviceSurfaceSupportKHR),
            15 => Some(Self::VkGetPhysicalDeviceSurfaceCapabilitiesKHR),
            16 => Some(Self::VkCreateSwapchainKHR),
            17 => Some(Self::VkDestroySwapchainKHR),
            18 => Some(Self::VkGetSwapchainImagesKHR),
            19 => Some(Self::VkAcquireNextImageKHR),
            20 => Some(Self::VkQueuePresentKHR),
            21 => Some(Self::VkCmdDraw),
            22 => Some(Self::VkGetInstanceProcAddr),
            23 => Some(Self::VkGetDeviceProcAddr),
            24 => Some(Self::VkEnumerateInstanceExtensionProperties),
            _ => None,
        }
    }
}

#[cfg(target_os = "android")]
#[repr(C)]
struct HostVkApplicationInfo {
    s_type: u32,
    p_next: *const c_void,
    p_application_name: *const c_char,
    application_version: u32,
    p_engine_name: *const c_char,
    engine_version: u32,
    api_version: u32,
}

#[cfg(target_os = "android")]
#[repr(C)]
struct HostVkInstanceCreateInfo {
    s_type: u32,
    p_next: *const c_void,
    flags: u32,
    p_application_info: *const HostVkApplicationInfo,
    enabled_layer_count: u32,
    pp_enabled_layer_names: *const *const c_char,
    enabled_extension_count: u32,
    pp_enabled_extension_names: *const *const c_char,
}

#[cfg(target_os = "android")]
#[repr(C)]
struct HostVkAndroidSurfaceCreateInfoKHR {
    s_type: u32,
    p_next: *const c_void,
    flags: u32,
    window: *mut c_void,
}

// Vulkan Structure Types (sTypes)
pub const VK_STRUCTURE_TYPE_APPLICATION_INFO: u32 = 0;
pub const VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO: u32 = 1;
pub const VK_STRUCTURE_TYPE_DEVICE_QUEUE_CREATE_INFO: u32 = 2;
pub const VK_STRUCTURE_TYPE_DEVICE_CREATE_INFO: u32 = 3;
pub const VK_STRUCTURE_TYPE_SUBMIT_INFO: u32 = 4;
pub const VK_STRUCTURE_TYPE_SWAPCHAIN_CREATE_INFO_KHR: u32 = 1000001000;
pub const VK_STRUCTURE_TYPE_PRESENT_INFO_KHR: u32 = 1000001001;
pub const VK_STRUCTURE_TYPE_ANDROID_SURFACE_CREATE_INFO_KHR: u32 = 1000008000;

/// 32-bit Guest Representation of VkApplicationInfo (28 bytes)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VkApplicationInfo32 {
    pub s_type: u32,
    pub p_next: GuestAddr,
    pub p_application_name: GuestAddr,
    pub application_version: u32,
    pub p_engine_name: GuestAddr,
    pub engine_version: u32,
    pub api_version: u32,
}

impl VkApplicationInfo32 {
    pub fn read(mem: &impl Memory, addr: GuestAddr) -> Result<Self, MemoryError> {
        Ok(Self {
            s_type: mem.read_u32(addr)?,
            p_next: GuestAddr::new(mem.read_u32(addr.add(4))?),
            p_application_name: GuestAddr::new(mem.read_u32(addr.add(8))?),
            application_version: mem.read_u32(addr.add(12))?,
            p_engine_name: GuestAddr::new(mem.read_u32(addr.add(16))?),
            engine_version: mem.read_u32(addr.add(20))?,
            api_version: mem.read_u32(addr.add(24))?,
        })
    }
}

/// 32-bit Guest Representation of VkInstanceCreateInfo (32 bytes)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VkInstanceCreateInfo32 {
    pub s_type: u32,
    pub p_next: GuestAddr,
    pub flags: u32,
    pub p_application_info: GuestAddr,
    pub enabled_layer_count: u32,
    pub pp_enabled_layer_names: GuestAddr,
    pub enabled_extension_count: u32,
    pub pp_enabled_extension_names: GuestAddr,
}

impl VkInstanceCreateInfo32 {
    pub fn read(mem: &impl Memory, addr: GuestAddr) -> Result<Self, MemoryError> {
        Ok(Self {
            s_type: mem.read_u32(addr)?,
            p_next: GuestAddr::new(mem.read_u32(addr.add(4))?),
            flags: mem.read_u32(addr.add(8))?,
            p_application_info: GuestAddr::new(mem.read_u32(addr.add(12))?),
            enabled_layer_count: mem.read_u32(addr.add(16))?,
            pp_enabled_layer_names: GuestAddr::new(mem.read_u32(addr.add(20))?),
            enabled_extension_count: mem.read_u32(addr.add(24))?,
            pp_enabled_extension_names: GuestAddr::new(mem.read_u32(addr.add(28))?),
        })
    }
}

/// 32-bit Guest Representation of VkDeviceCreateInfo (40 bytes)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VkDeviceCreateInfo32 {
    pub s_type: u32,
    pub p_next: GuestAddr,
    pub flags: u32,
    pub queue_create_info_count: u32,
    pub p_queue_create_infos: GuestAddr,
    pub enabled_layer_count: u32,
    pub pp_enabled_layer_names: GuestAddr,
    pub enabled_extension_count: u32,
    pub pp_enabled_extension_names: GuestAddr,
    pub p_enabled_features: GuestAddr,
}

impl VkDeviceCreateInfo32 {
    pub fn read(mem: &impl Memory, addr: GuestAddr) -> Result<Self, MemoryError> {
        Ok(Self {
            s_type: mem.read_u32(addr)?,
            p_next: GuestAddr::new(mem.read_u32(addr.add(4))?),
            flags: mem.read_u32(addr.add(8))?,
            queue_create_info_count: mem.read_u32(addr.add(12))?,
            p_queue_create_infos: GuestAddr::new(mem.read_u32(addr.add(16))?),
            enabled_layer_count: mem.read_u32(addr.add(20))?,
            pp_enabled_layer_names: GuestAddr::new(mem.read_u32(addr.add(24))?),
            enabled_extension_count: mem.read_u32(addr.add(28))?,
            pp_enabled_extension_names: GuestAddr::new(mem.read_u32(addr.add(32))?),
            p_enabled_features: GuestAddr::new(mem.read_u32(addr.add(36))?),
        })
    }
}

/// 32-bit Guest Representation of VkSubmitInfo (36 bytes)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VkSubmitInfo32 {
    pub s_type: u32,
    pub p_next: GuestAddr,
    pub wait_semaphore_count: u32,
    pub p_wait_semaphores: GuestAddr,
    pub p_wait_dst_stage_mask: GuestAddr,
    pub command_buffer_count: u32,
    pub p_command_buffers: GuestAddr,
    pub signal_semaphore_count: u32,
    pub p_signal_semaphores: GuestAddr,
}

impl VkSubmitInfo32 {
    pub fn read(mem: &impl Memory, addr: GuestAddr) -> Result<Self, MemoryError> {
        Ok(Self {
            s_type: mem.read_u32(addr)?,
            p_next: GuestAddr::new(mem.read_u32(addr.add(4))?),
            wait_semaphore_count: mem.read_u32(addr.add(8))?,
            p_wait_semaphores: GuestAddr::new(mem.read_u32(addr.add(12))?),
            p_wait_dst_stage_mask: GuestAddr::new(mem.read_u32(addr.add(16))?),
            command_buffer_count: mem.read_u32(addr.add(20))?,
            p_command_buffers: GuestAddr::new(mem.read_u32(addr.add(24))?),
            signal_semaphore_count: mem.read_u32(addr.add(28))?,
            p_signal_semaphores: GuestAddr::new(mem.read_u32(addr.add(32))?),
        })
    }
}

/// 32-bit Guest Representation of VkAndroidSurfaceCreateInfoKHR (16 bytes)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VkAndroidSurfaceCreateInfoKHR32 {
    pub s_type: u32,
    pub p_next: GuestAddr,
    pub flags: u32,
    pub window: GuestAddr, // ANativeWindow pointer
}

impl VkAndroidSurfaceCreateInfoKHR32 {
    pub fn read(mem: &impl Memory, addr: GuestAddr) -> Result<Self, MemoryError> {
        Ok(Self {
            s_type: mem.read_u32(addr)?,
            p_next: GuestAddr::new(mem.read_u32(addr.add(4))?),
            flags: mem.read_u32(addr.add(8))?,
            window: GuestAddr::new(mem.read_u32(addr.add(12))?),
        })
    }
}

/// 32-bit Guest Representation of VkSwapchainCreateInfoKHR (44 bytes)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VkSwapchainCreateInfoKHR32 {
    pub s_type: u32,
    pub p_next: GuestAddr,
    pub flags: u32,
    pub surface: u32,
    pub min_image_count: u32,
    pub image_format: u32,
    pub image_color_space: u32,
    pub image_extent_width: u32,
    pub image_extent_height: u32,
    pub image_array_layers: u32,
    pub image_usage: u32,
}

impl VkSwapchainCreateInfoKHR32 {
    pub fn read(mem: &impl Memory, addr: GuestAddr) -> Result<Self, MemoryError> {
        Ok(Self {
            s_type: mem.read_u32(addr)?,
            p_next: GuestAddr::new(mem.read_u32(addr.add(4))?),
            flags: mem.read_u32(addr.add(8))?,
            surface: mem.read_u32(addr.add(12))?,
            min_image_count: mem.read_u32(addr.add(16))?,
            image_format: mem.read_u32(addr.add(20))?,
            image_color_space: mem.read_u32(addr.add(24))?,
            image_extent_width: mem.read_u32(addr.add(28))?,
            image_extent_height: mem.read_u32(addr.add(32))?,
            image_array_layers: mem.read_u32(addr.add(36))?,
            image_usage: mem.read_u32(addr.add(40))?,
        })
    }
}

/// 32-bit Guest Representation of VkPresentInfoKHR (32 bytes)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VkPresentInfoKHR32 {
    pub s_type: u32,
    pub p_next: GuestAddr,
    pub wait_semaphore_count: u32,
    pub p_wait_semaphores: GuestAddr,
    pub swapchain_count: u32,
    pub p_swapchains: GuestAddr,
    pub p_image_indices: GuestAddr,
    pub p_results: GuestAddr,
}

impl VkPresentInfoKHR32 {
    pub fn read(mem: &impl Memory, addr: GuestAddr) -> Result<Self, MemoryError> {
        Ok(Self {
            s_type: mem.read_u32(addr)?,
            p_next: GuestAddr::new(mem.read_u32(addr.add(4))?),
            wait_semaphore_count: mem.read_u32(addr.add(8))?,
            p_wait_semaphores: GuestAddr::new(mem.read_u32(addr.add(12))?),
            swapchain_count: mem.read_u32(addr.add(16))?,
            p_swapchains: GuestAddr::new(mem.read_u32(addr.add(20))?),
            p_image_indices: GuestAddr::new(mem.read_u32(addr.add(24))?),
            p_results: GuestAddr::new(mem.read_u32(addr.add(28))?),
        })
    }
}

/// Vulkan Passthrough Bridge managing 32-bit <-> 64-bit handle translation and forwarding
pub struct VulkanBridge {
    pub stub_base: GuestAddr,
    symbol_table: HashMap<String, GuestAddr>,
    next_handle32: u32,
    /// 32-bit guest handle -> 64-bit host handle
    handle_map_32_to_64: HashMap<u32, u64>,
    /// 64-bit host handle -> 32-bit guest handle
    handle_map_64_to_32: HashMap<u64, u32>,
    /// Tracked draw and submit calls for verification and telemetry
    pub submit_count: u64,
    pub draw_count: u64,
    pub present_count: u64,
    pub bound_android_window: Option<GuestAddr>,
    pub host_window_ptr: usize,
    pub active_surfaces: HashMap<u32, GuestAddr>,
    pub active_swapchains: HashMap<u32, u32>,
    #[cfg(target_os = "android")]
    host: HostBridge,
}

impl Default for VulkanBridge {
    fn default() -> Self {
        Self::new()
    }
}

impl VulkanBridge {
    pub fn new() -> Self {
        Self::with_stub_base(GuestAddr::new(0))
    }

    pub fn with_stub_base(stub_base: GuestAddr) -> Self {
        let mut bridge = Self {
            stub_base,
            symbol_table: HashMap::new(),
            next_handle32: 100,
            handle_map_32_to_64: HashMap::new(),
            handle_map_64_to_32: HashMap::new(),
            submit_count: 0,
            draw_count: 0,
            present_count: 0,
            bound_android_window: None,
            host_window_ptr: 0,
            active_surfaces: HashMap::new(),
            active_swapchains: HashMap::new(),
            #[cfg(target_os = "android")]
            host: HostBridge::new(),
        };
        bridge.register_known_symbols();
        bridge
    }

    fn register_known_symbols(&mut self) {
        if self.stub_base.as_u32() == 0 {
            return;
        }
        let funcs = [
            ("vkCreateInstance", VulkanFuncId::VkCreateInstance),
            ("vkDestroyInstance", VulkanFuncId::VkDestroyInstance),
            ("vkEnumeratePhysicalDevices", VulkanFuncId::VkEnumeratePhysicalDevices),
            ("vkGetPhysicalDeviceProperties", VulkanFuncId::VkGetPhysicalDeviceProperties),
            ("vkGetPhysicalDeviceQueueFamilyProperties", VulkanFuncId::VkGetPhysicalDeviceQueueFamilyProperties),
            ("vkCreateDevice", VulkanFuncId::VkCreateDevice),
            ("vkDestroyDevice", VulkanFuncId::VkDestroyDevice),
            ("vkGetDeviceQueue", VulkanFuncId::VkGetDeviceQueue),
            ("vkQueueSubmit", VulkanFuncId::VkQueueSubmit),
            ("vkQueueWaitIdle", VulkanFuncId::VkQueueWaitIdle),
            ("vkDeviceWaitIdle", VulkanFuncId::VkDeviceWaitIdle),
            ("vkCreateAndroidSurfaceKHR", VulkanFuncId::VkCreateAndroidSurfaceKHR),
            ("vkDestroySurfaceKHR", VulkanFuncId::VkDestroySurfaceKHR),
            ("vkGetPhysicalDeviceSurfaceSupportKHR", VulkanFuncId::VkGetPhysicalDeviceSurfaceSupportKHR),
            ("vkGetPhysicalDeviceSurfaceCapabilitiesKHR", VulkanFuncId::VkGetPhysicalDeviceSurfaceCapabilitiesKHR),
            ("vkCreateSwapchainKHR", VulkanFuncId::VkCreateSwapchainKHR),
            ("vkDestroySwapchainKHR", VulkanFuncId::VkDestroySwapchainKHR),
            ("vkGetSwapchainImagesKHR", VulkanFuncId::VkGetSwapchainImagesKHR),
            ("vkAcquireNextImageKHR", VulkanFuncId::VkAcquireNextImageKHR),
            ("vkQueuePresentKHR", VulkanFuncId::VkQueuePresentKHR),
            ("vkCmdDraw", VulkanFuncId::VkCmdDraw),
            ("vkGetInstanceProcAddr", VulkanFuncId::VkGetInstanceProcAddr),
            ("vkGetDeviceProcAddr", VulkanFuncId::VkGetDeviceProcAddr),
            ("vkEnumerateInstanceExtensionProperties", VulkanFuncId::VkEnumerateInstanceExtensionProperties),
        ];
        for (name, id) in funcs {
            let addr = self.stub_base.add((id as u32) * 8);
            self.symbol_table.insert(name.to_string(), addr);
        }
    }

    /// Installs ARM32 SVC stubs for all Vulkan entry points into guest memory
    pub fn install_stubs(&self, mem: &mut impl Memory) -> Result<(), MemoryError> {
        if self.stub_base.as_u32() == 0 {
            return Ok(());
        }
        for id_val in 1..=24 {
            if let Some(id) = VulkanFuncId::from_u32(id_val) {
                let addr = self.stub_base.add((id as u32) * 8);
                let svc_code = 0xEF00_0000 | (VULKAN_SVC_MAGIC | (id as u32));
                let bx_lr = 0xE12F_FF1E;
                mem.write_u32(addr, svc_code)?;
                mem.write_u32(addr.add(4), bx_lr)?;
            }
        }
        Ok(())
    }

    fn read_c_string(mem: &impl Memory, addr: GuestAddr) -> Result<String, MemoryError> {
        if addr.as_u32() == 0 {
            return Ok(String::new());
        }
        let mut bytes = Vec::new();
        let mut cur = addr;
        for _ in 0..4096 {
            let b = mem.read_u8(cur)?;
            if b == 0 {
                break;
            }
            bytes.push(b);
            cur = cur.add(1);
        }
        Ok(String::from_utf8_lossy(&bytes).to_string())
    }

    #[cfg(target_os = "android")]
    fn read_c_string_array(
        mem: &impl Memory,
        array_addr: GuestAddr,
        count: u32,
    ) -> Result<Vec<CString>, MemoryError> {
        let mut out = Vec::new();
        if array_addr.as_u32() == 0 || count == 0 {
            return Ok(out);
        }
        for i in 0..count.min(128) {
            let ptr = GuestAddr::new(mem.read_u32(array_addr.add(i * 4))?);
            let s = Self::read_c_string(mem, ptr)?;
            if let Ok(cs) = CString::new(s) {
                out.push(cs);
            }
        }
        Ok(out)
    }

    /// Registers a 64-bit host handle and returns a 32-bit handle safe for guest memory
    pub fn register_host_handle(&mut self, host_handle: u64) -> u32 {
        if let Some(&handle32) = self.handle_map_64_to_32.get(&host_handle) {
            return handle32;
        }
        let handle32 = self.next_handle32;
        self.next_handle32 += 1;
        self.handle_map_32_to_64.insert(handle32, host_handle);
        self.handle_map_64_to_32.insert(host_handle, handle32);
        handle32
    }

    /// Resolves a 32-bit guest handle back to the host 64-bit Vulkan handle
    pub fn resolve_guest_handle(&self, handle32: u32) -> Option<u64> {
        self.handle_map_32_to_64.get(&handle32).copied()
    }

    /// Unregisters and destroys a 32-bit guest handle, preventing translation map leaks
    pub fn unregister_guest_handle(&mut self, handle32: u32) {
        if let Some(host_handle) = self.handle_map_32_to_64.remove(&handle32) {
            self.handle_map_64_to_32.remove(&host_handle);
        }
        self.active_surfaces.remove(&handle32);
        self.active_swapchains.remove(&handle32);
    }

    /// Intercepts vkCreateInstance from guest 32-bit ARM code
    pub fn vk_create_instance(
        &mut self,
        mem: &mut impl Memory,
        p_create_info: GuestAddr,
        p_instance: GuestAddr,
    ) -> Result<i32, MemoryError> {
        let create_info = VkInstanceCreateInfo32::read(mem, p_create_info)?;
        if create_info.s_type != VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO {
            return Ok(VK_ERROR_INITIALIZATION_FAILED);
        }

        #[cfg(target_os = "android")]
        if let Some(fp) = self.host.resolve("vkCreateInstance") {
            let app_info_32 = if create_info.p_application_info.as_u32() != 0 {
                Some(VkApplicationInfo32::read(mem, create_info.p_application_info)?)
            } else {
                None
            };
            let app_name_c = app_info_32
                .as_ref()
                .filter(|a| a.p_application_name.as_u32() != 0)
                .map(|a| Self::read_c_string(mem, a.p_application_name))
                .transpose()?
                .and_then(|s| CString::new(s).ok());
            let engine_name_c = app_info_32
                .as_ref()
                .filter(|a| a.p_engine_name.as_u32() != 0)
                .map(|a| Self::read_c_string(mem, a.p_engine_name))
                .transpose()?
                .and_then(|s| CString::new(s).ok());

            let host_app_info = app_info_32.as_ref().map(|a| HostVkApplicationInfo {
                s_type: a.s_type,
                p_next: std::ptr::null(),
                p_application_name: app_name_c.as_ref().map(|c| c.as_ptr()).unwrap_or(std::ptr::null()),
                application_version: a.application_version,
                p_engine_name: engine_name_c.as_ref().map(|c| c.as_ptr()).unwrap_or(std::ptr::null()),
                engine_version: a.engine_version,
                api_version: a.api_version,
            });

            let layers_c = Self::read_c_string_array(
                mem,
                create_info.pp_enabled_layer_names,
                create_info.enabled_layer_count,
            )?;
            let layer_ptrs: Vec<*const c_char> = layers_c.iter().map(|c| c.as_ptr()).collect();
            let exts_c = Self::read_c_string_array(
                mem,
                create_info.pp_enabled_extension_names,
                create_info.enabled_extension_count,
            )?;
            let ext_ptrs: Vec<*const c_char> = exts_c.iter().map(|c| c.as_ptr()).collect();

            let host_ci = HostVkInstanceCreateInfo {
                s_type: create_info.s_type,
                p_next: std::ptr::null(),
                flags: create_info.flags,
                p_application_info: host_app_info
                    .as_ref()
                    .map(|a| a as *const HostVkApplicationInfo)
                    .unwrap_or(std::ptr::null()),
                enabled_layer_count: layer_ptrs.len() as u32,
                pp_enabled_layer_names: if layer_ptrs.is_empty() {
                    std::ptr::null()
                } else {
                    layer_ptrs.as_ptr()
                },
                enabled_extension_count: ext_ptrs.len() as u32,
                pp_enabled_extension_names: if ext_ptrs.is_empty() {
                    std::ptr::null()
                } else {
                    ext_ptrs.as_ptr()
                },
            };

            let create_fn: unsafe extern "C" fn(
                *const HostVkInstanceCreateInfo,
                *const c_void,
                *mut u64,
            ) -> i32 = unsafe { std::mem::transmute(fp) };
            let mut host_instance: u64 = 0;
            let res = unsafe { create_fn(&host_ci, std::ptr::null(), &mut host_instance) };
            if res != VK_SUCCESS || host_instance == 0 {
                return Ok(res);
            }
            let handle32 = self.register_host_handle(host_instance);
            if p_instance.as_u32() != 0 {
                mem.write_u32(p_instance, handle32)?;
            }
            return Ok(VK_SUCCESS);
        }

        // Mock / non-Android fallback
        let mock_host_instance: u64 = 0x7FFF_8000_1000;
        let handle32 = self.register_host_handle(mock_host_instance);

        // Write 32-bit handle into guest pointer
        if p_instance.as_u32() != 0 {
            mem.write_u32(p_instance, handle32)?;
        }
        Ok(VK_SUCCESS)
    }

    /// Intercepts vkQueueSubmit from guest 32-bit ARM code
    pub fn vk_queue_submit(
        &mut self,
        mem: &impl Memory,
        queue_handle32: u32,
        submit_count: u32,
        p_submits: GuestAddr,
    ) -> Result<i32, MemoryError> {
        if self.resolve_guest_handle(queue_handle32).is_none() {
            return Ok(VK_ERROR_DEVICE_LOST);
        }

        for i in 0..submit_count {
            let submit_addr = p_submits.add(i * 36);
            let submit = VkSubmitInfo32::read(mem, submit_addr)?;
            if submit.s_type != VK_STRUCTURE_TYPE_SUBMIT_INFO {
                return Ok(VK_ERROR_INITIALIZATION_FAILED);
            }
            self.submit_count += 1;
        }

        Ok(VK_SUCCESS)
    }

    /// Intercepts vkCmdDraw
    pub fn vk_cmd_draw(
        &mut self,
        _cmd_buf_handle32: u32,
        _vertex_count: u32,
        _instance_count: u32,
        _first_vertex: u32,
        _first_instance: u32,
    ) {
        self.draw_count += 1;
    }

    /// Intercepts vkCreateAndroidSurfaceKHR from guest 32-bit ARM code
    pub fn vk_create_android_surface_khr(
        &mut self,
        mem: &mut impl Memory,
        _instance_handle32: u32,
        p_create_info: GuestAddr,
        p_surface: GuestAddr,
    ) -> Result<i32, MemoryError> {
        let create_info = VkAndroidSurfaceCreateInfoKHR32::read(mem, p_create_info)?;
        if create_info.s_type != VK_STRUCTURE_TYPE_ANDROID_SURFACE_CREATE_INFO_KHR {
            return Ok(VK_ERROR_INITIALIZATION_FAILED);
        }

        self.bound_android_window = Some(create_info.window);

        #[cfg(target_os = "android")]
        if self.host_window_ptr != 0 {
            if let (Some(inst64), Some(fp)) = (
                self.resolve_guest_handle(_instance_handle32),
                self.host.resolve("vkCreateAndroidSurfaceKHR"),
            ) {
                let host_ci = HostVkAndroidSurfaceCreateInfoKHR {
                    s_type: create_info.s_type,
                    p_next: std::ptr::null(),
                    flags: create_info.flags,
                    window: self.host_window_ptr as *mut c_void,
                };
                let create_surf: unsafe extern "C" fn(
                    u64,
                    *const HostVkAndroidSurfaceCreateInfoKHR,
                    *const c_void,
                    *mut u64,
                ) -> i32 = unsafe { std::mem::transmute(fp) };
                let mut host_surface: u64 = 0;
                let res = unsafe {
                    create_surf(inst64, &host_ci, std::ptr::null(), &mut host_surface)
                };
                if res != VK_SUCCESS {
                    return Ok(res);
                }
                let surface32 = self.register_host_handle(host_surface);
                self.active_surfaces.insert(surface32, create_info.window);
                if p_surface.as_u32() != 0 {
                    mem.write_u32(p_surface, surface32)?;
                }
                return Ok(VK_SUCCESS);
            }
        }

        let mock_host_surface = 0x8888_1111_2222_3333_u64;
        let surface32 = self.register_host_handle(mock_host_surface);
        self.active_surfaces.insert(surface32, create_info.window);
        mem.write_u32(p_surface, surface32)?;
        Ok(VK_SUCCESS)
    }

    /// Intercepts vkCreateSwapchainKHR from guest 32-bit ARM code
    pub fn vk_create_swapchain_khr(
        &mut self,
        mem: &mut impl Memory,
        _device_handle32: u32,
        p_create_info: GuestAddr,
        p_swapchain: GuestAddr,
    ) -> Result<i32, MemoryError> {
        let create_info = VkSwapchainCreateInfoKHR32::read(mem, p_create_info)?;
        if create_info.s_type != VK_STRUCTURE_TYPE_SWAPCHAIN_CREATE_INFO_KHR {
            return Ok(VK_ERROR_INITIALIZATION_FAILED);
        }

        let mock_host_swapchain = 0x7777_4444_5555_6666_u64;
        let swapchain32 = self.register_host_handle(mock_host_swapchain);
        self.active_swapchains.insert(swapchain32, create_info.surface);
        mem.write_u32(p_swapchain, swapchain32)?;
        Ok(VK_SUCCESS)
    }

    /// Intercepts vkGetSwapchainImagesKHR from guest 32-bit ARM code
    pub fn vk_get_swapchain_images_khr(
        &mut self,
        mem: &mut impl Memory,
        _device32: u32,
        swapchain32: u32,
        p_count: GuestAddr,
        p_images: GuestAddr,
    ) -> Result<i32, MemoryError> {
        if self.resolve_guest_handle(swapchain32).is_none() {
            return Ok(VK_ERROR_DEVICE_LOST);
        }

        if p_images.as_u32() == 0 {
            mem.write_u32(p_count, 3)?; // 3 swapchain images (triple buffering)
        } else {
            let count = mem.read_u32(p_count)?;
            for i in 0..count.min(3) {
                let mock_img = 0x9000_0000_0000_0000_u64 | (i as u64);
                let img32 = self.register_host_handle(mock_img);
                mem.write_u32(p_images.add(i * 4), img32)?;
            }
        }
        Ok(VK_SUCCESS)
    }

    /// Intercepts vkQueuePresentKHR
    pub fn vk_queue_present_khr(
        &mut self,
        mem: &impl Memory,
        queue32: u32,
        p_present_info: GuestAddr,
    ) -> Result<i32, MemoryError> {
        if self.resolve_guest_handle(queue32).is_none() {
            return Ok(VK_ERROR_DEVICE_LOST);
        }

        let present = VkPresentInfoKHR32::read(mem, p_present_info)?;
        if present.s_type != VK_STRUCTURE_TYPE_PRESENT_INFO_KHR {
            return Ok(VK_ERROR_INITIALIZATION_FAILED);
        }

        self.present_count += 1;
        Ok(VK_SUCCESS)
    }

    /// Handles an incoming Vulkan SVC call (`VULKAN_SVC_MAGIC | VulkanFuncId`)
    pub fn handle_svc(
        &mut self,
        svc_imm: u32,
        cpu: &mut CpuState,
        mem: &mut impl Memory,
    ) -> Result<bool, MemoryError> {
        if (svc_imm & 0xFF0000) != VULKAN_SVC_MAGIC {
            return Ok(false);
        }
        let func_id = svc_imm & 0xFFFF;
        match VulkanFuncId::from_u32(func_id) {
            Some(VulkanFuncId::VkCreateInstance) => {
                let p_ci = GuestAddr::new(cpu.reg(Reg::R0));
                let p_inst = GuestAddr::new(cpu.reg(Reg::R2));
                let res = self.vk_create_instance(mem, p_ci, p_inst)?;
                cpu.set_reg(Reg::R0, res as u32);
            }
            Some(VulkanFuncId::VkDestroyInstance) => {
                let inst32 = cpu.reg(Reg::R0);
                #[cfg(target_os = "android")]
                if let (Some(inst64), Some(fp)) = (
                    self.resolve_guest_handle(inst32),
                    self.host.resolve("vkDestroyInstance"),
                ) {
                    let destroy_fn: unsafe extern "C" fn(u64, *const c_void) =
                        unsafe { std::mem::transmute(fp) };
                    unsafe { destroy_fn(inst64, std::ptr::null()) };
                }
                self.unregister_guest_handle(inst32);
            }
            Some(VulkanFuncId::VkEnumeratePhysicalDevices) => {
                let inst32 = cpu.reg(Reg::R0);
                let p_count = GuestAddr::new(cpu.reg(Reg::R1));
                let p_devs = GuestAddr::new(cpu.reg(Reg::R2));
                if self.resolve_guest_handle(inst32).is_none() || p_count.as_u32() == 0 {
                    cpu.set_reg(Reg::R0, VK_ERROR_INITIALIZATION_FAILED as u32);
                    return Ok(true);
                }

                #[cfg(target_os = "android")]
                if let (Some(inst64), Some(fp)) = (
                    self.resolve_guest_handle(inst32),
                    self.host.resolve("vkEnumeratePhysicalDevices"),
                ) {
                    let enum_fn: unsafe extern "C" fn(u64, *mut u32, *mut u64) -> i32 =
                        unsafe { std::mem::transmute(fp) };
                    let mut count = if p_devs.as_u32() == 0 {
                        0
                    } else {
                        mem.read_u32(p_count)?.min(32)
                    };
                    let mut host_devs = vec![0u64; count as usize];
                    let ptr = if p_devs.as_u32() == 0 {
                        std::ptr::null_mut()
                    } else {
                        host_devs.as_mut_ptr()
                    };
                    let res = unsafe { enum_fn(inst64, &mut count, ptr) };
                    mem.write_u32(p_count, count)?;
                    if p_devs.as_u32() != 0 && res == VK_SUCCESS {
                        for (i, &hd) in host_devs.iter().take(count as usize).enumerate() {
                            let d32 = self.register_host_handle(hd);
                            mem.write_u32(p_devs.add((i as u32) * 4), d32)?;
                        }
                    }
                    cpu.set_reg(Reg::R0, res as u32);
                    return Ok(true);
                }

                // Non-Android / fallback single physical device
                if p_devs.as_u32() == 0 {
                    mem.write_u32(p_count, 1)?;
                } else {
                    let requested = mem.read_u32(p_count)?;
                    let written = requested.min(1);
                    mem.write_u32(p_count, written)?;
                    if written > 0 {
                        let d32 = self.register_host_handle(0x7FFF_8100_0001);
                        mem.write_u32(p_devs, d32)?;
                    }
                }
                cpu.set_reg(Reg::R0, VK_SUCCESS as u32);
            }
            Some(VulkanFuncId::VkCreateDevice) => {
                let p_dev = GuestAddr::new(cpu.reg(Reg::R3));
                let d32 = self.register_host_handle(0x7FFF_8200_0001);
                if p_dev.as_u32() != 0 {
                    mem.write_u32(p_dev, d32)?;
                }
                cpu.set_reg(Reg::R0, VK_SUCCESS as u32);
            }
            Some(VulkanFuncId::VkDestroyDevice) => {
                let dev32 = cpu.reg(Reg::R0);
                self.unregister_guest_handle(dev32);
            }
            Some(VulkanFuncId::VkGetDeviceQueue) => {
                let p_queue = GuestAddr::new(cpu.reg(Reg::R3));
                let q32 = self.register_host_handle(0x7FFF_8300_0001);
                if p_queue.as_u32() != 0 {
                    mem.write_u32(p_queue, q32)?;
                }
            }
            Some(VulkanFuncId::VkQueueSubmit) => {
                let q32 = cpu.reg(Reg::R0);
                let count = cpu.reg(Reg::R1);
                let p_submits = GuestAddr::new(cpu.reg(Reg::R2));
                let res = self.vk_queue_submit(mem, q32, count, p_submits)?;
                cpu.set_reg(Reg::R0, res as u32);
            }
            Some(VulkanFuncId::VkQueueWaitIdle | VulkanFuncId::VkDeviceWaitIdle) => {
                cpu.set_reg(Reg::R0, VK_SUCCESS as u32);
            }
            Some(VulkanFuncId::VkCreateAndroidSurfaceKHR) => {
                let inst32 = cpu.reg(Reg::R0);
                let p_ci = GuestAddr::new(cpu.reg(Reg::R1));
                let p_surf = GuestAddr::new(cpu.reg(Reg::R3));
                let res = self.vk_create_android_surface_khr(mem, inst32, p_ci, p_surf)?;
                cpu.set_reg(Reg::R0, res as u32);
            }
            Some(VulkanFuncId::VkDestroySurfaceKHR) => {
                let inst32 = cpu.reg(Reg::R0);
                let surf32 = cpu.reg(Reg::R1);
                #[cfg(target_os = "android")]
                if let (Some(inst64), Some(surf64), Some(fp)) = (
                    self.resolve_guest_handle(inst32),
                    self.resolve_guest_handle(surf32),
                    self.host.resolve("vkDestroySurfaceKHR"),
                ) {
                    let destroy_fn: unsafe extern "C" fn(u64, u64, *const c_void) =
                        unsafe { std::mem::transmute(fp) };
                    unsafe { destroy_fn(inst64, surf64, std::ptr::null()) };
                }
                let _ = inst32;
                self.unregister_guest_handle(surf32);
            }
            Some(VulkanFuncId::VkGetPhysicalDeviceSurfaceSupportKHR) => {
                let p_supported = GuestAddr::new(cpu.reg(Reg::R3));
                if p_supported.as_u32() != 0 {
                    mem.write_u32(p_supported, 1)?;
                }
                cpu.set_reg(Reg::R0, VK_SUCCESS as u32);
            }
            Some(VulkanFuncId::VkCreateSwapchainKHR) => {
                let dev32 = cpu.reg(Reg::R0);
                let p_ci = GuestAddr::new(cpu.reg(Reg::R1));
                let p_sc = GuestAddr::new(cpu.reg(Reg::R3));
                let res = self.vk_create_swapchain_khr(mem, dev32, p_ci, p_sc)?;
                cpu.set_reg(Reg::R0, res as u32);
            }
            Some(VulkanFuncId::VkDestroySwapchainKHR) => {
                let sc32 = cpu.reg(Reg::R1);
                self.unregister_guest_handle(sc32);
            }
            Some(VulkanFuncId::VkGetSwapchainImagesKHR) => {
                let dev32 = cpu.reg(Reg::R0);
                let sc32 = cpu.reg(Reg::R1);
                let p_count = GuestAddr::new(cpu.reg(Reg::R2));
                let p_images = GuestAddr::new(cpu.reg(Reg::R3));
                let res = self.vk_get_swapchain_images_khr(mem, dev32, sc32, p_count, p_images)?;
                cpu.set_reg(Reg::R0, res as u32);
            }
            Some(VulkanFuncId::VkAcquireNextImageKHR) => {
                let sp = GuestAddr::new(cpu.sp());
                let p_index = GuestAddr::new(mem.read_u32(sp.add(4))?);
                if p_index.as_u32() != 0 {
                    mem.write_u32(p_index, (self.present_count % 3) as u32)?;
                }
                cpu.set_reg(Reg::R0, VK_SUCCESS as u32);
            }
            Some(VulkanFuncId::VkQueuePresentKHR) => {
                let q32 = cpu.reg(Reg::R0);
                let p_pi = GuestAddr::new(cpu.reg(Reg::R1));
                let res = self.vk_queue_present_khr(mem, q32, p_pi)?;
                cpu.set_reg(Reg::R0, res as u32);
            }
            Some(VulkanFuncId::VkCmdDraw) => {
                let cmd = cpu.reg(Reg::R0);
                let v = cpu.reg(Reg::R1);
                let inst = cpu.reg(Reg::R2);
                let fv = cpu.reg(Reg::R3);
                let fi = mem.read_u32(GuestAddr::new(cpu.sp()))?;
                self.vk_cmd_draw(cmd, v, inst, fv, fi);
            }
            Some(VulkanFuncId::VkGetInstanceProcAddr | VulkanFuncId::VkGetDeviceProcAddr) => {
                let name_ptr = GuestAddr::new(cpu.reg(Reg::R1));
                let name = Self::read_c_string(mem, name_ptr)?;
                let addr = self.symbol_table.get(&name).map(|a| a.as_u32()).unwrap_or(0);
                cpu.set_reg(Reg::R0, addr);
            }
            Some(VulkanFuncId::VkEnumerateInstanceExtensionProperties) => {
                let p_count = GuestAddr::new(cpu.reg(Reg::R1));
                let p_props = GuestAddr::new(cpu.reg(Reg::R2));
                if p_count.as_u32() != 0 && p_props.as_u32() == 0 {
                    mem.write_u32(p_count, 0)?;
                }
                cpu.set_reg(Reg::R0, VK_SUCCESS as u32);
            }
            Some(
                VulkanFuncId::VkGetPhysicalDeviceProperties
                | VulkanFuncId::VkGetPhysicalDeviceQueueFamilyProperties
                | VulkanFuncId::VkGetPhysicalDeviceSurfaceCapabilitiesKHR,
            ) => {
                if func_id == VulkanFuncId::VkGetPhysicalDeviceQueueFamilyProperties as u32 {
                    let p_count = GuestAddr::new(cpu.reg(Reg::R1));
                    let p_props = GuestAddr::new(cpu.reg(Reg::R2));
                    if p_count.as_u32() != 0 {
                        if p_props.as_u32() == 0 {
                            mem.write_u32(p_count, 1)?;
                        } else {
                            let n = mem.read_u32(p_count)?.min(1);
                            mem.write_u32(p_count, n)?;
                            if n > 0 {
                                // VkQueueFamilyProperties: GRAPHICS | COMPUTE | TRANSFER, count=4
                                mem.write_u32(p_props, 0x07)?;
                                mem.write_u32(p_props.add(4), 4)?;
                                mem.write_u32(p_props.add(8), 64)?;
                                mem.write_u32(p_props.add(12), 1)?;
                                mem.write_u32(p_props.add(16), 1)?;
                                mem.write_u32(p_props.add(20), 1)?;
                            }
                        }
                    }
                }
                cpu.set_reg(Reg::R0, VK_SUCCESS as u32);
            }
            None => {
                cpu.set_reg(Reg::R0, VK_ERROR_INITIALIZATION_FAILED as u32);
            }
        }
        Ok(true)
    }
}

impl SymbolResolver for VulkanBridge {
    fn resolve(&self, name: &str) -> Option<GuestAddr> {
        self.symbol_table.get(name).copied()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use walzer32_core::FlatMemory;

    #[test]
    fn test_vulkan_handle_translation() {
        let mut bridge = VulkanBridge::new();
        let host_handle = 0xDEAD_BEEF_CAFE_BABE_u64;
        let handle32 = bridge.register_host_handle(host_handle);

        assert_eq!(bridge.resolve_guest_handle(handle32), Some(host_handle));
        // Idempotent
        assert_eq!(bridge.register_host_handle(host_handle), handle32);
    }

    #[test]
    fn test_vulkan_create_instance_passthrough() {
        let mut mem = FlatMemory::new(GuestAddr::new(0x1000), 0x2000);
        let mut bridge = VulkanBridge::new();

        // Setup VkInstanceCreateInfo32 at 0x1100
        let p_create_info = GuestAddr::new(0x1100);
        mem.write_u32(p_create_info, VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO).unwrap();
        mem.write_u32(p_create_info.add(4), 0).unwrap(); // pNext = NULL
        mem.write_u32(p_create_info.add(8), 0).unwrap(); // flags = 0
        mem.write_u32(p_create_info.add(12), 0).unwrap(); // pApplicationInfo = NULL
        mem.write_u32(p_create_info.add(16), 0).unwrap(); // enabledLayerCount = 0
        mem.write_u32(p_create_info.add(20), 0).unwrap();
        mem.write_u32(p_create_info.add(24), 0).unwrap();
        mem.write_u32(p_create_info.add(28), 0).unwrap();

        let p_instance = GuestAddr::new(0x1500);
        let res = bridge.vk_create_instance(&mut mem, p_create_info, p_instance).unwrap();
        assert_eq!(res, VK_SUCCESS);

        let created_handle32 = mem.read_u32(p_instance).unwrap();
        assert!(created_handle32 >= 100);
        assert!(bridge.resolve_guest_handle(created_handle32).is_some());
    }

    #[test]
    fn test_vulkan_queue_submit() {
        let mut mem = FlatMemory::new(GuestAddr::new(0x1000), 0x2000);
        let mut bridge = VulkanBridge::new();

        let queue32 = bridge.register_host_handle(0x1234_5678_u64);

        // Setup VkSubmitInfo32 at 0x1200
        let p_submit = GuestAddr::new(0x1200);
        mem.write_u32(p_submit, VK_STRUCTURE_TYPE_SUBMIT_INFO).unwrap();
        mem.write_u32(p_submit.add(4), 0).unwrap();
        mem.write_u32(p_submit.add(8), 0).unwrap(); // waitSemaphoreCount = 0
        mem.write_u32(p_submit.add(12), 0).unwrap();
        mem.write_u32(p_submit.add(16), 0).unwrap();
        mem.write_u32(p_submit.add(20), 1).unwrap(); // cmdBufferCount = 1
        mem.write_u32(p_submit.add(24), 0x1300).unwrap();
        mem.write_u32(p_submit.add(28), 0).unwrap();
        mem.write_u32(p_submit.add(32), 0).unwrap();

        let res = bridge.vk_queue_submit(&mem, queue32, 1, p_submit).unwrap();
        assert_eq!(res, VK_SUCCESS);
        assert_eq!(bridge.submit_count, 1);
    }

    #[test]
    fn test_vulkan_android_surface_and_swapchain() {
        let mut mem = FlatMemory::new(GuestAddr::new(0x2000), 0x2000);
        let mut bridge = VulkanBridge::new();

        // 1. Create Android Surface KHR
        let p_surface_info = GuestAddr::new(0x2100);
        mem.write_u32(p_surface_info, VK_STRUCTURE_TYPE_ANDROID_SURFACE_CREATE_INFO_KHR).unwrap();
        mem.write_u32(p_surface_info.add(4), 0).unwrap(); // pNext
        mem.write_u32(p_surface_info.add(8), 0).unwrap(); // flags
        mem.write_u32(p_surface_info.add(12), 0x3000_0001).unwrap(); // ANativeWindow*

        let p_surface = GuestAddr::new(0x2150);
        let res = bridge.vk_create_android_surface_khr(&mut mem, 100, p_surface_info, p_surface).unwrap();
        assert_eq!(res, VK_SUCCESS);

        let surface32 = mem.read_u32(p_surface).unwrap();
        assert!(surface32 >= 100);
        assert_eq!(bridge.bound_android_window, Some(GuestAddr::new(0x3000_0001)));

        // 2. Create Swapchain KHR
        let p_swapchain_info = GuestAddr::new(0x2200);
        mem.write_u32(p_swapchain_info, VK_STRUCTURE_TYPE_SWAPCHAIN_CREATE_INFO_KHR).unwrap();
        mem.write_u32(p_swapchain_info.add(4), 0).unwrap();
        mem.write_u32(p_swapchain_info.add(8), 0).unwrap();
        mem.write_u32(p_swapchain_info.add(12), surface32).unwrap();
        mem.write_u32(p_swapchain_info.add(16), 3).unwrap(); // minImageCount = 3
        mem.write_u32(p_swapchain_info.add(20), 44).unwrap(); // format
        mem.write_u32(p_swapchain_info.add(24), 0).unwrap();
        mem.write_u32(p_swapchain_info.add(28), 1920).unwrap();
        mem.write_u32(p_swapchain_info.add(32), 1080).unwrap();
        mem.write_u32(p_swapchain_info.add(36), 1).unwrap();
        mem.write_u32(p_swapchain_info.add(40), 0x10).unwrap();

        let p_swapchain = GuestAddr::new(0x2250);
        let res_sc = bridge.vk_create_swapchain_khr(&mut mem, 101, p_swapchain_info, p_swapchain).unwrap();
        assert_eq!(res_sc, VK_SUCCESS);

        let swapchain32 = mem.read_u32(p_swapchain).unwrap();
        assert_eq!(bridge.active_swapchains.get(&swapchain32), Some(&surface32));

        // 3. Get Swapchain Images
        let p_count = GuestAddr::new(0x2300);
        bridge.vk_get_swapchain_images_khr(&mut mem, 101, swapchain32, p_count, GuestAddr::new(0)).unwrap();
        let count = mem.read_u32(p_count).unwrap();
        assert_eq!(count, 3);

        let p_images = GuestAddr::new(0x2310);
        bridge.vk_get_swapchain_images_khr(&mut mem, 101, swapchain32, p_count, p_images).unwrap();
        let img0 = mem.read_u32(p_images).unwrap();
        assert!(img0 >= 100);

        // 4. Queue Present KHR
        let p_present = GuestAddr::new(0x2400);
        mem.write_u32(p_present, VK_STRUCTURE_TYPE_PRESENT_INFO_KHR).unwrap();
        mem.write_u32(p_present.add(4), 0).unwrap();
        mem.write_u32(p_present.add(8), 0).unwrap();
        mem.write_u32(p_present.add(12), 0).unwrap();
        mem.write_u32(p_present.add(16), 1).unwrap(); // swapchainCount = 1
        mem.write_u32(p_present.add(20), p_swapchain.as_u32()).unwrap();
        mem.write_u32(p_present.add(24), 0).unwrap();
        mem.write_u32(p_present.add(28), 0).unwrap();

        let queue32 = bridge.register_host_handle(0x5555_6666_u64);
        let res_pres = bridge.vk_queue_present_khr(&mem, queue32, p_present).unwrap();
        assert_eq!(res_pres, VK_SUCCESS);
        assert_eq!(bridge.present_count, 1);
    }

    #[test]
    fn test_vulkan_svc_dispatch_and_proc_addr() {
        let stub_base = GuestAddr::new(0x7000_0000);
        let mut mem = FlatMemory::new(stub_base, 0x10_000);
        let mut bridge = VulkanBridge::with_stub_base(stub_base);
        bridge.install_stubs(&mut mem).unwrap();

        let mut cpu = CpuState::new();
        let name_addr = stub_base.add(0x2000);
        mem.write_bytes(name_addr, b"vkCreateInstance\0").unwrap();
        cpu.set_reg(Reg::R0, 0);
        cpu.set_reg(Reg::R1, name_addr.as_u32());
        let handled = bridge
            .handle_svc(
                VULKAN_SVC_MAGIC | (VulkanFuncId::VkGetInstanceProcAddr as u32),
                &mut cpu,
                &mut mem,
            )
            .unwrap();
        assert!(handled);
        assert_eq!(cpu.reg(Reg::R0), bridge.resolve("vkCreateInstance").unwrap().as_u32());

        let ci = stub_base.add(0x3000);
        mem.write_u32(ci, VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO).unwrap();
        let out_inst = stub_base.add(0x3100);
        cpu.set_reg(Reg::R0, ci.as_u32());
        cpu.set_reg(Reg::R1, 0);
        cpu.set_reg(Reg::R2, out_inst.as_u32());
        bridge
            .handle_svc(
                VULKAN_SVC_MAGIC | (VulkanFuncId::VkCreateInstance as u32),
                &mut cpu,
                &mut mem,
            )
            .unwrap();
        assert_eq!(cpu.reg(Reg::R0) as i32, VK_SUCCESS);
        assert!(mem.read_u32(out_inst).unwrap() >= 100);
    }
}
