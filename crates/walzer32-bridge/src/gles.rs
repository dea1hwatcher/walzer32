use std::collections::HashMap;
#[cfg(target_os = "android")]
use std::ffi::{CStr, CString, c_char, c_void};
use walzer32_core::{GuestAddr, Memory, MemoryError, Reg};
use walzer32_elf::SymbolResolver;
use crate::host::{HostBridge, RawFnPtr};

pub const GLES_SVC_MAGIC: u32 = 0xE60000; // 'G' << 16

// EGL Constants
pub const EGL_NO_CONTEXT: u32 = 0;
pub const EGL_NO_SURFACE: u32 = 0;
pub const EGL_NO_DISPLAY: u32 = 0;
pub const EGL_DEFAULT_DISPLAY: u32 = 0;
pub const EGL_TRUE: u32 = 1;
pub const EGL_FALSE: u32 = 0;

pub const EGL_SUCCESS: u32 = 0x3000;
pub const EGL_NOT_INITIALIZED: u32 = 0x3001;
pub const EGL_BAD_ACCESS: u32 = 0x3002;
pub const EGL_BAD_ALLOC: u32 = 0x3003;
pub const EGL_BAD_ATTRIBUTE: u32 = 0x3004;
pub const EGL_BAD_CONFIG: u32 = 0x3005;
pub const EGL_BAD_CONTEXT: u32 = 0x3006;
pub const EGL_BAD_CURRENT_SURFACE: u32 = 0x3007;
pub const EGL_BAD_DISPLAY: u32 = 0x3008;
pub const EGL_BAD_MATCH: u32 = 0x3009;
pub const EGL_BAD_NATIVE_PIXMAP: u32 = 0x300A;
pub const EGL_BAD_NATIVE_WINDOW: u32 = 0x300B;
pub const EGL_BAD_PARAMETER: u32 = 0x300C;
pub const EGL_BAD_SURFACE: u32 = 0x300D;
pub const EGL_CONTEXT_LOST: u32 = 0x300E;

pub const EGL_NONE: u32 = 0x3038;
pub const EGL_WIDTH: u32 = 0x3057;
pub const EGL_HEIGHT: u32 = 0x3056;
pub const EGL_DRAW: u32 = 0x3059;
pub const EGL_READ: u32 = 0x305A;
pub const EGL_TEXTURE_FORMAT: u32 = 0x3080;
pub const EGL_TEXTURE_TARGET: u32 = 0x3081;
pub const EGL_CONTEXT_CLIENT_VERSION: u32 = 0x3098;

// EGL Sync / Fence Constants (EGL_KHR_fence_sync)
pub const EGL_SYNC_FENCE_KHR: u32 = 0x30FA;
pub const EGL_SYNC_TYPE_KHR: u32 = 0x30F7;
pub const EGL_SYNC_STATUS_KHR: u32 = 0x30F1;
pub const EGL_SIGNALED_KHR: u32 = 0x30F2;
pub const EGL_UNSIGNALED_KHR: u32 = 0x30F3;
pub const EGL_CONDITION_SATISFIED_KHR: u32 = 0x30F6;
pub const EGL_TIMEOUT_EXPIRED_KHR: u32 = 0x30F5;
pub const EGL_SYNC_FLUSH_COMMANDS_BIT_KHR: u32 = 0x0001;
pub const EGL_FOREVER_KHR: u64 = 0xFFFF_FFFF_FFFF_FFFF;

// OpenGL ES String Queries (glGetString name)
pub const GL_VENDOR: u32 = 0x1F00;
pub const GL_RENDERER: u32 = 0x1F01;
pub const GL_VERSION: u32 = 0x1F02;
pub const GL_EXTENSIONS: u32 = 0x1F03;
pub const GL_SHADING_LANGUAGE_VERSION: u32 = 0x8B8C;

// OpenGL ES Modes
pub const GL_TRIANGLES: u32 = 0x0004;
pub const GL_COLOR_BUFFER_BIT: u32 = 0x00004000;
pub const GL_DEPTH_BUFFER_BIT: u32 = 0x00000100;

// OpenGL ES Textures & Framebuffers
pub const GL_TEXTURE_2D: u32 = 0x0DE1;
pub const GL_TEXTURE_CUBE_MAP: u32 = 0x8513;
pub const GL_FRAMEBUFFER: u32 = 0x8D40;
pub const GL_FRAMEBUFFER_COMPLETE: u32 = 0x8CD5;
pub const GL_COLOR_ATTACHMENT0: u32 = 0x8CE0;
pub const GL_DEPTH_ATTACHMENT: u32 = 0x8D00;
pub const GL_RGBA: u32 = 0x1908;
pub const GL_RGB: u32 = 0x1907;
pub const GL_UNSIGNED_BYTE: u32 = 0x1401;

pub const GL_TEXTURE_MIN_FILTER: u32 = 0x2801;
pub const GL_TEXTURE_MAG_FILTER: u32 = 0x2800;
pub const GL_TEXTURE_WRAP_S: u32 = 0x2802;
pub const GL_TEXTURE_WRAP_T: u32 = 0x2803;

pub const GL_NEAREST: u32 = 0x2600;
pub const GL_LINEAR: u32 = 0x2601;
pub const GL_REPEAT: u32 = 0x2901;
pub const GL_CLAMP_TO_EDGE: u32 = 0x812F;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum GlesFuncId {
    // EGL Core
    EglGetDisplay = 1,
    EglInitialize = 2,
    EglChooseConfig = 3,
    EglCreateWindowSurface = 4,
    EglCreateContext = 5,
    EglMakeCurrent = 6,
    EglSwapBuffers = 7,
    EglGetError = 8,
    EglTerminate = 9,
    EglQueryString = 10,
    EglCreatePbufferSurface = 11,
    EglDestroySurface = 12,
    EglDestroyContext = 13,
    EglGetCurrentContext = 14,
    EglGetCurrentSurface = 15,
    EglGetCurrentDisplay = 16,
    EglReleaseThread = 17,
    EglGetProcAddress = 18,
    EglGetConfigAttrib = 19,

    // GLES State & Clear
    GlClearColor = 20,
    GlClear = 21,
    GlViewport = 22,
    GlEnable = 23,
    GlDisable = 24,
    EglQuerySurface = 25,
    GlBlendFunc = 26,
    GlDepthFunc = 27,
    GlCullFace = 28,
    GlFrontFace = 29,

    // GLES Shaders & Programs
    GlCreateShader = 30,
    GlShaderSource = 31,
    GlCompileShader = 32,
    GlGetShaderiv = 33,
    GlCreateProgram = 34,
    GlAttachShader = 35,
    GlLinkProgram = 36,
    GlGetProgramiv = 37,
    GlUseProgram = 38,
    GlDeleteShader = 39,

    // GLES Buffers & Drawing
    GlGenBuffers = 40,
    GlBindBuffer = 41,
    GlBufferData = 42,
    GlEnableVertexAttribArray = 43,
    GlVertexAttribPointer = 44,
    GlDrawArrays = 45,
    GlDrawElements = 46,
    GlDeleteBuffers = 47,
    GlDisableVertexAttribArray = 48,
    GlDeleteProgram = 49,

    // GLES Textures & Framebuffers
    GlGenTextures = 50,
    GlBindTexture = 51,
    GlTexImage2D = 52,
    GlTexParameteri = 53,
    GlActiveTexture = 54,
    GlGenFramebuffers = 55,
    GlBindFramebuffer = 56,
    GlFramebufferTexture2D = 57,
    GlCheckFramebufferStatus = 58,
    GlDeleteTextures = 59,

    // GLES Queries & Uniforms
    GlGetString = 60,
    GlGetUniformLocation = 61,
    GlUniform1i = 62,
    GlUniform4f = 63,
    GlGetError = 64,
    GlGetShaderInfoLog = 65,
    GlGetProgramInfoLog = 66,
    GlGetAttribLocation = 67,
    GlUniform1f = 68,
    GlUniform2f = 69,

    // EGL KHR Sync Fences
    EglCreateSyncKHR = 70,
    EglClientWaitSyncKHR = 71,
    EglDestroySyncKHR = 72,
    EglGetSyncAttribKHR = 73,
    EglWaitSyncKHR = 74,
    GlUniform3f = 75,
    GlUniformMatrix4fv = 76,
    GlClearDepthf = 77,
    GlDepthMask = 78,
    GlColorMask = 79,

    // GLES 1.1 Fixed-Function Pipeline (Stage 102)
    GlMatrixMode                            = 80,
    GlLoadIdentity                          = 81,
    GlLoadMatrixf                           = 82,
    GlPushMatrix                            = 83,
    GlPopMatrix                             = 84,
    GlOrthof                                = 85,
    GlFrustumf                              = 86,
    GlTranslatef                            = 87,
    GlScalef                                = 88,
    GlRotatef                               = 89,
    GlEnableClientState                     = 90,
    GlDisableClientState                    = 91,
    GlVertexPointer                         = 92,
    GlColorPointer                          = 93,
    GlTexCoordPointer                       = 94,
    GlNormalPointer                         = 95,
    GlAlphaFunc                             = 96,
    GlColor4f                               = 97,
    GlColor4ub                              = 98,
    GlClientActiveTexture                   = 99,
    GlShadeModel                            = 100,
    GlTexEnvf                               = 101,
    GlTexEnvi                               = 102,
    GlLightf                                = 103,
    GlLightfv                               = 104,
    GlMaterialf                             = 105,
    GlMaterialfv                            = 106,
    GlFogf                                  = 107,
    GlFogfv                                 = 108,
    GlUniform2fv                            = 109,
    GlUniform3fv                            = 110,
    GlUniform4fv                            = 111,
    GlDeleteFramebuffers                    = 112,
    GlScissor                               = 113,
    GlGetIntegerv                           = 114,
    GlPixelStorei                           = 115,
}

impl GlesFuncId {
    pub fn from_u32(val: u32) -> Option<Self> {
        match val {
            1 => Some(Self::EglGetDisplay),
            2 => Some(Self::EglInitialize),
            3 => Some(Self::EglChooseConfig),
            4 => Some(Self::EglCreateWindowSurface),
            5 => Some(Self::EglCreateContext),
            6 => Some(Self::EglMakeCurrent),
            7 => Some(Self::EglSwapBuffers),
            8 => Some(Self::EglGetError),
            9 => Some(Self::EglTerminate),
            10 => Some(Self::EglQueryString),
            11 => Some(Self::EglCreatePbufferSurface),
            12 => Some(Self::EglDestroySurface),
            13 => Some(Self::EglDestroyContext),
            14 => Some(Self::EglGetCurrentContext),
            15 => Some(Self::EglGetCurrentSurface),
            16 => Some(Self::EglGetCurrentDisplay),
            17 => Some(Self::EglReleaseThread),
            18 => Some(Self::EglGetProcAddress),
            19 => Some(Self::EglGetConfigAttrib),

            20 => Some(Self::GlClearColor),
            21 => Some(Self::GlClear),
            22 => Some(Self::GlViewport),
            23 => Some(Self::GlEnable),
            24 => Some(Self::GlDisable),
            25 => Some(Self::EglQuerySurface),
            26 => Some(Self::GlBlendFunc),
            27 => Some(Self::GlDepthFunc),
            28 => Some(Self::GlCullFace),
            29 => Some(Self::GlFrontFace),

            30 => Some(Self::GlCreateShader),
            31 => Some(Self::GlShaderSource),
            32 => Some(Self::GlCompileShader),
            33 => Some(Self::GlGetShaderiv),
            34 => Some(Self::GlCreateProgram),
            35 => Some(Self::GlAttachShader),
            36 => Some(Self::GlLinkProgram),
            37 => Some(Self::GlGetProgramiv),
            38 => Some(Self::GlUseProgram),
            39 => Some(Self::GlDeleteShader),

            40 => Some(Self::GlGenBuffers),
            41 => Some(Self::GlBindBuffer),
            42 => Some(Self::GlBufferData),
            43 => Some(Self::GlEnableVertexAttribArray),
            44 => Some(Self::GlVertexAttribPointer),
            45 => Some(Self::GlDrawArrays),
            46 => Some(Self::GlDrawElements),
            47 => Some(Self::GlDeleteBuffers),
            48 => Some(Self::GlDisableVertexAttribArray),
            49 => Some(Self::GlDeleteProgram),

            50 => Some(Self::GlGenTextures),
            51 => Some(Self::GlBindTexture),
            52 => Some(Self::GlTexImage2D),
            53 => Some(Self::GlTexParameteri),
            54 => Some(Self::GlActiveTexture),
            55 => Some(Self::GlGenFramebuffers),
            56 => Some(Self::GlBindFramebuffer),
            57 => Some(Self::GlFramebufferTexture2D),
            58 => Some(Self::GlCheckFramebufferStatus),
            59 => Some(Self::GlDeleteTextures),

            60 => Some(Self::GlGetString),
            61 => Some(Self::GlGetUniformLocation),
            62 => Some(Self::GlUniform1i),
            63 => Some(Self::GlUniform4f),
            64 => Some(Self::GlGetError),
            65 => Some(Self::GlGetShaderInfoLog),
            66 => Some(Self::GlGetProgramInfoLog),
            67 => Some(Self::GlGetAttribLocation),
            68 => Some(Self::GlUniform1f),
            69 => Some(Self::GlUniform2f),

            70 => Some(Self::EglCreateSyncKHR),
            71 => Some(Self::EglClientWaitSyncKHR),
            72 => Some(Self::EglDestroySyncKHR),
            73 => Some(Self::EglGetSyncAttribKHR),
            74 => Some(Self::EglWaitSyncKHR),
            75 => Some(Self::GlUniform3f),
            76 => Some(Self::GlUniformMatrix4fv),
            77 => Some(Self::GlClearDepthf),
            78 => Some(Self::GlDepthMask),
            79 => Some(Self::GlColorMask),

            80 => Some(Self::GlMatrixMode),
            81 => Some(Self::GlLoadIdentity),
            82 => Some(Self::GlLoadMatrixf),
            83 => Some(Self::GlPushMatrix),
            84 => Some(Self::GlPopMatrix),
            85 => Some(Self::GlOrthof),
            86 => Some(Self::GlFrustumf),
            87 => Some(Self::GlTranslatef),
            88 => Some(Self::GlScalef),
            89 => Some(Self::GlRotatef),
            90 => Some(Self::GlEnableClientState),
            91 => Some(Self::GlDisableClientState),
            92 => Some(Self::GlVertexPointer),
            93 => Some(Self::GlColorPointer),
            94 => Some(Self::GlTexCoordPointer),
            95 => Some(Self::GlNormalPointer),
            96 => Some(Self::GlAlphaFunc),
            97 => Some(Self::GlColor4f),
            98 => Some(Self::GlColor4ub),
            99 => Some(Self::GlClientActiveTexture),
            100 => Some(Self::GlShadeModel),
            101 => Some(Self::GlTexEnvf),
            102 => Some(Self::GlTexEnvi),
            103 => Some(Self::GlLightf),
            104 => Some(Self::GlLightfv),
            105 => Some(Self::GlMaterialf),
            106 => Some(Self::GlMaterialfv),
            107 => Some(Self::GlFogf),
            108 => Some(Self::GlFogfv),
            109 => Some(Self::GlUniform2fv),
            110 => Some(Self::GlUniform3fv),
            111 => Some(Self::GlUniform4fv),
            112 => Some(Self::GlDeleteFramebuffers),
            113 => Some(Self::GlScissor),
            114 => Some(Self::GlGetIntegerv),
            115 => Some(Self::GlPixelStorei),

            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct DrawCallRecord {
    pub mode: u32,
    pub first: i32,
    pub count: i32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SurfaceKind {
    Window,
    Pbuffer,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EglSurfaceState {
    pub surface_id: u32,
    pub kind: SurfaceKind,
    pub native_window: u32,
    pub width: u32,
    pub height: u32,
    pub texture_format: u32,
    pub texture_target: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TextureState {
    pub id: u32,
    pub target: u32,
    pub width: u32,
    pub height: u32,
    pub format: u32,
    pub min_filter: u32,
    pub mag_filter: u32,
    pub wrap_s: u32,
    pub wrap_t: u32,
    pub data: Option<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BufferState {
    pub id: u32,
    pub target: u32,
    pub size: usize,
    pub usage: u32,
    pub data: Option<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncFenceState {
    pub sync_id: u32,
    pub sync_type: u32,
    pub status: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShareGroup {
    pub group_id: u32,
    pub textures: HashMap<u32, TextureState>,
    pub buffers: HashMap<u32, BufferState>,
    pub sync_fences: HashMap<u32, SyncFenceState>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EglContextState {
    pub context_id: u32,
    pub share_group_id: u32,
    pub client_version: u32,
    pub bound_texture_2d: u32,
    pub bound_array_buffer: u32,
    pub bound_element_array_buffer: u32,
    pub bound_framebuffer: u32,
    pub active_texture_unit: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ThreadEglBinding {
    pub context_id: u32,
    pub draw_surface: u32,
    pub read_surface: u32,
}

/// Provides EGL & OpenGL ES 2.0 / 3.0 Passthrough Stubs for 32-bit guest applications
pub struct GlesBridge {
    pub stub_base: GuestAddr,
    pub symbol_table: HashMap<String, GuestAddr>,
    pub string_heap: GuestAddr,

    // Execution statistics & state
    pub draw_calls: Vec<DrawCallRecord>,
    pub total_draw_calls: u64,
    pub clear_color: [f32; 4],
    pub viewport: [i32; 4],
    pub next_resource_id: u32,
    pub active_program: u32,
    pub swap_count: u64,

    // EGL Hardware Surface & Context Binding
    pub egl_surfaces: HashMap<u32, EglSurfaceState>,
    pub egl_contexts: HashMap<u32, EglContextState>,
    pub share_groups: HashMap<u32, ShareGroup>,
    pub thread_bindings: HashMap<u32, ThreadEglBinding>,
    pub sync_fences: HashMap<u32, SyncFenceState>,
    pub next_share_group_id: u32,
    pub last_egl_error: u32,

    pub active_draw_surface: u32,
    pub active_read_surface: u32,
    pub active_context: u32,
    pub bound_native_window: u32,

    // GLES 1.1 Fixed-Function Pipeline state
    pub matrix_mode: u32,
    pub client_states: u32,
    pub client_active_texture: u32,

    // Hardware Android host bridge & 64-bit handle translation
    pub host: HostBridge,
    pub host_window_ptr: usize,
    #[cfg_attr(not(target_os = "android"), allow(dead_code))]
    host_egl_handles: HashMap<u32, u64>,
    #[cfg_attr(not(target_os = "android"), allow(dead_code))]
    next_egl_handle: u32,
    #[cfg_attr(not(target_os = "android"), allow(dead_code))]
    host_gl_strings: HashMap<u32, u32>,
    #[cfg_attr(not(target_os = "android"), allow(dead_code))]
    host_egl_strings: HashMap<u32, u32>,
    fallback_array_buffer: u32,
    fallback_element_buffer: u32,
}

impl GlesBridge {
    pub fn new(stub_base: GuestAddr, string_heap: GuestAddr) -> Self {
        let mut bridge = Self {
            stub_base,
            symbol_table: HashMap::new(),
            string_heap,
            draw_calls: Vec::with_capacity(64),
            total_draw_calls: 0,
            clear_color: [0.0; 4],
            viewport: [0; 4],
            next_resource_id: 1,
            active_program: 0,
            swap_count: 0,
            egl_surfaces: HashMap::new(),
            egl_contexts: HashMap::new(),
            share_groups: HashMap::new(),
            thread_bindings: HashMap::new(),
            sync_fences: HashMap::new(),
            next_share_group_id: 1,
            last_egl_error: EGL_SUCCESS,
            active_draw_surface: 0,
            active_read_surface: 0,
            active_context: 0,
            bound_native_window: 0,
            matrix_mode: 0x1700, // GL_MODELVIEW
            client_states: 0,
            client_active_texture: 0x84C0, // GL_TEXTURE0
            host: HostBridge::new(),
            host_window_ptr: 0,
            host_egl_handles: HashMap::new(),
            next_egl_handle: 0x1001,
            host_gl_strings: HashMap::new(),
            host_egl_strings: HashMap::new(),
            fallback_array_buffer: 0,
            fallback_element_buffer: 0,
        };

        bridge.register_known_symbols();
        bridge
    }

    pub fn resolve_host_symbol(&mut self, name: &str) -> Option<RawFnPtr> {
        self.host.resolve(name)
    }

    #[cfg_attr(not(target_os = "android"), allow(dead_code))]
    fn register_host_egl_handle(&mut self, host_val: usize) -> u32 {
        if host_val == 0 {
            return 0;
        }
        let host_u64 = host_val as u64;
        for (&guest_id, &mapped) in &self.host_egl_handles {
            if mapped == host_u64 {
                return guest_id;
            }
        }
        let id = self.next_egl_handle;
        self.next_egl_handle = self.next_egl_handle.wrapping_add(1).max(0x1001);
        self.host_egl_handles.insert(id, host_u64);
        id
    }

    #[cfg_attr(not(target_os = "android"), allow(dead_code))]
    fn resolve_host_egl_handle(&self, guest_id: u32) -> usize {
        if guest_id == 0 {
            return 0;
        }
        self.host_egl_handles
            .get(&guest_id)
            .copied()
            .unwrap_or(guest_id as u64) as usize
    }

    #[cfg_attr(not(target_os = "android"), allow(dead_code))]
    fn read_egl_attribs(&self, mem: &impl Memory, attrib_ptr: GuestAddr) -> Result<Vec<i32>, MemoryError> {
        let mut attribs = Vec::new();
        if attrib_ptr.as_u32() == 0 {
            attribs.push(EGL_NONE as i32);
            return Ok(attribs);
        }
        let mut cur = attrib_ptr;
        for _ in 0..64 {
            let key = mem.read_u32(cur)?;
            attribs.push(key as i32);
            if key == EGL_NONE {
                return Ok(attribs);
            }
            let val = mem.read_u32(cur.add(4))?;
            attribs.push(val as i32);
            cur = cur.add(8);
        }
        attribs.push(EGL_NONE as i32);
        Ok(attribs)
    }

    fn read_guest_cstring(&self, mem: &impl Memory, ptr: GuestAddr) -> Result<String, MemoryError> {
        if ptr.as_u32() == 0 {
            return Ok(String::new());
        }
        let mut bytes = Vec::new();
        let mut cur = ptr;
        for _ in 0..4096 {
            let b = mem.read_u8(cur)?;
            if b == 0 {
                break;
            }
            bytes.push(b);
            cur = cur.add(1);
        }
        Ok(String::from_utf8_lossy(&bytes).into_owned())
    }

    fn alloc_guest_string(&mut self, mem: &mut impl Memory, bytes_with_nul: &[u8]) -> Result<u32, MemoryError> {
        let addr = self.string_heap;
        mem.write_bytes(addr, bytes_with_nul)?;
        let len = if bytes_with_nul.ends_with(&[0]) {
            bytes_with_nul.len() as u32
        } else {
            mem.write_u8(addr.add(bytes_with_nul.len() as u32), 0)?;
            bytes_with_nul.len() as u32 + 1
        };
        self.string_heap = addr.add((len + 3) & !3);
        Ok(addr.as_u32())
    }

    fn record_bind_buffer(&mut self, cpu: &walzer32_core::CpuState, target: u32, buffer: u32) {
        if target == 0x8892 {
            self.fallback_array_buffer = buffer;
        } else if target == 0x8893 {
            self.fallback_element_buffer = buffer;
        }
        let ctx_id = self.current_context_id(cpu);
        if let Some(ctx) = self.egl_contexts.get_mut(&ctx_id) {
            if target == 0x8892 {
                ctx.bound_array_buffer = buffer;
            } else if target == 0x8893 {
                ctx.bound_element_array_buffer = buffer;
            }
        }
    }

    fn current_bound_buffer(&self, cpu: &walzer32_core::CpuState, target: u32) -> u32 {
        let ctx_id = self.current_context_id(cpu);
        if let Some(ctx) = self.egl_contexts.get(&ctx_id) {
            if target == 0x8892 {
                return ctx.bound_array_buffer;
            } else if target == 0x8893 {
                return ctx.bound_element_array_buffer;
            }
        }
        if target == 0x8892 {
            self.fallback_array_buffer
        } else if target == 0x8893 {
            self.fallback_element_buffer
        } else {
            0
        }
    }

    fn register_known_symbols(&mut self) {
        let symbols = [
            ("eglGetDisplay", GlesFuncId::EglGetDisplay),
            ("eglInitialize", GlesFuncId::EglInitialize),
            ("eglChooseConfig", GlesFuncId::EglChooseConfig),
            ("eglCreateWindowSurface", GlesFuncId::EglCreateWindowSurface),
            ("eglCreateContext", GlesFuncId::EglCreateContext),
            ("eglMakeCurrent", GlesFuncId::EglMakeCurrent),
            ("eglSwapBuffers", GlesFuncId::EglSwapBuffers),
            ("eglGetError", GlesFuncId::EglGetError),
            ("eglTerminate", GlesFuncId::EglTerminate),
            ("eglQueryString", GlesFuncId::EglQueryString),
            ("eglCreatePbufferSurface", GlesFuncId::EglCreatePbufferSurface),
            ("eglDestroySurface", GlesFuncId::EglDestroySurface),
            ("eglDestroyContext", GlesFuncId::EglDestroyContext),
            ("eglGetCurrentContext", GlesFuncId::EglGetCurrentContext),
            ("eglGetCurrentSurface", GlesFuncId::EglGetCurrentSurface),
            ("eglGetCurrentDisplay", GlesFuncId::EglGetCurrentDisplay),
            ("eglReleaseThread", GlesFuncId::EglReleaseThread),
            ("eglGetProcAddress", GlesFuncId::EglGetProcAddress),
            ("eglGetConfigAttrib", GlesFuncId::EglGetConfigAttrib),
            ("eglQuerySurface", GlesFuncId::EglQuerySurface),
            ("eglCreateSyncKHR", GlesFuncId::EglCreateSyncKHR),
            ("eglClientWaitSyncKHR", GlesFuncId::EglClientWaitSyncKHR),
            ("eglDestroySyncKHR", GlesFuncId::EglDestroySyncKHR),
            ("eglGetSyncAttribKHR", GlesFuncId::EglGetSyncAttribKHR),
            ("eglWaitSyncKHR", GlesFuncId::EglWaitSyncKHR),
            ("eglCreateSync", GlesFuncId::EglCreateSyncKHR),
            ("eglClientWaitSync", GlesFuncId::EglClientWaitSyncKHR),
            ("eglDestroySync", GlesFuncId::EglDestroySyncKHR),

            // GLES 1.1 Fixed-Function symbols
            ("glMatrixMode", GlesFuncId::GlMatrixMode),
            ("glLoadIdentity", GlesFuncId::GlLoadIdentity),
            ("glLoadMatrixf", GlesFuncId::GlLoadMatrixf),
            ("glPushMatrix", GlesFuncId::GlPushMatrix),
            ("glPopMatrix", GlesFuncId::GlPopMatrix),
            ("glOrthof", GlesFuncId::GlOrthof),
            ("glFrustumf", GlesFuncId::GlFrustumf),
            ("glTranslatef", GlesFuncId::GlTranslatef),
            ("glScalef", GlesFuncId::GlScalef),
            ("glRotatef", GlesFuncId::GlRotatef),
            ("glEnableClientState", GlesFuncId::GlEnableClientState),
            ("glDisableClientState", GlesFuncId::GlDisableClientState),
            ("glVertexPointer", GlesFuncId::GlVertexPointer),
            ("glColorPointer", GlesFuncId::GlColorPointer),
            ("glTexCoordPointer", GlesFuncId::GlTexCoordPointer),
            ("glNormalPointer", GlesFuncId::GlNormalPointer),
            ("glAlphaFunc", GlesFuncId::GlAlphaFunc),
            ("glColor4f", GlesFuncId::GlColor4f),
            ("glColor4ub", GlesFuncId::GlColor4ub),
            ("glClientActiveTexture", GlesFuncId::GlClientActiveTexture),
            ("glShadeModel", GlesFuncId::GlShadeModel),
            ("glTexEnvf", GlesFuncId::GlTexEnvf),
            ("glTexEnvi", GlesFuncId::GlTexEnvi),
            ("glLightf", GlesFuncId::GlLightf),
            ("glLightfv", GlesFuncId::GlLightfv),
            ("glMaterialf", GlesFuncId::GlMaterialf),
            ("glMaterialfv", GlesFuncId::GlMaterialfv),
            ("glFogf", GlesFuncId::GlFogf),
            ("glFogfv", GlesFuncId::GlFogfv),
            ("glClearColor", GlesFuncId::GlClearColor),
            ("glClearDepthf", GlesFuncId::GlClearDepthf),
            ("glClear", GlesFuncId::GlClear),
            ("glViewport", GlesFuncId::GlViewport),
            ("glScissor", GlesFuncId::GlScissor),
            ("glEnable", GlesFuncId::GlEnable),
            ("glDisable", GlesFuncId::GlDisable),
            ("glBlendFunc", GlesFuncId::GlBlendFunc),
            ("glDepthFunc", GlesFuncId::GlDepthFunc),
            ("glDepthMask", GlesFuncId::GlDepthMask),
            ("glColorMask", GlesFuncId::GlColorMask),
            ("glCullFace", GlesFuncId::GlCullFace),
            ("glFrontFace", GlesFuncId::GlFrontFace),
            ("glCreateShader", GlesFuncId::GlCreateShader),
            ("glDeleteShader", GlesFuncId::GlDeleteShader),
            ("glShaderSource", GlesFuncId::GlShaderSource),
            ("glCompileShader", GlesFuncId::GlCompileShader),
            ("glGetShaderiv", GlesFuncId::GlGetShaderiv),
            ("glGetShaderInfoLog", GlesFuncId::GlGetShaderInfoLog),
            ("glCreateProgram", GlesFuncId::GlCreateProgram),
            ("glDeleteProgram", GlesFuncId::GlDeleteProgram),
            ("glAttachShader", GlesFuncId::GlAttachShader),
            ("glLinkProgram", GlesFuncId::GlLinkProgram),
            ("glGetProgramiv", GlesFuncId::GlGetProgramiv),
            ("glGetProgramInfoLog", GlesFuncId::GlGetProgramInfoLog),
            ("glUseProgram", GlesFuncId::GlUseProgram),
            ("glGenBuffers", GlesFuncId::GlGenBuffers),
            ("glDeleteBuffers", GlesFuncId::GlDeleteBuffers),
            ("glBindBuffer", GlesFuncId::GlBindBuffer),
            ("glBufferData", GlesFuncId::GlBufferData),
            ("glEnableVertexAttribArray", GlesFuncId::GlEnableVertexAttribArray),
            ("glDisableVertexAttribArray", GlesFuncId::GlDisableVertexAttribArray),
            ("glVertexAttribPointer", GlesFuncId::GlVertexAttribPointer),
            ("glDrawArrays", GlesFuncId::GlDrawArrays),
            ("glDrawElements", GlesFuncId::GlDrawElements),
            ("glGenTextures", GlesFuncId::GlGenTextures),
            ("glDeleteTextures", GlesFuncId::GlDeleteTextures),
            ("glBindTexture", GlesFuncId::GlBindTexture),
            ("glTexImage2D", GlesFuncId::GlTexImage2D),
            ("glTexParameteri", GlesFuncId::GlTexParameteri),
            ("glPixelStorei", GlesFuncId::GlPixelStorei),
            ("glActiveTexture", GlesFuncId::GlActiveTexture),
            ("glGenFramebuffers", GlesFuncId::GlGenFramebuffers),
            ("glDeleteFramebuffers", GlesFuncId::GlDeleteFramebuffers),
            ("glBindFramebuffer", GlesFuncId::GlBindFramebuffer),
            ("glFramebufferTexture2D", GlesFuncId::GlFramebufferTexture2D),
            ("glCheckFramebufferStatus", GlesFuncId::GlCheckFramebufferStatus),
            ("glGetString", GlesFuncId::GlGetString),
            ("glGetIntegerv", GlesFuncId::GlGetIntegerv),
            ("glGetUniformLocation", GlesFuncId::GlGetUniformLocation),
            ("glGetAttribLocation", GlesFuncId::GlGetAttribLocation),
            ("glUniform1i", GlesFuncId::GlUniform1i),
            ("glUniform1f", GlesFuncId::GlUniform1f),
            ("glUniform2f", GlesFuncId::GlUniform2f),
            ("glUniform3f", GlesFuncId::GlUniform3f),
            ("glUniform4f", GlesFuncId::GlUniform4f),
            ("glUniform2fv", GlesFuncId::GlUniform2fv),
            ("glUniform3fv", GlesFuncId::GlUniform3fv),
            ("glUniform4fv", GlesFuncId::GlUniform4fv),
            ("glUniformMatrix4fv", GlesFuncId::GlUniformMatrix4fv),
            ("glGetError", GlesFuncId::GlGetError),
        ];

        for (name, id) in symbols {
            let addr = self.stub_base.add((id as u32) * 8);
            self.symbol_table.insert(name.to_string(), addr);
        }
    }

    /// Installs stub code into guest memory
    pub fn install_stubs(&self, mem: &mut impl Memory) -> Result<(), MemoryError> {
        let all_ids = [
            GlesFuncId::EglGetDisplay,
            GlesFuncId::EglInitialize,
            GlesFuncId::EglChooseConfig,
            GlesFuncId::EglCreateWindowSurface,
            GlesFuncId::EglCreateContext,
            GlesFuncId::EglMakeCurrent,
            GlesFuncId::EglSwapBuffers,
            GlesFuncId::EglGetError,
            GlesFuncId::EglTerminate,
            GlesFuncId::EglQueryString,
            GlesFuncId::EglCreatePbufferSurface,
            GlesFuncId::EglDestroySurface,
            GlesFuncId::EglDestroyContext,
            GlesFuncId::EglGetCurrentContext,
            GlesFuncId::EglGetCurrentSurface,
            GlesFuncId::EglGetCurrentDisplay,
            GlesFuncId::EglReleaseThread,
            GlesFuncId::EglGetProcAddress,
            GlesFuncId::EglGetConfigAttrib,
            GlesFuncId::EglQuerySurface,
            GlesFuncId::GlClearColor,
            GlesFuncId::GlClearDepthf,
            GlesFuncId::GlClear,
            GlesFuncId::GlViewport,
            GlesFuncId::GlScissor,
            GlesFuncId::GlEnable,
            GlesFuncId::GlDisable,
            GlesFuncId::GlBlendFunc,
            GlesFuncId::GlDepthFunc,
            GlesFuncId::GlDepthMask,
            GlesFuncId::GlColorMask,
            GlesFuncId::GlCullFace,
            GlesFuncId::GlFrontFace,
            GlesFuncId::GlCreateShader,
            GlesFuncId::GlDeleteShader,
            GlesFuncId::GlShaderSource,
            GlesFuncId::GlCompileShader,
            GlesFuncId::GlGetShaderiv,
            GlesFuncId::GlGetShaderInfoLog,
            GlesFuncId::GlCreateProgram,
            GlesFuncId::GlDeleteProgram,
            GlesFuncId::GlAttachShader,
            GlesFuncId::GlLinkProgram,
            GlesFuncId::GlGetProgramiv,
            GlesFuncId::GlGetProgramInfoLog,
            GlesFuncId::GlUseProgram,
            GlesFuncId::GlGenBuffers,
            GlesFuncId::GlDeleteBuffers,
            GlesFuncId::GlBindBuffer,
            GlesFuncId::GlBufferData,
            GlesFuncId::GlEnableVertexAttribArray,
            GlesFuncId::GlDisableVertexAttribArray,
            GlesFuncId::GlVertexAttribPointer,
            GlesFuncId::GlDrawArrays,
            GlesFuncId::GlDrawElements,
            GlesFuncId::GlGenTextures,
            GlesFuncId::GlDeleteTextures,
            GlesFuncId::GlBindTexture,
            GlesFuncId::GlTexImage2D,
            GlesFuncId::GlTexParameteri,
            GlesFuncId::GlPixelStorei,
            GlesFuncId::GlActiveTexture,
            GlesFuncId::GlGenFramebuffers,
            GlesFuncId::GlDeleteFramebuffers,
            GlesFuncId::GlBindFramebuffer,
            GlesFuncId::GlFramebufferTexture2D,
            GlesFuncId::GlCheckFramebufferStatus,
            GlesFuncId::GlGetString,
            GlesFuncId::GlGetIntegerv,
            GlesFuncId::GlGetUniformLocation,
            GlesFuncId::GlGetAttribLocation,
            GlesFuncId::GlUniform1i,
            GlesFuncId::GlUniform1f,
            GlesFuncId::GlUniform2f,
            GlesFuncId::GlUniform3f,
            GlesFuncId::GlUniform4f,
            GlesFuncId::GlUniform2fv,
            GlesFuncId::GlUniform3fv,
            GlesFuncId::GlUniform4fv,
            GlesFuncId::GlUniformMatrix4fv,
            GlesFuncId::GlGetError,
            GlesFuncId::EglCreateSyncKHR,
            GlesFuncId::EglClientWaitSyncKHR,
            GlesFuncId::EglDestroySyncKHR,
            GlesFuncId::EglGetSyncAttribKHR,
            GlesFuncId::EglWaitSyncKHR,
            GlesFuncId::GlMatrixMode,
            GlesFuncId::GlLoadIdentity,
            GlesFuncId::GlLoadMatrixf,
            GlesFuncId::GlPushMatrix,
            GlesFuncId::GlPopMatrix,
            GlesFuncId::GlOrthof,
            GlesFuncId::GlFrustumf,
            GlesFuncId::GlTranslatef,
            GlesFuncId::GlScalef,
            GlesFuncId::GlRotatef,
            GlesFuncId::GlEnableClientState,
            GlesFuncId::GlDisableClientState,
            GlesFuncId::GlVertexPointer,
            GlesFuncId::GlColorPointer,
            GlesFuncId::GlTexCoordPointer,
            GlesFuncId::GlNormalPointer,
            GlesFuncId::GlAlphaFunc,
            GlesFuncId::GlColor4f,
            GlesFuncId::GlColor4ub,
            GlesFuncId::GlClientActiveTexture,
            GlesFuncId::GlShadeModel,
            GlesFuncId::GlTexEnvf,
            GlesFuncId::GlTexEnvi,
            GlesFuncId::GlLightf,
            GlesFuncId::GlLightfv,
            GlesFuncId::GlMaterialf,
            GlesFuncId::GlMaterialfv,
            GlesFuncId::GlFogf,
            GlesFuncId::GlFogfv,
        ];

        for &id in &all_ids {
            let addr = self.stub_base.add((id as u32) * 8);
            let svc_code = 0xEF00_0000 | (GLES_SVC_MAGIC | (id as u32));
            let bx_lr = 0xE12F_FF1E;

            mem.write_u32(addr, svc_code)?;
            mem.write_u32(addr.add(4), bx_lr)?;
        }
        Ok(())
    }

    /// Returns the active thread ID based on guest CP15 TLS register
    pub fn current_thread_id(&self, cpu: &walzer32_core::CpuState) -> u32 {
        let tls = cpu.tls_ptr;
        if tls != 0 {
            tls
        } else {
            1 // Default main thread ID
        }
    }

    /// Returns the context ID bound to the calling thread
    pub fn current_context_id(&self, cpu: &walzer32_core::CpuState) -> u32 {
        let tid = self.current_thread_id(cpu);
        self.thread_bindings
            .get(&tid)
            .map(|b| b.context_id)
            .unwrap_or(self.active_context)
    }

    /// Returns the share group ID of the active context
    pub fn current_share_group_id(&self, cpu: &walzer32_core::CpuState) -> u32 {
        let ctx_id = self.current_context_id(cpu);
        if let Some(ctx) = self.egl_contexts.get(&ctx_id) {
            ctx.share_group_id
        } else {
            1
        }
    }

    /// Retrieves a shared texture by ID from a given share group
    pub fn get_shared_texture(&self, group_id: u32, texture_id: u32) -> Option<&TextureState> {
        self.share_groups.get(&group_id).and_then(|g| g.textures.get(&texture_id))
    }

    /// Retrieves a shared texture by ID for a specific EGLContext
    pub fn get_shared_texture_for_context(&self, context_id: u32, texture_id: u32) -> Option<&TextureState> {
        let ctx = self.egl_contexts.get(&context_id)?;
        self.get_shared_texture(ctx.share_group_id, texture_id)
    }

    /// Handles an incoming OpenGL ES or EGL SVC call
    pub fn handle_svc(
        &mut self,
        svc_imm: u32,
        cpu: &mut walzer32_core::CpuState,
        mem: &mut impl Memory,
    ) -> Result<bool, MemoryError> {
        if (svc_imm & 0xFF0000) != GLES_SVC_MAGIC {
            return Ok(false);
        }

        let func_id_raw = svc_imm & 0xFFFF;
        let func_id = match GlesFuncId::from_u32(func_id_raw) {
            Some(id) => id,
            None => return Ok(false),
        };

        #[cfg(target_os = "android")]
        if self.try_handle_android(func_id, cpu, mem)? {
            return Ok(true);
        }

        match func_id {
            // --- EGL Core Functions ---
            GlesFuncId::EglGetDisplay => {
                cpu.set_reg(Reg::R0, 0x1000); // Valid non-zero EGLDisplay handle
            }
            GlesFuncId::EglInitialize => {
                let major_ptr = GuestAddr::new(cpu.reg(Reg::R1));
                let minor_ptr = GuestAddr::new(cpu.reg(Reg::R2));
                if major_ptr.as_u32() != 0 {
                    mem.write_u32(major_ptr, 1)?; // EGL 1.5
                }
                if minor_ptr.as_u32() != 0 {
                    mem.write_u32(minor_ptr, 5)?;
                }
                cpu.set_reg(Reg::R0, EGL_TRUE);
            }
            GlesFuncId::EglChooseConfig => {
                let configs_ptr = GuestAddr::new(cpu.reg(Reg::R2));
                // ARM32 AAPCS: Arguments 1..4 in R0..R3; 5th argument (num_config) is on stack [SP, #0]
                let sp = GuestAddr::new(cpu.sp());
                let num_config_ptr = GuestAddr::new(mem.read_u32(sp).unwrap_or(0));
                if configs_ptr.as_u32() != 0 {
                    mem.write_u32(configs_ptr, 0x2001)?; // Valid EGLConfig handle
                }
                if num_config_ptr.as_u32() != 0 {
                    mem.write_u32(num_config_ptr, 1)?;
                }
                cpu.set_reg(Reg::R0, EGL_TRUE);
            }
            GlesFuncId::EglCreateWindowSurface => {
                let native_window = cpu.reg(Reg::R2);
                let surface_id = self.next_resource_id;
                self.next_resource_id += 1;
                self.bound_native_window = native_window;
                self.egl_surfaces.insert(
                    surface_id,
                    EglSurfaceState {
                        surface_id,
                        kind: SurfaceKind::Window,
                        native_window,
                        width: 1920,
                        height: 1080,
                        texture_format: 0,
                        texture_target: 0,
                    },
                );
                cpu.set_reg(Reg::R0, surface_id);
            }
            GlesFuncId::EglCreatePbufferSurface => {
                let attrib_ptr = GuestAddr::new(cpu.reg(Reg::R2));
                let mut width = 256;
                let mut height = 256;
                let mut texture_format = 0;
                let mut texture_target = 0;

                if attrib_ptr.as_u32() != 0 {
                    let mut cur = attrib_ptr;
                    loop {
                        let attr = mem.read_u32(cur)?;
                        if attr == EGL_NONE {
                            break;
                        }
                        let val = mem.read_u32(cur.add(4))?;
                        match attr {
                            EGL_WIDTH => width = val,
                            EGL_HEIGHT => height = val,
                            EGL_TEXTURE_FORMAT => texture_format = val,
                            EGL_TEXTURE_TARGET => texture_target = val,
                            _ => {}
                        }
                        cur = cur.add(8);
                    }
                }

                let surface_id = self.next_resource_id;
                self.next_resource_id += 1;
                self.egl_surfaces.insert(
                    surface_id,
                    EglSurfaceState {
                        surface_id,
                        kind: SurfaceKind::Pbuffer,
                        native_window: 0,
                        width,
                        height,
                        texture_format,
                        texture_target,
                    },
                );
                cpu.set_reg(Reg::R0, surface_id);
            }
            GlesFuncId::EglCreateContext => {
                let share_context = cpu.reg(Reg::R2);
                let attrib_ptr = GuestAddr::new(cpu.reg(Reg::R3));

                let mut client_version = 3;
                if attrib_ptr.as_u32() != 0 {
                    let mut cur = attrib_ptr;
                    loop {
                        let attr = mem.read_u32(cur)?;
                        if attr == EGL_NONE {
                            break;
                        }
                        let val = mem.read_u32(cur.add(4))?;
                        if attr == EGL_CONTEXT_CLIENT_VERSION {
                            client_version = val;
                        }
                        cur = cur.add(8);
                    }
                }

                // If share_context is non-null and exists, join its share group; otherwise create a new one
                let share_group_id = if share_context != 0 {
                    if let Some(shared) = self.egl_contexts.get(&share_context) {
                        shared.share_group_id
                    } else {
                        let gid = self.next_share_group_id;
                        self.next_share_group_id += 1;
                        self.share_groups.insert(
                            gid,
                            ShareGroup {
                                group_id: gid,
                                textures: HashMap::new(),
                                buffers: HashMap::new(),
                                sync_fences: HashMap::new(),
                            },
                        );
                        gid
                    }
                } else {
                    let gid = self.next_share_group_id;
                    self.next_share_group_id += 1;
                    self.share_groups.insert(
                        gid,
                        ShareGroup {
                            group_id: gid,
                            textures: HashMap::new(),
                            buffers: HashMap::new(),
                            sync_fences: HashMap::new(),
                        },
                    );
                    gid
                };

                let context_id = self.next_resource_id;
                self.next_resource_id += 1;

                self.egl_contexts.insert(
                    context_id,
                    EglContextState {
                        context_id,
                        share_group_id,
                        client_version,
                        bound_texture_2d: 0,
                        bound_array_buffer: 0,
                        bound_element_array_buffer: 0,
                        bound_framebuffer: 0,
                        active_texture_unit: 0,
                    },
                );
                cpu.set_reg(Reg::R0, context_id);
            }
            GlesFuncId::EglMakeCurrent => {
                let tid = self.current_thread_id(cpu);
                let draw = cpu.reg(Reg::R1);
                let read = cpu.reg(Reg::R2);
                let ctx = cpu.reg(Reg::R3);

                if ctx == 0 && draw == 0 && read == 0 {
                    self.thread_bindings.remove(&tid);
                    self.active_context = 0;
                    self.active_draw_surface = 0;
                    self.active_read_surface = 0;
                } else {
                    self.thread_bindings.insert(
                        tid,
                        ThreadEglBinding {
                            context_id: ctx,
                            draw_surface: draw,
                            read_surface: read,
                        },
                    );
                    self.active_draw_surface = draw;
                    self.active_read_surface = read;
                    self.active_context = ctx;
                }
                cpu.set_reg(Reg::R0, EGL_TRUE);
            }
            GlesFuncId::EglGetCurrentContext => {
                let tid = self.current_thread_id(cpu);
                let ctx = self
                    .thread_bindings
                    .get(&tid)
                    .map(|b| b.context_id)
                    .unwrap_or(0);
                cpu.set_reg(Reg::R0, ctx);
            }
            GlesFuncId::EglGetCurrentSurface => {
                let which = cpu.reg(Reg::R0);
                let tid = self.current_thread_id(cpu);
                let surface = if which == EGL_READ {
                    self.thread_bindings
                        .get(&tid)
                        .map(|b| b.read_surface)
                        .unwrap_or(0)
                } else {
                    self.thread_bindings
                        .get(&tid)
                        .map(|b| b.draw_surface)
                        .unwrap_or(0)
                };
                cpu.set_reg(Reg::R0, surface);
            }
            GlesFuncId::EglGetCurrentDisplay => {
                cpu.set_reg(Reg::R0, 0x1000);
            }
            GlesFuncId::EglDestroySurface => {
                let surface = cpu.reg(Reg::R1);
                self.egl_surfaces.remove(&surface);
                cpu.set_reg(Reg::R0, EGL_TRUE);
            }
            GlesFuncId::EglDestroyContext => {
                let ctx = cpu.reg(Reg::R1);
                self.egl_contexts.remove(&ctx);
                cpu.set_reg(Reg::R0, EGL_TRUE);
            }
            GlesFuncId::EglReleaseThread => {
                let tid = self.current_thread_id(cpu);
                self.thread_bindings.remove(&tid);
                cpu.set_reg(Reg::R0, EGL_TRUE);
            }
            GlesFuncId::EglGetProcAddress => {
                let proc_ptr = GuestAddr::new(cpu.reg(Reg::R0));
                if proc_ptr.as_u32() == 0 {
                    cpu.set_reg(Reg::R0, 0);
                } else {
                    let name = self.read_guest_cstring(mem, proc_ptr)?;
                    let resolved = self.symbol_table.get(name.as_str()).copied().map(|a| a.as_u32()).unwrap_or(0);
                    cpu.set_reg(Reg::R0, resolved);
                }
            }
            GlesFuncId::EglGetConfigAttrib | GlesFuncId::EglQuerySurface => {
                let val_ptr = GuestAddr::new(cpu.reg(Reg::R3));
                if val_ptr.as_u32() != 0 {
                    mem.write_u32(val_ptr, 8)?;
                }
                cpu.set_reg(Reg::R0, EGL_TRUE);
            }
            GlesFuncId::EglSwapBuffers => {
                self.swap_count += 1;
                cpu.set_reg(Reg::R0, EGL_TRUE);
            }
            GlesFuncId::EglGetError => {
                let err = self.last_egl_error;
                self.last_egl_error = EGL_SUCCESS;
                cpu.set_reg(Reg::R0, err);
            }
            GlesFuncId::EglTerminate => {
                cpu.set_reg(Reg::R0, EGL_TRUE);
            }
            GlesFuncId::EglQueryString => {
                let name = cpu.reg(Reg::R1);
                let string_val = match name {
                    0x308D => "OpenGL_ES\0", // EGL_CLIENT_APIS
                    0x3053 => "Google DeepMind / Walzer32\0", // EGL_VENDOR
                    0x3054 => "1.5 Walzer32 Android EGL\0", // EGL_VERSION
                    0x3055 => "EGL_KHR_image_base EGL_KHR_gl_texture_2D_image EGL_KHR_fence_sync EGL_ANDROID_native_fence_sync\0",
                    _ => "Walzer32 EGL\0",
                };
                let addr = self.alloc_guest_string(mem, string_val.as_bytes())?;
                cpu.set_reg(Reg::R0, addr);
            }

            // --- EGL KHR Sync / Fences ---
            GlesFuncId::EglCreateSyncKHR => {
                let sync_type = cpu.reg(Reg::R1);
                let sync_id = self.next_resource_id;
                self.next_resource_id += 1;

                let fence = SyncFenceState {
                    sync_id,
                    sync_type,
                    status: EGL_SIGNALED_KHR,
                };
                self.sync_fences.insert(sync_id, fence.clone());

                let group_id = self.current_share_group_id(cpu);
                if let Some(group) = self.share_groups.get_mut(&group_id) {
                    group.sync_fences.insert(sync_id, fence);
                }
                cpu.set_reg(Reg::R0, sync_id);
            }
            GlesFuncId::EglClientWaitSyncKHR => {
                let sync_id = cpu.reg(Reg::R1);
                if self.sync_fences.contains_key(&sync_id) {
                    cpu.set_reg(Reg::R0, EGL_CONDITION_SATISFIED_KHR);
                } else {
                    self.last_egl_error = EGL_BAD_PARAMETER;
                    cpu.set_reg(Reg::R0, EGL_FALSE);
                }
            }
            GlesFuncId::EglDestroySyncKHR => {
                let sync_id = cpu.reg(Reg::R1);
                self.sync_fences.remove(&sync_id);
                let group_id = self.current_share_group_id(cpu);
                if let Some(group) = self.share_groups.get_mut(&group_id) {
                    group.sync_fences.remove(&sync_id);
                }
                cpu.set_reg(Reg::R0, EGL_TRUE);
            }
            GlesFuncId::EglGetSyncAttribKHR => {
                let sync_id = cpu.reg(Reg::R1);
                let attribute = cpu.reg(Reg::R2);
                let value_ptr = GuestAddr::new(cpu.reg(Reg::R3));

                if let Some(sync) = self.sync_fences.get(&sync_id) {
                    if attribute == EGL_SYNC_STATUS_KHR && value_ptr.as_u32() != 0 {
                        mem.write_u32(value_ptr, sync.status)?;
                    }
                    cpu.set_reg(Reg::R0, EGL_TRUE);
                } else {
                    self.last_egl_error = EGL_BAD_PARAMETER;
                    cpu.set_reg(Reg::R0, EGL_FALSE);
                }
            }
            GlesFuncId::EglWaitSyncKHR => {
                cpu.set_reg(Reg::R0, EGL_TRUE);
            }

            // --- GLES State ---
            GlesFuncId::GlClearColor => {
                let r = f32::from_bits(cpu.reg(Reg::R0));
                let g = f32::from_bits(cpu.reg(Reg::R1));
                let b = f32::from_bits(cpu.reg(Reg::R2));
                let a = f32::from_bits(cpu.reg(Reg::R3));
                self.clear_color = [r, g, b, a];
            }
            GlesFuncId::GlClear => {}
            GlesFuncId::GlViewport => {
                let x = cpu.reg(Reg::R0) as i32;
                let y = cpu.reg(Reg::R1) as i32;
                let w = cpu.reg(Reg::R2) as i32;
                let h = cpu.reg(Reg::R3) as i32;
                self.viewport = [x, y, w, h];
            }
            GlesFuncId::GlEnable | GlesFuncId::GlDisable => {}

            // --- GLES Shaders & Programs ---
            GlesFuncId::GlCreateShader | GlesFuncId::GlCreateProgram => {
                let id = self.next_resource_id;
                self.next_resource_id += 1;
                cpu.set_reg(Reg::R0, id);
            }
            GlesFuncId::GlGetShaderiv | GlesFuncId::GlGetProgramiv => {
                let params_ptr = GuestAddr::new(cpu.reg(Reg::R2));
                mem.write_u32(params_ptr, 1)?; // GL_TRUE
            }
            GlesFuncId::GlUseProgram => {
                self.active_program = cpu.reg(Reg::R0);
            }

            // --- GLES Buffers & Textures ---
            GlesFuncId::GlGenBuffers => {
                let n = cpu.reg(Reg::R0);
                let ptr = GuestAddr::new(cpu.reg(Reg::R1));
                let group_id = self.current_share_group_id(cpu);

                for i in 0..n {
                    let id = self.next_resource_id;
                    self.next_resource_id += 1;
                    mem.write_u32(ptr.add(i * 4), id)?;

                    if let Some(group) = self.share_groups.get_mut(&group_id) {
                        group.buffers.insert(
                            id,
                            BufferState {
                                id,
                                target: 0,
                                size: 0,
                                usage: 0,
                                data: None,
                            },
                        );
                    }
                }
            }
            GlesFuncId::GlBindBuffer => {
                let target = cpu.reg(Reg::R0);
                let buffer = cpu.reg(Reg::R1);
                self.record_bind_buffer(cpu, target, buffer);
            }
            GlesFuncId::GlBufferData => {
                let target = cpu.reg(Reg::R0);
                let size = cpu.reg(Reg::R1) as usize;
                let data_ptr = GuestAddr::new(cpu.reg(Reg::R2));
                let usage = cpu.reg(Reg::R3);

                let group_id = self.current_share_group_id(cpu);
                let buffer_id = self.current_bound_buffer(cpu, target);

                if buffer_id != 0 {
                    let mut data = None;
                    if data_ptr.as_u32() != 0 && size > 0 {
                        let mut buf = vec![0u8; size];
                        if mem.read_bytes(data_ptr, &mut buf).is_ok() {
                            data = Some(buf);
                        }
                    }

                    if let Some(group) = self.share_groups.get_mut(&group_id) {
                        group.buffers.insert(
                            buffer_id,
                            BufferState {
                                id: buffer_id,
                                target,
                                size,
                                usage,
                                data,
                            },
                        );
                    }
                }
            }
            GlesFuncId::GlGenTextures => {
                let n = cpu.reg(Reg::R0);
                let ptr = GuestAddr::new(cpu.reg(Reg::R1));
                let group_id = self.current_share_group_id(cpu);

                for i in 0..n {
                    let id = self.next_resource_id;
                    self.next_resource_id += 1;
                    mem.write_u32(ptr.add(i * 4), id)?;

                    if let Some(group) = self.share_groups.get_mut(&group_id) {
                        group.textures.insert(
                            id,
                            TextureState {
                                id,
                                target: GL_TEXTURE_2D,
                                width: 0,
                                height: 0,
                                format: GL_RGBA,
                                min_filter: GL_NEAREST,
                                mag_filter: GL_LINEAR,
                                wrap_s: GL_REPEAT,
                                wrap_t: GL_REPEAT,
                                data: None,
                            },
                        );
                    }
                }
            }
            GlesFuncId::GlBindTexture => {
                let target = cpu.reg(Reg::R0);
                let texture = cpu.reg(Reg::R1);
                let ctx_id = self.current_context_id(cpu);
                if let Some(ctx) = self.egl_contexts.get_mut(&ctx_id) {
                    ctx.bound_texture_2d = texture;
                }
                let group_id = self.current_share_group_id(cpu);
                if let Some(group) = self.share_groups.get_mut(&group_id) {
                    if let Some(tex) = group.textures.get_mut(&texture) {
                        tex.target = target;
                    }
                }
            }
            GlesFuncId::GlTexImage2D => {
                let target = cpu.reg(Reg::R0);
                let _level = cpu.reg(Reg::R1);
                let _internal_format = cpu.reg(Reg::R2);
                let width = cpu.reg(Reg::R3);

                let sp = GuestAddr::new(cpu.sp());
                let height = mem.read_u32(sp)?;
                let _border = mem.read_u32(sp.add(4))?;
                let format = mem.read_u32(sp.add(8))?;
                let _pixel_type = mem.read_u32(sp.add(12))?;
                let pixels_ptr = GuestAddr::new(mem.read_u32(sp.add(16))?);

                let ctx_id = self.current_context_id(cpu);
                let group_id = self.current_share_group_id(cpu);
                let tex_id = self
                    .egl_contexts
                    .get(&ctx_id)
                    .map(|c| c.bound_texture_2d)
                    .unwrap_or(0);

                if tex_id != 0 {
                    let bpp = if format == GL_RGB { 3 } else { 4 };
                    let byte_count = (width * height * bpp) as usize;
                    let mut data = None;
                    if pixels_ptr.as_u32() != 0 && byte_count > 0 {
                        let mut buf = vec![0u8; byte_count];
                        if mem.read_bytes(pixels_ptr, &mut buf).is_ok() {
                            data = Some(buf);
                        }
                    }

                    if let Some(group) = self.share_groups.get_mut(&group_id) {
                        if let Some(tex) = group.textures.get_mut(&tex_id) {
                            tex.target = target;
                            tex.width = width;
                            tex.height = height;
                            tex.format = format;
                            tex.data = data;
                        }
                    }
                }
            }
            GlesFuncId::GlTexParameteri => {
                let _target = cpu.reg(Reg::R0);
                let pname = cpu.reg(Reg::R1);
                let param = cpu.reg(Reg::R2);

                let ctx_id = self.current_context_id(cpu);
                let group_id = self.current_share_group_id(cpu);
                let tex_id = self
                    .egl_contexts
                    .get(&ctx_id)
                    .map(|c| c.bound_texture_2d)
                    .unwrap_or(0);

                if tex_id != 0 {
                    if let Some(group) = self.share_groups.get_mut(&group_id) {
                        if let Some(tex) = group.textures.get_mut(&tex_id) {
                            match pname {
                                GL_TEXTURE_MIN_FILTER => tex.min_filter = param,
                                GL_TEXTURE_MAG_FILTER => tex.mag_filter = param,
                                GL_TEXTURE_WRAP_S => tex.wrap_s = param,
                                GL_TEXTURE_WRAP_T => tex.wrap_t = param,
                                _ => {}
                            }
                        }
                    }
                }
            }
            GlesFuncId::GlActiveTexture => {
                let tex_unit = cpu.reg(Reg::R0);
                let ctx_id = self.current_context_id(cpu);
                if let Some(ctx) = self.egl_contexts.get_mut(&ctx_id) {
                    ctx.active_texture_unit = tex_unit.saturating_sub(0x84C0);
                }
            }
            GlesFuncId::GlGenFramebuffers => {
                let n = cpu.reg(Reg::R0);
                let ptr = GuestAddr::new(cpu.reg(Reg::R1));
                for i in 0..n {
                    let id = self.next_resource_id;
                    self.next_resource_id += 1;
                    mem.write_u32(ptr.add(i * 4), id)?;
                }
            }
            GlesFuncId::GlBindFramebuffer => {
                let _target = cpu.reg(Reg::R0);
                let fbo_id = cpu.reg(Reg::R1);
                let ctx_id = self.current_context_id(cpu);
                if let Some(ctx) = self.egl_contexts.get_mut(&ctx_id) {
                    ctx.bound_framebuffer = fbo_id;
                }
            }
            GlesFuncId::GlFramebufferTexture2D => {
                // Associates texture with currently bound framebuffer
            }
            GlesFuncId::GlCheckFramebufferStatus => {
                cpu.set_reg(Reg::R0, GL_FRAMEBUFFER_COMPLETE);
            }

            // --- GLES Drawing ---
            GlesFuncId::GlDrawArrays => {
                let mode = cpu.reg(Reg::R0);
                let first = cpu.reg(Reg::R1) as i32;
                let count = cpu.reg(Reg::R2) as i32;
                self.total_draw_calls += 1;
                if self.draw_calls.len() >= 64 {
                    self.draw_calls.remove(0);
                }
                self.draw_calls.push(DrawCallRecord { mode, first, count });
            }
            GlesFuncId::GlDrawElements => {
                let mode = cpu.reg(Reg::R0);
                let count = cpu.reg(Reg::R1) as i32;
                self.total_draw_calls += 1;
                if self.draw_calls.len() >= 64 {
                    self.draw_calls.remove(0);
                }
                self.draw_calls.push(DrawCallRecord { mode, first: 0, count });
            }

            // --- GLES Queries & Errors ---
            GlesFuncId::GlGetString => {
                let name = cpu.reg(Reg::R0);
                let string_val = match name {
                    GL_VENDOR => "Walzer32 / Google DeepMind\0",
                    GL_RENDERER => "Walzer32 Adreno/Mali Passthrough Engine\0",
                    GL_VERSION => "OpenGL ES 3.2 Walzer32\0",
                    GL_SHADING_LANGUAGE_VERSION => "OpenGL ES GLSL ES 3.20\0",
                    GL_EXTENSIONS => "GL_OES_EGL_image GL_OES_EGL_sync GL_OES_texture_npot GL_EXT_texture_format_BGRA8888\0",
                    _ => "Walzer32 Generic\0",
                };

                let addr = self.alloc_guest_string(mem, string_val.as_bytes())?;
                cpu.set_reg(Reg::R0, addr);
            }
            GlesFuncId::GlGetAttribLocation => {
                cpu.set_reg(Reg::R0, 0);
            }
            GlesFuncId::GlGetShaderInfoLog | GlesFuncId::GlGetProgramInfoLog => {
                let len_ptr = GuestAddr::new(cpu.reg(Reg::R2));
                if len_ptr.as_u32() != 0 {
                    mem.write_u32(len_ptr, 0)?;
                }
            }
            GlesFuncId::GlGetError => {
                cpu.set_reg(Reg::R0, 0); // GL_NO_ERROR
            }
            // --- GLES 1.1 Fixed-Function State Machine ---
            GlesFuncId::GlMatrixMode => {
                self.matrix_mode = cpu.reg(Reg::R0);
                cpu.set_reg(Reg::R0, 0);
            }
            GlesFuncId::GlEnableClientState => {
                self.client_states |= 1 << (cpu.reg(Reg::R0) & 0x1F);
                cpu.set_reg(Reg::R0, 0);
            }
            GlesFuncId::GlDisableClientState => {
                self.client_states &= !(1 << (cpu.reg(Reg::R0) & 0x1F));
                cpu.set_reg(Reg::R0, 0);
            }
            GlesFuncId::GlClientActiveTexture => {
                self.client_active_texture = cpu.reg(Reg::R0);
                cpu.set_reg(Reg::R0, 0);
            }
            GlesFuncId::GlLoadIdentity |
            GlesFuncId::GlLoadMatrixf |
            GlesFuncId::GlPushMatrix |
            GlesFuncId::GlPopMatrix |
            GlesFuncId::GlOrthof |
            GlesFuncId::GlFrustumf |
            GlesFuncId::GlTranslatef |
            GlesFuncId::GlScalef |
            GlesFuncId::GlRotatef |
            GlesFuncId::GlVertexPointer |
            GlesFuncId::GlColorPointer |
            GlesFuncId::GlTexCoordPointer |
            GlesFuncId::GlNormalPointer |
            GlesFuncId::GlAlphaFunc |
            GlesFuncId::GlColor4f |
            GlesFuncId::GlColor4ub |
            GlesFuncId::GlShadeModel |
            GlesFuncId::GlTexEnvf |
            GlesFuncId::GlTexEnvi |
            GlesFuncId::GlLightf |
            GlesFuncId::GlLightfv |
            GlesFuncId::GlMaterialf |
            GlesFuncId::GlMaterialfv |
            GlesFuncId::GlFogf |
            GlesFuncId::GlFogfv => {
                cpu.set_reg(Reg::R0, 0);
            }
            _ => {
                cpu.set_reg(Reg::R0, 0);
            }
        }

        Ok(true)
    }

    #[cfg(target_os = "android")]
    fn guest_ptr(mem: &mut impl Memory, addr: u32) -> *mut c_void {
        if addr == 0 {
            return std::ptr::null_mut();
        }
        let base = mem.as_mut_ptr();
        if base.is_null() {
            std::ptr::null_mut()
        } else {
            unsafe { base.add(addr as usize) as *mut c_void }
        }
    }

    #[cfg(target_os = "android")]
    fn guest_ptr_const(mem: &mut impl Memory, addr: u32) -> *const c_void {
        Self::guest_ptr(mem, addr) as *const c_void
    }

    #[cfg(target_os = "android")]
    fn host_gen_ids(
        mem: &mut impl Memory,
        n: u32,
        ptr: GuestAddr,
        f: extern "C" fn(i32, *mut u32),
    ) -> Result<(), MemoryError> {
        if n == 0 || ptr.as_u32() == 0 {
            return Ok(());
        }
        let mut ids = vec![0u32; n as usize];
        f(n as i32, ids.as_mut_ptr());
        for (i, &id) in ids.iter().enumerate() {
            mem.write_u32(ptr.add((i as u32) * 4), id)?;
        }
        Ok(())
    }

    #[cfg(target_os = "android")]
    fn host_delete_ids(
        mem: &impl Memory,
        n: u32,
        ptr: GuestAddr,
        f: extern "C" fn(i32, *const u32),
    ) -> Result<(), MemoryError> {
        if n == 0 || ptr.as_u32() == 0 {
            return Ok(());
        }
        let mut ids = Vec::with_capacity(n as usize);
        for i in 0..n {
            ids.push(mem.read_u32(ptr.add(i * 4))?);
        }
        f(n as i32, ids.as_ptr());
        Ok(())
    }

    #[cfg(target_os = "android")]
    fn host_get_iv(
        mem: &mut impl Memory,
        obj: u32,
        pname: u32,
        params_ptr: GuestAddr,
        f: extern "C" fn(u32, u32, *mut i32),
    ) -> Result<(), MemoryError> {
        let mut val: i32 = 0;
        f(obj, pname, &mut val);
        if params_ptr.as_u32() != 0 {
            mem.write_u32(params_ptr, val as u32)?;
        }
        Ok(())
    }

    #[cfg(target_os = "android")]
    fn host_get_info_log(
        mem: &mut impl Memory,
        obj: u32,
        max_len: i32,
        len_ptr: GuestAddr,
        log_ptr: GuestAddr,
        f: extern "C" fn(u32, i32, *mut i32, *mut c_void),
    ) -> Result<(), MemoryError> {
        let cap = max_len.max(0) as usize;
        let mut buf = vec![0u8; cap];
        let mut out_len: i32 = 0;
        let log_out = if cap == 0 || log_ptr.as_u32() == 0 {
            std::ptr::null_mut()
        } else {
            buf.as_mut_ptr() as *mut c_void
        };
        f(obj, max_len, &mut out_len, log_out);
        if len_ptr.as_u32() != 0 {
            mem.write_u32(len_ptr, out_len.max(0) as u32)?;
        }
        if !log_out.is_null() {
            let copy_len = (out_len.max(0) as usize).saturating_add(1).min(cap);
            mem.write_bytes(log_ptr, &buf[..copy_len])?;
        }
        Ok(())
    }

    #[cfg(target_os = "android")]
    fn try_handle_android(
        &mut self,
        func_id: GlesFuncId,
        cpu: &mut walzer32_core::CpuState,
        mem: &mut impl Memory,
    ) -> Result<bool, MemoryError> {
        macro_rules! resolve_host {
            ($sym:literal, $ty:ty) => {{
                let Some(fp) = self.host.resolve($sym) else {
                    return Ok(false);
                };
                unsafe { std::mem::transmute::<RawFnPtr, $ty>(fp) }
            }};
        }

        match func_id {
            // --- EGL Core ---
            GlesFuncId::EglGetDisplay => {
                let f = resolve_host!("eglGetDisplay", extern "C" fn(usize) -> usize);
                let raw_disp = cpu.reg(Reg::R0);
                let host_dpy = f(if raw_disp == 0 { 0 } else { self.resolve_host_egl_handle(raw_disp) });
                let guest_dpy = self.register_host_egl_handle(host_dpy);
                cpu.set_reg(Reg::R0, guest_dpy);
                Ok(true)
            }
            GlesFuncId::EglInitialize => {
                let f = resolve_host!("eglInitialize", extern "C" fn(usize, *mut i32, *mut i32) -> u32);
                let host_dpy = self.resolve_host_egl_handle(cpu.reg(Reg::R0));
                let major_ptr = GuestAddr::new(cpu.reg(Reg::R1));
                let minor_ptr = GuestAddr::new(cpu.reg(Reg::R2));
                let mut maj: i32 = 0;
                let mut min: i32 = 0;
                let ok = f(host_dpy, &mut maj, &mut min);
                if major_ptr.as_u32() != 0 {
                    mem.write_u32(major_ptr, maj as u32)?;
                }
                if minor_ptr.as_u32() != 0 {
                    mem.write_u32(minor_ptr, min as u32)?;
                }
                cpu.set_reg(Reg::R0, ok);
                Ok(true)
            }
            GlesFuncId::EglChooseConfig => {
                let f = resolve_host!(
                    "eglChooseConfig",
                    extern "C" fn(usize, *const i32, *mut usize, i32, *mut i32) -> u32
                );
                let host_dpy = self.resolve_host_egl_handle(cpu.reg(Reg::R0));
                let attribs = self.read_egl_attribs(mem, GuestAddr::new(cpu.reg(Reg::R1)))?;
                let configs_ptr = GuestAddr::new(cpu.reg(Reg::R2));
                let config_size = cpu.reg(Reg::R3) as i32;
                let sp = GuestAddr::new(cpu.sp());
                let num_config_ptr = GuestAddr::new(mem.read_u32(sp).unwrap_or(0));

                let mut num_returned: i32 = 0;
                let ok = if configs_ptr.as_u32() != 0 && config_size > 0 {
                    let mut host_cfgs = vec![0usize; config_size as usize];
                    let res = f(
                        host_dpy,
                        attribs.as_ptr(),
                        host_cfgs.as_mut_ptr(),
                        config_size,
                        &mut num_returned,
                    );
                    if res == EGL_TRUE {
                        let count = num_returned.max(0).min(config_size) as usize;
                        for (i, &hcfg) in host_cfgs.iter().take(count).enumerate() {
                            let gcfg = self.register_host_egl_handle(hcfg);
                            mem.write_u32(configs_ptr.add((i as u32) * 4), gcfg)?;
                        }
                    }
                    res
                } else {
                    f(
                        host_dpy,
                        attribs.as_ptr(),
                        std::ptr::null_mut(),
                        config_size,
                        &mut num_returned,
                    )
                };

                if num_config_ptr.as_u32() != 0 {
                    mem.write_u32(num_config_ptr, num_returned.max(0) as u32)?;
                }
                cpu.set_reg(Reg::R0, ok);
                Ok(true)
            }
            GlesFuncId::EglGetConfigAttrib => {
                let f = resolve_host!("eglGetConfigAttrib", extern "C" fn(usize, usize, i32, *mut i32) -> u32);
                let host_dpy = self.resolve_host_egl_handle(cpu.reg(Reg::R0));
                let host_cfg = self.resolve_host_egl_handle(cpu.reg(Reg::R1));
                let attr = cpu.reg(Reg::R2) as i32;
                let val_ptr = GuestAddr::new(cpu.reg(Reg::R3));
                let mut val: i32 = 0;
                let ok = f(host_dpy, host_cfg, attr, &mut val);
                if ok == EGL_TRUE && val_ptr.as_u32() != 0 {
                    mem.write_u32(val_ptr, val as u32)?;
                }
                cpu.set_reg(Reg::R0, ok);
                Ok(true)
            }
            GlesFuncId::EglCreateWindowSurface => {
                let f = resolve_host!(
                    "eglCreateWindowSurface",
                    extern "C" fn(usize, usize, usize, *const i32) -> usize
                );
                let host_dpy = self.resolve_host_egl_handle(cpu.reg(Reg::R0));
                let host_cfg = self.resolve_host_egl_handle(cpu.reg(Reg::R1));
                let guest_win = cpu.reg(Reg::R2);
                let host_win = if self.host_window_ptr != 0 {
                    self.host_window_ptr
                } else {
                    self.resolve_host_egl_handle(guest_win)
                };
                let attribs = self.read_egl_attribs(mem, GuestAddr::new(cpu.reg(Reg::R3)))?;
                let host_surf = f(host_dpy, host_cfg, host_win, attribs.as_ptr());
                let guest_surf = self.register_host_egl_handle(host_surf);
                if guest_surf != 0 {
                    self.bound_native_window = guest_win;
                    self.egl_surfaces.insert(
                        guest_surf,
                        EglSurfaceState {
                            surface_id: guest_surf,
                            kind: SurfaceKind::Window,
                            native_window: guest_win,
                            width: 0,
                            height: 0,
                            texture_format: 0,
                            texture_target: 0,
                        },
                    );
                }
                cpu.set_reg(Reg::R0, guest_surf);
                Ok(true)
            }
            GlesFuncId::EglCreatePbufferSurface => {
                let f = resolve_host!(
                    "eglCreatePbufferSurface",
                    extern "C" fn(usize, usize, *const i32) -> usize
                );
                let host_dpy = self.resolve_host_egl_handle(cpu.reg(Reg::R0));
                let host_cfg = self.resolve_host_egl_handle(cpu.reg(Reg::R1));
                let attribs = self.read_egl_attribs(mem, GuestAddr::new(cpu.reg(Reg::R2)))?;
                let host_surf = f(host_dpy, host_cfg, attribs.as_ptr());
                let guest_surf = self.register_host_egl_handle(host_surf);
                if guest_surf != 0 {
                    self.egl_surfaces.insert(
                        guest_surf,
                        EglSurfaceState {
                            surface_id: guest_surf,
                            kind: SurfaceKind::Pbuffer,
                            native_window: 0,
                            width: 256,
                            height: 256,
                            texture_format: 0,
                            texture_target: 0,
                        },
                    );
                }
                cpu.set_reg(Reg::R0, guest_surf);
                Ok(true)
            }
            GlesFuncId::EglDestroySurface => {
                let f = resolve_host!("eglDestroySurface", extern "C" fn(usize, usize) -> u32);
                let host_dpy = self.resolve_host_egl_handle(cpu.reg(Reg::R0));
                let guest_surf = cpu.reg(Reg::R1);
                let host_surf = self.resolve_host_egl_handle(guest_surf);
                let ok = f(host_dpy, host_surf);
                self.egl_surfaces.remove(&guest_surf);
                self.host_egl_handles.remove(&guest_surf);
                cpu.set_reg(Reg::R0, ok);
                Ok(true)
            }
            GlesFuncId::EglQuerySurface => {
                let f = resolve_host!("eglQuerySurface", extern "C" fn(usize, usize, i32, *mut i32) -> u32);
                let host_dpy = self.resolve_host_egl_handle(cpu.reg(Reg::R0));
                let host_surf = self.resolve_host_egl_handle(cpu.reg(Reg::R1));
                let attr = cpu.reg(Reg::R2) as i32;
                let val_ptr = GuestAddr::new(cpu.reg(Reg::R3));
                let mut val: i32 = 0;
                let ok = f(host_dpy, host_surf, attr, &mut val);
                if ok == EGL_TRUE && val_ptr.as_u32() != 0 {
                    mem.write_u32(val_ptr, val as u32)?;
                }
                cpu.set_reg(Reg::R0, ok);
                Ok(true)
            }
            GlesFuncId::EglCreateContext => {
                let f = resolve_host!(
                    "eglCreateContext",
                    extern "C" fn(usize, usize, usize, *const i32) -> usize
                );
                let host_dpy = self.resolve_host_egl_handle(cpu.reg(Reg::R0));
                let host_cfg = self.resolve_host_egl_handle(cpu.reg(Reg::R1));
                let share_ctx = cpu.reg(Reg::R2);
                let host_share = self.resolve_host_egl_handle(share_ctx);
                let attribs = self.read_egl_attribs(mem, GuestAddr::new(cpu.reg(Reg::R3)))?;
                let host_ctx = f(host_dpy, host_cfg, host_share, attribs.as_ptr());
                let guest_ctx = self.register_host_egl_handle(host_ctx);
                if guest_ctx != 0 {
                    let share_group_id = if share_ctx != 0 {
                        self.egl_contexts
                            .get(&share_ctx)
                            .map(|c| c.share_group_id)
                            .unwrap_or_else(|| {
                                let gid = self.next_share_group_id;
                                self.next_share_group_id += 1;
                                gid
                            })
                    } else {
                        let gid = self.next_share_group_id;
                        self.next_share_group_id += 1;
                        gid
                    };
                    self.share_groups.entry(share_group_id).or_insert_with(|| ShareGroup {
                        group_id: share_group_id,
                        textures: HashMap::new(),
                        buffers: HashMap::new(),
                        sync_fences: HashMap::new(),
                    });
                    self.egl_contexts.insert(
                        guest_ctx,
                        EglContextState {
                            context_id: guest_ctx,
                            share_group_id,
                            client_version: 2,
                            bound_texture_2d: 0,
                            bound_array_buffer: 0,
                            bound_element_array_buffer: 0,
                            bound_framebuffer: 0,
                            active_texture_unit: 0,
                        },
                    );
                }
                cpu.set_reg(Reg::R0, guest_ctx);
                Ok(true)
            }
            GlesFuncId::EglDestroyContext => {
                let f = resolve_host!("eglDestroyContext", extern "C" fn(usize, usize) -> u32);
                let host_dpy = self.resolve_host_egl_handle(cpu.reg(Reg::R0));
                let guest_ctx = cpu.reg(Reg::R1);
                let host_ctx = self.resolve_host_egl_handle(guest_ctx);
                let ok = f(host_dpy, host_ctx);
                self.egl_contexts.remove(&guest_ctx);
                self.host_egl_handles.remove(&guest_ctx);
                cpu.set_reg(Reg::R0, ok);
                Ok(true)
            }
            GlesFuncId::EglMakeCurrent => {
                let f = resolve_host!("eglMakeCurrent", extern "C" fn(usize, usize, usize, usize) -> u32);
                let host_dpy = self.resolve_host_egl_handle(cpu.reg(Reg::R0));
                let draw = cpu.reg(Reg::R1);
                let read = cpu.reg(Reg::R2);
                let ctx = cpu.reg(Reg::R3);
                let ok = f(
                    host_dpy,
                    self.resolve_host_egl_handle(draw),
                    self.resolve_host_egl_handle(read),
                    self.resolve_host_egl_handle(ctx),
                );
                if ok == EGL_TRUE {
                    let tid = self.current_thread_id(cpu);
                    if ctx == 0 && draw == 0 && read == 0 {
                        self.thread_bindings.remove(&tid);
                        self.active_context = 0;
                        self.active_draw_surface = 0;
                        self.active_read_surface = 0;
                    } else {
                        self.thread_bindings.insert(
                            tid,
                            ThreadEglBinding {
                                context_id: ctx,
                                draw_surface: draw,
                                read_surface: read,
                            },
                        );
                        self.active_draw_surface = draw;
                        self.active_read_surface = read;
                        self.active_context = ctx;
                    }
                }
                cpu.set_reg(Reg::R0, ok);
                Ok(true)
            }
            GlesFuncId::EglGetCurrentContext => {
                let f = resolve_host!("eglGetCurrentContext", extern "C" fn() -> usize);
                let guest_ctx = self.register_host_egl_handle(f());
                cpu.set_reg(Reg::R0, guest_ctx);
                Ok(true)
            }
            GlesFuncId::EglGetCurrentSurface => {
                let f = resolve_host!("eglGetCurrentSurface", extern "C" fn(i32) -> usize);
                let guest_surf = self.register_host_egl_handle(f(cpu.reg(Reg::R0) as i32));
                cpu.set_reg(Reg::R0, guest_surf);
                Ok(true)
            }
            GlesFuncId::EglGetCurrentDisplay => {
                let f = resolve_host!("eglGetCurrentDisplay", extern "C" fn() -> usize);
                let guest_dpy = self.register_host_egl_handle(f());
                cpu.set_reg(Reg::R0, guest_dpy);
                Ok(true)
            }
            GlesFuncId::EglSwapBuffers => {
                let f = resolve_host!("eglSwapBuffers", extern "C" fn(usize, usize) -> u32);
                let host_dpy = self.resolve_host_egl_handle(cpu.reg(Reg::R0));
                let host_surf = self.resolve_host_egl_handle(cpu.reg(Reg::R1));
                let ok = f(host_dpy, host_surf);
                if ok == EGL_TRUE {
                    self.swap_count += 1;
                }
                cpu.set_reg(Reg::R0, ok);
                Ok(true)
            }
            GlesFuncId::EglGetError => {
                let f = resolve_host!("eglGetError", extern "C" fn() -> i32);
                cpu.set_reg(Reg::R0, f() as u32);
                Ok(true)
            }
            GlesFuncId::EglTerminate => {
                let f = resolve_host!("eglTerminate", extern "C" fn(usize) -> u32);
                let host_dpy = self.resolve_host_egl_handle(cpu.reg(Reg::R0));
                cpu.set_reg(Reg::R0, f(host_dpy));
                Ok(true)
            }
            GlesFuncId::EglReleaseThread => {
                let f = resolve_host!("eglReleaseThread", extern "C" fn() -> u32);
                let tid = self.current_thread_id(cpu);
                self.thread_bindings.remove(&tid);
                cpu.set_reg(Reg::R0, f());
                Ok(true)
            }
            GlesFuncId::EglQueryString => {
                let name = cpu.reg(Reg::R1);
                if let Some(&cached) = self.host_egl_strings.get(&name) {
                    cpu.set_reg(Reg::R0, cached);
                    return Ok(true);
                }
                let f = resolve_host!("eglQueryString", extern "C" fn(usize, i32) -> *const c_char);
                let host_dpy = self.resolve_host_egl_handle(cpu.reg(Reg::R0));
                let ptr = f(host_dpy, name as i32);
                if ptr.is_null() {
                    cpu.set_reg(Reg::R0, 0);
                } else {
                    let bytes = unsafe { CStr::from_ptr(ptr).to_bytes_with_nul() };
                    let addr = self.alloc_guest_string(mem, bytes)?;
                    self.host_egl_strings.insert(name, addr);
                    cpu.set_reg(Reg::R0, addr);
                }
                Ok(true)
            }
            GlesFuncId::EglCreateSyncKHR => {
                let f = resolve_host!("eglCreateSyncKHR", extern "C" fn(usize, u32, *const i32) -> usize);
                let host_dpy = self.resolve_host_egl_handle(cpu.reg(Reg::R0));
                let sync_type = cpu.reg(Reg::R1);
                let attribs = self.read_egl_attribs(mem, GuestAddr::new(cpu.reg(Reg::R2)))?;
                let guest_sync = self.register_host_egl_handle(f(host_dpy, sync_type, attribs.as_ptr()));
                cpu.set_reg(Reg::R0, guest_sync);
                Ok(true)
            }
            GlesFuncId::EglClientWaitSyncKHR => {
                let f = resolve_host!("eglClientWaitSyncKHR", extern "C" fn(usize, usize, i32, u64) -> i32);
                let host_dpy = self.resolve_host_egl_handle(cpu.reg(Reg::R0));
                let host_sync = self.resolve_host_egl_handle(cpu.reg(Reg::R1));
                let flags = cpu.reg(Reg::R2) as i32;
                let sp = GuestAddr::new(cpu.sp());
                let lo = mem.read_u32(sp).unwrap_or(0) as u64;
                let hi = mem.read_u32(sp.add(4)).unwrap_or(0) as u64;
                let timeout = (hi << 32) | lo;
                cpu.set_reg(Reg::R0, f(host_dpy, host_sync, flags, timeout) as u32);
                Ok(true)
            }
            GlesFuncId::EglDestroySyncKHR => {
                let f = resolve_host!("eglDestroySyncKHR", extern "C" fn(usize, usize) -> u32);
                let host_dpy = self.resolve_host_egl_handle(cpu.reg(Reg::R0));
                let guest_sync = cpu.reg(Reg::R1);
                let ok = f(host_dpy, self.resolve_host_egl_handle(guest_sync));
                self.host_egl_handles.remove(&guest_sync);
                cpu.set_reg(Reg::R0, ok);
                Ok(true)
            }
            GlesFuncId::EglGetSyncAttribKHR => {
                let f = resolve_host!("eglGetSyncAttribKHR", extern "C" fn(usize, usize, i32, *mut i32) -> u32);
                let host_dpy = self.resolve_host_egl_handle(cpu.reg(Reg::R0));
                let host_sync = self.resolve_host_egl_handle(cpu.reg(Reg::R1));
                let attr = cpu.reg(Reg::R2) as i32;
                let val_ptr = GuestAddr::new(cpu.reg(Reg::R3));
                let mut val: i32 = 0;
                let ok = f(host_dpy, host_sync, attr, &mut val);
                if ok == EGL_TRUE && val_ptr.as_u32() != 0 {
                    mem.write_u32(val_ptr, val as u32)?;
                }
                cpu.set_reg(Reg::R0, ok);
                Ok(true)
            }
            GlesFuncId::EglWaitSyncKHR => {
                let f = resolve_host!("eglWaitSyncKHR", extern "C" fn(usize, usize, i32) -> i32);
                let host_dpy = self.resolve_host_egl_handle(cpu.reg(Reg::R0));
                let host_sync = self.resolve_host_egl_handle(cpu.reg(Reg::R1));
                cpu.set_reg(Reg::R0, f(host_dpy, host_sync, cpu.reg(Reg::R2) as i32) as u32);
                Ok(true)
            }

            // --- GLES State & Clear ---
            GlesFuncId::GlClearColor => {
                let f = resolve_host!("glClearColor", extern "C" fn(f32, f32, f32, f32));
                let r = f32::from_bits(cpu.reg(Reg::R0));
                let g = f32::from_bits(cpu.reg(Reg::R1));
                let b = f32::from_bits(cpu.reg(Reg::R2));
                let a = f32::from_bits(cpu.reg(Reg::R3));
                self.clear_color = [r, g, b, a];
                f(r, g, b, a);
                Ok(true)
            }
            GlesFuncId::GlClearDepthf => {
                let f = resolve_host!("glClearDepthf", extern "C" fn(f32));
                f(f32::from_bits(cpu.reg(Reg::R0)));
                Ok(true)
            }
            GlesFuncId::GlClear => {
                let f = resolve_host!("glClear", extern "C" fn(u32));
                f(cpu.reg(Reg::R0));
                Ok(true)
            }
            GlesFuncId::GlViewport => {
                let f = resolve_host!("glViewport", extern "C" fn(i32, i32, i32, i32));
                let x = cpu.reg(Reg::R0) as i32;
                let y = cpu.reg(Reg::R1) as i32;
                let w = cpu.reg(Reg::R2) as i32;
                let h = cpu.reg(Reg::R3) as i32;
                self.viewport = [x, y, w, h];
                f(x, y, w, h);
                Ok(true)
            }
            GlesFuncId::GlScissor => {
                let f = resolve_host!("glScissor", extern "C" fn(i32, i32, i32, i32));
                f(
                    cpu.reg(Reg::R0) as i32,
                    cpu.reg(Reg::R1) as i32,
                    cpu.reg(Reg::R2) as i32,
                    cpu.reg(Reg::R3) as i32,
                );
                Ok(true)
            }
            GlesFuncId::GlEnable => {
                let f = resolve_host!("glEnable", extern "C" fn(u32));
                f(cpu.reg(Reg::R0));
                Ok(true)
            }
            GlesFuncId::GlDisable => {
                let f = resolve_host!("glDisable", extern "C" fn(u32));
                f(cpu.reg(Reg::R0));
                Ok(true)
            }
            GlesFuncId::GlBlendFunc => {
                let f = resolve_host!("glBlendFunc", extern "C" fn(u32, u32));
                f(cpu.reg(Reg::R0), cpu.reg(Reg::R1));
                Ok(true)
            }
            GlesFuncId::GlDepthFunc => {
                let f = resolve_host!("glDepthFunc", extern "C" fn(u32));
                f(cpu.reg(Reg::R0));
                Ok(true)
            }
            GlesFuncId::GlDepthMask => {
                let f = resolve_host!("glDepthMask", extern "C" fn(u8));
                f(cpu.reg(Reg::R0) as u8);
                Ok(true)
            }
            GlesFuncId::GlColorMask => {
                let f = resolve_host!("glColorMask", extern "C" fn(u8, u8, u8, u8));
                f(
                    cpu.reg(Reg::R0) as u8,
                    cpu.reg(Reg::R1) as u8,
                    cpu.reg(Reg::R2) as u8,
                    cpu.reg(Reg::R3) as u8,
                );
                Ok(true)
            }
            GlesFuncId::GlCullFace => {
                let f = resolve_host!("glCullFace", extern "C" fn(u32));
                f(cpu.reg(Reg::R0));
                Ok(true)
            }
            GlesFuncId::GlFrontFace => {
                let f = resolve_host!("glFrontFace", extern "C" fn(u32));
                f(cpu.reg(Reg::R0));
                Ok(true)
            }

            // --- Shaders & Programs ---
            GlesFuncId::GlCreateShader => {
                let f = resolve_host!("glCreateShader", extern "C" fn(u32) -> u32);
                cpu.set_reg(Reg::R0, f(cpu.reg(Reg::R0)));
                Ok(true)
            }
            GlesFuncId::GlDeleteShader => {
                let f = resolve_host!("glDeleteShader", extern "C" fn(u32));
                f(cpu.reg(Reg::R0));
                Ok(true)
            }
            GlesFuncId::GlShaderSource => {
                let f = resolve_host!(
                    "glShaderSource",
                    extern "C" fn(u32, i32, *const *const c_void, *const i32)
                );
                let shader = cpu.reg(Reg::R0);
                let count = cpu.reg(Reg::R1) as i32;
                let string_arr_ptr = GuestAddr::new(cpu.reg(Reg::R2));
                let length_addr = cpu.reg(Reg::R3);
                if count > 0 && string_arr_ptr.as_u32() != 0 {
                    let mut host_ptrs = Vec::with_capacity(count as usize);
                    for i in 0..(count as u32) {
                        let gstr = mem.read_u32(string_arr_ptr.add(i * 4))?;
                        host_ptrs.push(Self::guest_ptr_const(mem, gstr));
                    }
                    let host_lengths = Self::guest_ptr_const(mem, length_addr) as *const i32;
                    f(shader, count, host_ptrs.as_ptr(), host_lengths);
                }
                Ok(true)
            }
            GlesFuncId::GlCompileShader => {
                let f = resolve_host!("glCompileShader", extern "C" fn(u32));
                f(cpu.reg(Reg::R0));
                Ok(true)
            }
            GlesFuncId::GlGetShaderiv => {
                let f = resolve_host!("glGetShaderiv", extern "C" fn(u32, u32, *mut i32));
                Self::host_get_iv(mem, cpu.reg(Reg::R0), cpu.reg(Reg::R1), GuestAddr::new(cpu.reg(Reg::R2)), f)?;
                Ok(true)
            }
            GlesFuncId::GlGetShaderInfoLog => {
                let f = resolve_host!("glGetShaderInfoLog", extern "C" fn(u32, i32, *mut i32, *mut c_void));
                Self::host_get_info_log(
                    mem,
                    cpu.reg(Reg::R0),
                    cpu.reg(Reg::R1) as i32,
                    GuestAddr::new(cpu.reg(Reg::R2)),
                    GuestAddr::new(cpu.reg(Reg::R3)),
                    f,
                )?;
                Ok(true)
            }
            GlesFuncId::GlCreateProgram => {
                let f = resolve_host!("glCreateProgram", extern "C" fn() -> u32);
                cpu.set_reg(Reg::R0, f());
                Ok(true)
            }
            GlesFuncId::GlDeleteProgram => {
                let f = resolve_host!("glDeleteProgram", extern "C" fn(u32));
                f(cpu.reg(Reg::R0));
                Ok(true)
            }
            GlesFuncId::GlAttachShader => {
                let f = resolve_host!("glAttachShader", extern "C" fn(u32, u32));
                f(cpu.reg(Reg::R0), cpu.reg(Reg::R1));
                Ok(true)
            }
            GlesFuncId::GlLinkProgram => {
                let f = resolve_host!("glLinkProgram", extern "C" fn(u32));
                f(cpu.reg(Reg::R0));
                Ok(true)
            }
            GlesFuncId::GlGetProgramiv => {
                let f = resolve_host!("glGetProgramiv", extern "C" fn(u32, u32, *mut i32));
                Self::host_get_iv(mem, cpu.reg(Reg::R0), cpu.reg(Reg::R1), GuestAddr::new(cpu.reg(Reg::R2)), f)?;
                Ok(true)
            }
            GlesFuncId::GlGetProgramInfoLog => {
                let f = resolve_host!("glGetProgramInfoLog", extern "C" fn(u32, i32, *mut i32, *mut c_void));
                Self::host_get_info_log(
                    mem,
                    cpu.reg(Reg::R0),
                    cpu.reg(Reg::R1) as i32,
                    GuestAddr::new(cpu.reg(Reg::R2)),
                    GuestAddr::new(cpu.reg(Reg::R3)),
                    f,
                )?;
                Ok(true)
            }
            GlesFuncId::GlUseProgram => {
                let f = resolve_host!("glUseProgram", extern "C" fn(u32));
                let prog = cpu.reg(Reg::R0);
                self.active_program = prog;
                f(prog);
                Ok(true)
            }

            // --- Buffers & Drawing ---
            GlesFuncId::GlGenBuffers => {
                let f = resolve_host!("glGenBuffers", extern "C" fn(i32, *mut u32));
                Self::host_gen_ids(mem, cpu.reg(Reg::R0), GuestAddr::new(cpu.reg(Reg::R1)), f)?;
                Ok(true)
            }
            GlesFuncId::GlDeleteBuffers => {
                let f = resolve_host!("glDeleteBuffers", extern "C" fn(i32, *const u32));
                Self::host_delete_ids(mem, cpu.reg(Reg::R0), GuestAddr::new(cpu.reg(Reg::R1)), f)?;
                Ok(true)
            }
            GlesFuncId::GlBindBuffer => {
                let f = resolve_host!("glBindBuffer", extern "C" fn(u32, u32));
                let target = cpu.reg(Reg::R0);
                let buffer = cpu.reg(Reg::R1);
                self.record_bind_buffer(cpu, target, buffer);
                f(target, buffer);
                Ok(true)
            }
            GlesFuncId::GlBufferData => {
                let f = resolve_host!("glBufferData", extern "C" fn(u32, isize, *const c_void, u32));
                let target = cpu.reg(Reg::R0);
                let size = cpu.reg(Reg::R1) as isize;
                let data_ptr = Self::guest_ptr_const(mem, cpu.reg(Reg::R2));
                let usage = cpu.reg(Reg::R3);
                f(target, size, data_ptr, usage);
                Ok(true)
            }
            GlesFuncId::GlEnableVertexAttribArray => {
                let f = resolve_host!("glEnableVertexAttribArray", extern "C" fn(u32));
                f(cpu.reg(Reg::R0));
                Ok(true)
            }
            GlesFuncId::GlDisableVertexAttribArray => {
                let f = resolve_host!("glDisableVertexAttribArray", extern "C" fn(u32));
                f(cpu.reg(Reg::R0));
                Ok(true)
            }
            GlesFuncId::GlVertexAttribPointer => {
                let f = resolve_host!(
                    "glVertexAttribPointer",
                    extern "C" fn(u32, i32, u32, u8, i32, *const c_void)
                );
                let index = cpu.reg(Reg::R0);
                let size = cpu.reg(Reg::R1) as i32;
                let ty = cpu.reg(Reg::R2);
                let normalized = cpu.reg(Reg::R3) as u8;
                let sp = GuestAddr::new(cpu.sp());
                let stride = mem.read_u32(sp)? as i32;
                let pointer_val = mem.read_u32(sp.add(4))?;
                let bound_vbo = self.current_bound_buffer(cpu, 0x8892);
                let host_pointer = if bound_vbo != 0 {
                    pointer_val as usize as *const c_void
                } else {
                    Self::guest_ptr_const(mem, pointer_val)
                };
                f(index, size, ty, normalized, stride, host_pointer);
                Ok(true)
            }
            GlesFuncId::GlDrawArrays => {
                let f = resolve_host!("glDrawArrays", extern "C" fn(u32, i32, i32));
                let mode = cpu.reg(Reg::R0);
                let first = cpu.reg(Reg::R1) as i32;
                let count = cpu.reg(Reg::R2) as i32;
                f(mode, first, count);
                self.total_draw_calls += 1;
                if self.draw_calls.len() >= 64 {
                    self.draw_calls.remove(0);
                }
                self.draw_calls.push(DrawCallRecord { mode, first, count });
                Ok(true)
            }
            GlesFuncId::GlDrawElements => {
                let f = resolve_host!("glDrawElements", extern "C" fn(u32, i32, u32, *const c_void));
                let mode = cpu.reg(Reg::R0);
                let count = cpu.reg(Reg::R1) as i32;
                let ty = cpu.reg(Reg::R2);
                let indices_val = cpu.reg(Reg::R3);
                let bound_ebo = self.current_bound_buffer(cpu, 0x8893);
                let host_indices = if bound_ebo != 0 {
                    indices_val as usize as *const c_void
                } else {
                    Self::guest_ptr_const(mem, indices_val)
                };
                f(mode, count, ty, host_indices);
                self.total_draw_calls += 1;
                if self.draw_calls.len() >= 64 {
                    self.draw_calls.remove(0);
                }
                self.draw_calls.push(DrawCallRecord { mode, first: 0, count });
                Ok(true)
            }

            // --- Textures & Framebuffers ---
            GlesFuncId::GlGenTextures => {
                let f = resolve_host!("glGenTextures", extern "C" fn(i32, *mut u32));
                Self::host_gen_ids(mem, cpu.reg(Reg::R0), GuestAddr::new(cpu.reg(Reg::R1)), f)?;
                Ok(true)
            }
            GlesFuncId::GlDeleteTextures => {
                let f = resolve_host!("glDeleteTextures", extern "C" fn(i32, *const u32));
                Self::host_delete_ids(mem, cpu.reg(Reg::R0), GuestAddr::new(cpu.reg(Reg::R1)), f)?;
                Ok(true)
            }
            GlesFuncId::GlBindTexture => {
                let f = resolve_host!("glBindTexture", extern "C" fn(u32, u32));
                f(cpu.reg(Reg::R0), cpu.reg(Reg::R1));
                Ok(true)
            }
            GlesFuncId::GlTexImage2D => {
                let f = resolve_host!(
                    "glTexImage2D",
                    extern "C" fn(u32, i32, i32, i32, i32, i32, u32, u32, *const c_void)
                );
                let target = cpu.reg(Reg::R0);
                let level = cpu.reg(Reg::R1) as i32;
                let internal_format = cpu.reg(Reg::R2) as i32;
                let width = cpu.reg(Reg::R3) as i32;
                let sp = GuestAddr::new(cpu.sp());
                let height = mem.read_u32(sp)? as i32;
                let border = mem.read_u32(sp.add(4))? as i32;
                let format = mem.read_u32(sp.add(8))?;
                let pixel_type = mem.read_u32(sp.add(12))?;
                let pixels_addr = mem.read_u32(sp.add(16))?;
                let pixels = Self::guest_ptr_const(mem, pixels_addr);
                f(target, level, internal_format, width, height, border, format, pixel_type, pixels);
                Ok(true)
            }
            GlesFuncId::GlTexParameteri => {
                let f = resolve_host!("glTexParameteri", extern "C" fn(u32, u32, i32));
                f(cpu.reg(Reg::R0), cpu.reg(Reg::R1), cpu.reg(Reg::R2) as i32);
                Ok(true)
            }
            GlesFuncId::GlPixelStorei => {
                let f = resolve_host!("glPixelStorei", extern "C" fn(u32, i32));
                f(cpu.reg(Reg::R0), cpu.reg(Reg::R1) as i32);
                Ok(true)
            }
            GlesFuncId::GlActiveTexture => {
                let f = resolve_host!("glActiveTexture", extern "C" fn(u32));
                f(cpu.reg(Reg::R0));
                Ok(true)
            }
            GlesFuncId::GlGenFramebuffers => {
                let f = resolve_host!("glGenFramebuffers", extern "C" fn(i32, *mut u32));
                Self::host_gen_ids(mem, cpu.reg(Reg::R0), GuestAddr::new(cpu.reg(Reg::R1)), f)?;
                Ok(true)
            }
            GlesFuncId::GlDeleteFramebuffers => {
                let f = resolve_host!("glDeleteFramebuffers", extern "C" fn(i32, *const u32));
                Self::host_delete_ids(mem, cpu.reg(Reg::R0), GuestAddr::new(cpu.reg(Reg::R1)), f)?;
                Ok(true)
            }
            GlesFuncId::GlBindFramebuffer => {
                let f = resolve_host!("glBindFramebuffer", extern "C" fn(u32, u32));
                f(cpu.reg(Reg::R0), cpu.reg(Reg::R1));
                Ok(true)
            }
            GlesFuncId::GlFramebufferTexture2D => {
                let f = resolve_host!("glFramebufferTexture2D", extern "C" fn(u32, u32, u32, u32, i32));
                let sp = GuestAddr::new(cpu.sp());
                let level = mem.read_u32(sp)? as i32;
                f(
                    cpu.reg(Reg::R0),
                    cpu.reg(Reg::R1),
                    cpu.reg(Reg::R2),
                    cpu.reg(Reg::R3),
                    level,
                );
                Ok(true)
            }
            GlesFuncId::GlCheckFramebufferStatus => {
                let f = resolve_host!("glCheckFramebufferStatus", extern "C" fn(u32) -> u32);
                cpu.set_reg(Reg::R0, f(cpu.reg(Reg::R0)));
                Ok(true)
            }

            // --- Queries & Uniforms ---
            GlesFuncId::GlGetString => {
                let name = cpu.reg(Reg::R0);
                if let Some(&cached) = self.host_gl_strings.get(&name) {
                    cpu.set_reg(Reg::R0, cached);
                    return Ok(true);
                }
                let f = resolve_host!("glGetString", extern "C" fn(u32) -> *const c_char);
                let ptr = f(name);
                if ptr.is_null() {
                    cpu.set_reg(Reg::R0, 0);
                } else {
                    let bytes = unsafe { CStr::from_ptr(ptr).to_bytes_with_nul() };
                    let addr = self.alloc_guest_string(mem, bytes)?;
                    self.host_gl_strings.insert(name, addr);
                    cpu.set_reg(Reg::R0, addr);
                }
                Ok(true)
            }
            GlesFuncId::GlGetIntegerv => {
                let f = resolve_host!("glGetIntegerv", extern "C" fn(u32, *mut i32));
                let pname = cpu.reg(Reg::R0);
                let ptr = Self::guest_ptr(mem, cpu.reg(Reg::R1)) as *mut i32;
                if !ptr.is_null() {
                    f(pname, ptr);
                }
                Ok(true)
            }
            GlesFuncId::GlGetUniformLocation => {
                let f = resolve_host!("glGetUniformLocation", extern "C" fn(u32, *const c_char) -> i32);
                let prog = cpu.reg(Reg::R0);
                let name = self.read_guest_cstring(mem, GuestAddr::new(cpu.reg(Reg::R1)))?;
                let loc = CString::new(name)
                    .map(|c| f(prog, c.as_ptr()))
                    .unwrap_or(-1);
                cpu.set_reg(Reg::R0, loc as u32);
                Ok(true)
            }
            GlesFuncId::GlGetAttribLocation => {
                let f = resolve_host!("glGetAttribLocation", extern "C" fn(u32, *const c_char) -> i32);
                let prog = cpu.reg(Reg::R0);
                let name = self.read_guest_cstring(mem, GuestAddr::new(cpu.reg(Reg::R1)))?;
                let loc = CString::new(name)
                    .map(|c| f(prog, c.as_ptr()))
                    .unwrap_or(-1);
                cpu.set_reg(Reg::R0, loc as u32);
                Ok(true)
            }
            GlesFuncId::GlUniform1i => {
                let f = resolve_host!("glUniform1i", extern "C" fn(i32, i32));
                f(cpu.reg(Reg::R0) as i32, cpu.reg(Reg::R1) as i32);
                Ok(true)
            }
            GlesFuncId::GlUniform1f => {
                let f = resolve_host!("glUniform1f", extern "C" fn(i32, f32));
                f(cpu.reg(Reg::R0) as i32, f32::from_bits(cpu.reg(Reg::R1)));
                Ok(true)
            }
            GlesFuncId::GlUniform2f => {
                let f = resolve_host!("glUniform2f", extern "C" fn(i32, f32, f32));
                f(
                    cpu.reg(Reg::R0) as i32,
                    f32::from_bits(cpu.reg(Reg::R1)),
                    f32::from_bits(cpu.reg(Reg::R2)),
                );
                Ok(true)
            }
            GlesFuncId::GlUniform3f => {
                let f = resolve_host!("glUniform3f", extern "C" fn(i32, f32, f32, f32));
                f(
                    cpu.reg(Reg::R0) as i32,
                    f32::from_bits(cpu.reg(Reg::R1)),
                    f32::from_bits(cpu.reg(Reg::R2)),
                    f32::from_bits(cpu.reg(Reg::R3)),
                );
                Ok(true)
            }
            GlesFuncId::GlUniform4f => {
                let f = resolve_host!("glUniform4f", extern "C" fn(i32, f32, f32, f32, f32));
                let sp = GuestAddr::new(cpu.sp());
                let v3 = f32::from_bits(mem.read_u32(sp)?);
                f(
                    cpu.reg(Reg::R0) as i32,
                    f32::from_bits(cpu.reg(Reg::R1)),
                    f32::from_bits(cpu.reg(Reg::R2)),
                    f32::from_bits(cpu.reg(Reg::R3)),
                    v3,
                );
                Ok(true)
            }
            GlesFuncId::GlUniform2fv => {
                let f = resolve_host!("glUniform2fv", extern "C" fn(i32, i32, *const f32));
                let ptr = Self::guest_ptr_const(mem, cpu.reg(Reg::R2)) as *const f32;
                f(cpu.reg(Reg::R0) as i32, cpu.reg(Reg::R1) as i32, ptr);
                Ok(true)
            }
            GlesFuncId::GlUniform3fv => {
                let f = resolve_host!("glUniform3fv", extern "C" fn(i32, i32, *const f32));
                let ptr = Self::guest_ptr_const(mem, cpu.reg(Reg::R2)) as *const f32;
                f(cpu.reg(Reg::R0) as i32, cpu.reg(Reg::R1) as i32, ptr);
                Ok(true)
            }
            GlesFuncId::GlUniform4fv => {
                let f = resolve_host!("glUniform4fv", extern "C" fn(i32, i32, *const f32));
                let ptr = Self::guest_ptr_const(mem, cpu.reg(Reg::R2)) as *const f32;
                f(cpu.reg(Reg::R0) as i32, cpu.reg(Reg::R1) as i32, ptr);
                Ok(true)
            }
            GlesFuncId::GlUniformMatrix4fv => {
                let f = resolve_host!("glUniformMatrix4fv", extern "C" fn(i32, i32, u8, *const f32));
                let ptr = Self::guest_ptr_const(mem, cpu.reg(Reg::R3)) as *const f32;
                f(
                    cpu.reg(Reg::R0) as i32,
                    cpu.reg(Reg::R1) as i32,
                    cpu.reg(Reg::R2) as u8,
                    ptr,
                );
                Ok(true)
            }
            GlesFuncId::GlGetError => {
                let f = resolve_host!("glGetError", extern "C" fn() -> u32);
                cpu.set_reg(Reg::R0, f());
                Ok(true)
            }
            _ => Ok(false),
        }
    }
}

impl SymbolResolver for GlesBridge {
    fn resolve(&self, name: &str) -> Option<GuestAddr> {
        self.symbol_table.get(name).copied()
    }
}
