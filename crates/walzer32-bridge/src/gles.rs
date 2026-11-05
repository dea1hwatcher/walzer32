use std::collections::HashMap;
use walzer32_core::{GuestAddr, Memory, MemoryError, Reg};
use walzer32_elf::SymbolResolver;

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

    // GLES State & Clear
    GlClearColor = 20,
    GlClear = 21,
    GlViewport = 22,
    GlEnable = 23,
    GlDisable = 24,

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

    // GLES Buffers & Drawing
    GlGenBuffers = 40,
    GlBindBuffer = 41,
    GlBufferData = 42,
    GlEnableVertexAttribArray = 43,
    GlVertexAttribPointer = 44,
    GlDrawArrays = 45,
    GlDrawElements = 46,

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

    // GLES Queries & Uniforms
    GlGetString = 60,
    GlGetUniformLocation = 61,
    GlUniform1i = 62,
    GlUniform4f = 63,
    GlGetError = 64,

    // EGL KHR Sync Fences
    EglCreateSyncKHR = 70,
    EglClientWaitSyncKHR = 71,
    EglDestroySyncKHR = 72,
    EglGetSyncAttribKHR = 73,
    EglWaitSyncKHR = 74,

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

            20 => Some(Self::GlClearColor),
            21 => Some(Self::GlClear),
            22 => Some(Self::GlViewport),
            23 => Some(Self::GlEnable),
            24 => Some(Self::GlDisable),

            30 => Some(Self::GlCreateShader),
            31 => Some(Self::GlShaderSource),
            32 => Some(Self::GlCompileShader),
            33 => Some(Self::GlGetShaderiv),
            34 => Some(Self::GlCreateProgram),
            35 => Some(Self::GlAttachShader),
            36 => Some(Self::GlLinkProgram),
            37 => Some(Self::GlGetProgramiv),
            38 => Some(Self::GlUseProgram),

            40 => Some(Self::GlGenBuffers),
            41 => Some(Self::GlBindBuffer),
            42 => Some(Self::GlBufferData),
            43 => Some(Self::GlEnableVertexAttribArray),
            44 => Some(Self::GlVertexAttribPointer),
            45 => Some(Self::GlDrawArrays),
            46 => Some(Self::GlDrawElements),

            50 => Some(Self::GlGenTextures),
            51 => Some(Self::GlBindTexture),
            52 => Some(Self::GlTexImage2D),
            53 => Some(Self::GlTexParameteri),
            54 => Some(Self::GlActiveTexture),
            55 => Some(Self::GlGenFramebuffers),
            56 => Some(Self::GlBindFramebuffer),
            57 => Some(Self::GlFramebufferTexture2D),
            58 => Some(Self::GlCheckFramebufferStatus),

            60 => Some(Self::GlGetString),
            61 => Some(Self::GlGetUniformLocation),
            62 => Some(Self::GlUniform1i),
            63 => Some(Self::GlUniform4f),
            64 => Some(Self::GlGetError),

            70 => Some(Self::EglCreateSyncKHR),
            71 => Some(Self::EglClientWaitSyncKHR),
            72 => Some(Self::EglDestroySyncKHR),
            73 => Some(Self::EglGetSyncAttribKHR),
            74 => Some(Self::EglWaitSyncKHR),

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
        };

        bridge.register_known_symbols();
        bridge
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
            ("glClear", GlesFuncId::GlClear),
            ("glViewport", GlesFuncId::GlViewport),
            ("glEnable", GlesFuncId::GlEnable),
            ("glDisable", GlesFuncId::GlDisable),
            ("glCreateShader", GlesFuncId::GlCreateShader),
            ("glShaderSource", GlesFuncId::GlShaderSource),
            ("glCompileShader", GlesFuncId::GlCompileShader),
            ("glGetShaderiv", GlesFuncId::GlGetShaderiv),
            ("glCreateProgram", GlesFuncId::GlCreateProgram),
            ("glAttachShader", GlesFuncId::GlAttachShader),
            ("glLinkProgram", GlesFuncId::GlLinkProgram),
            ("glGetProgramiv", GlesFuncId::GlGetProgramiv),
            ("glUseProgram", GlesFuncId::GlUseProgram),
            ("glGenBuffers", GlesFuncId::GlGenBuffers),
            ("glBindBuffer", GlesFuncId::GlBindBuffer),
            ("glBufferData", GlesFuncId::GlBufferData),
            ("glEnableVertexAttribArray", GlesFuncId::GlEnableVertexAttribArray),
            ("glVertexAttribPointer", GlesFuncId::GlVertexAttribPointer),
            ("glDrawArrays", GlesFuncId::GlDrawArrays),
            ("glDrawElements", GlesFuncId::GlDrawElements),
            ("glGenTextures", GlesFuncId::GlGenTextures),
            ("glBindTexture", GlesFuncId::GlBindTexture),
            ("glTexImage2D", GlesFuncId::GlTexImage2D),
            ("glTexParameteri", GlesFuncId::GlTexParameteri),
            ("glActiveTexture", GlesFuncId::GlActiveTexture),
            ("glGenFramebuffers", GlesFuncId::GlGenFramebuffers),
            ("glBindFramebuffer", GlesFuncId::GlBindFramebuffer),
            ("glFramebufferTexture2D", GlesFuncId::GlFramebufferTexture2D),
            ("glCheckFramebufferStatus", GlesFuncId::GlCheckFramebufferStatus),
            ("glGetString", GlesFuncId::GlGetString),
            ("glGetUniformLocation", GlesFuncId::GlGetUniformLocation),
            ("glUniform1i", GlesFuncId::GlUniform1i),
            ("glUniform4f", GlesFuncId::GlUniform4f),
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
            GlesFuncId::GlClearColor,
            GlesFuncId::GlClear,
            GlesFuncId::GlViewport,
            GlesFuncId::GlEnable,
            GlesFuncId::GlDisable,
            GlesFuncId::GlCreateShader,
            GlesFuncId::GlShaderSource,
            GlesFuncId::GlCompileShader,
            GlesFuncId::GlGetShaderiv,
            GlesFuncId::GlCreateProgram,
            GlesFuncId::GlAttachShader,
            GlesFuncId::GlLinkProgram,
            GlesFuncId::GlGetProgramiv,
            GlesFuncId::GlUseProgram,
            GlesFuncId::GlGenBuffers,
            GlesFuncId::GlBindBuffer,
            GlesFuncId::GlBufferData,
            GlesFuncId::GlEnableVertexAttribArray,
            GlesFuncId::GlVertexAttribPointer,
            GlesFuncId::GlDrawArrays,
            GlesFuncId::GlDrawElements,
            GlesFuncId::GlGenTextures,
            GlesFuncId::GlBindTexture,
            GlesFuncId::GlTexImage2D,
            GlesFuncId::GlTexParameteri,
            GlesFuncId::GlActiveTexture,
            GlesFuncId::GlGenFramebuffers,
            GlesFuncId::GlBindFramebuffer,
            GlesFuncId::GlFramebufferTexture2D,
            GlesFuncId::GlCheckFramebufferStatus,
            GlesFuncId::GlGetString,
            GlesFuncId::GlGetUniformLocation,
            GlesFuncId::GlUniform1i,
            GlesFuncId::GlUniform4f,
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
                    let mut name_bytes = Vec::new();
                    let mut cur = proc_ptr;
                    loop {
                        let b = mem.read_u8(cur)?;
                        if b == 0 {
                            break;
                        }
                        name_bytes.push(b);
                        cur = cur.add(1);
                    }
                    let name = String::from_utf8_lossy(&name_bytes);
                    let resolved = self.symbol_table.get(name.as_ref()).copied().map(|a| a.as_u32()).unwrap_or(0);
                    cpu.set_reg(Reg::R0, resolved);
                }
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
                let addr = self.string_heap;
                mem.write_bytes(addr, string_val.as_bytes())?;
                self.string_heap = addr.add((string_val.len() as u32 + 3) & !3);
                cpu.set_reg(Reg::R0, addr.as_u32());
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
                let ctx_id = self.current_context_id(cpu);
                if let Some(ctx) = self.egl_contexts.get_mut(&ctx_id) {
                    if target == 0x8892 { // GL_ARRAY_BUFFER
                        ctx.bound_array_buffer = buffer;
                    } else if target == 0x8893 { // GL_ELEMENT_ARRAY_BUFFER
                        ctx.bound_element_array_buffer = buffer;
                    }
                }
            }
            GlesFuncId::GlBufferData => {
                let target = cpu.reg(Reg::R0);
                let size = cpu.reg(Reg::R1) as usize;
                let data_ptr = GuestAddr::new(cpu.reg(Reg::R2));
                let usage = cpu.reg(Reg::R3);

                let ctx_id = self.current_context_id(cpu);
                let group_id = self.current_share_group_id(cpu);

                let buffer_id = if let Some(ctx) = self.egl_contexts.get(&ctx_id) {
                    if target == 0x8892 {
                        ctx.bound_array_buffer
                    } else {
                        ctx.bound_element_array_buffer
                    }
                } else {
                    0
                };

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

                let addr = self.string_heap;
                mem.write_bytes(addr, string_val.as_bytes())?;
                self.string_heap = addr.add((string_val.len() as u32 + 3) & !3);
                cpu.set_reg(Reg::R0, addr.as_u32());
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
}

impl SymbolResolver for GlesBridge {
    fn resolve(&self, name: &str) -> Option<GuestAddr> {
        self.symbol_table.get(name).copied()
    }
}
