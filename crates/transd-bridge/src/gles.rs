use std::collections::HashMap;
use transd_core::{GuestAddr, Memory, MemoryError, Reg};
use transd_elf::SymbolResolver;

pub const GLES_SVC_MAGIC: u32 = 0xE60000; // 'G' << 16

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum GlesFuncId {
    // EGL
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

    // GLES Textures
    GlGenTextures = 50,
    GlBindTexture = 51,
    GlTexImage2D = 52,
    GlTexParameteri = 53,

    // GLES Queries & Uniforms
    GlGetString = 60,
    GlGetUniformLocation = 61,
    GlUniform1i = 62,
    GlUniform4f = 63,
    GlGetError = 64,
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
            60 => Some(Self::GlGetString),
            61 => Some(Self::GlGetUniformLocation),
            62 => Some(Self::GlUniform1i),
            63 => Some(Self::GlUniform4f),
            64 => Some(Self::GlGetError),
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EglSurfaceState {
    pub surface_id: u32,
    pub native_window: u32,
    pub width: u32,
    pub height: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EglContextState {
    pub context_id: u32,
    pub client_version: u32,
}

/// Provides EGL & OpenGL ES 2.0 / 3.0 Passthrough Stubs for 32-bit guest applications
pub struct GlesBridge {
    pub stub_base: GuestAddr,
    pub symbol_table: HashMap<String, GuestAddr>,
    pub string_heap: GuestAddr,

    // Execution statistics & state
    pub draw_calls: Vec<DrawCallRecord>,
    pub clear_color: [f32; 4],
    pub viewport: [i32; 4],
    pub next_resource_id: u32,
    pub active_program: u32,
    pub swap_count: u64,

    // EGL Hardware Surface & Context Binding
    pub egl_surfaces: HashMap<u32, EglSurfaceState>,
    pub egl_contexts: HashMap<u32, EglContextState>,
    pub active_draw_surface: u32,
    pub active_read_surface: u32,
    pub active_context: u32,
    pub bound_native_window: u32,
}

impl GlesBridge {
    pub fn new(stub_base: GuestAddr, string_heap: GuestAddr) -> Self {
        let mut bridge = Self {
            stub_base,
            symbol_table: HashMap::new(),
            string_heap,
            draw_calls: Vec::new(),
            clear_color: [0.0; 4],
            viewport: [0; 4],
            next_resource_id: 1,
            active_program: 0,
            swap_count: 0,
            egl_surfaces: HashMap::new(),
            egl_contexts: HashMap::new(),
            active_draw_surface: 0,
            active_read_surface: 0,
            active_context: 0,
            bound_native_window: 0,
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
        for &id in &[
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
            GlesFuncId::GlGetString,
            GlesFuncId::GlGetUniformLocation,
            GlesFuncId::GlUniform1i,
            GlesFuncId::GlUniform4f,
            GlesFuncId::GlGetError,
        ] {
            let addr = self.stub_base.add((id as u32) * 8);
            let svc_code = 0xEF00_0000 | (GLES_SVC_MAGIC | (id as u32));
            let bx_lr = 0xE12F_FF1E;

            mem.write_u32(addr, svc_code)?;
            mem.write_u32(addr.add(4), bx_lr)?;
        }
        Ok(())
    }

    /// Handles an incoming OpenGL ES or EGL SVC call
    pub fn handle_svc(
        &mut self,
        svc_imm: u32,
        cpu: &mut transd_core::CpuState,
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
            // --- EGL Functions ---
            GlesFuncId::EglGetDisplay => {
                // EGLDisplay eglGetDisplay(EGLNativeDisplayType display_id)
                cpu.set_reg(Reg::R0, 0x1000); // Non-zero EGLDisplay handle
            }
            GlesFuncId::EglInitialize => {
                // EGLBoolean eglInitialize(EGLDisplay dpy, EGLint *major, EGLint *minor)
                let major_ptr = GuestAddr::new(cpu.reg(Reg::R1));
                let minor_ptr = GuestAddr::new(cpu.reg(Reg::R2));
                if major_ptr.as_u32() != 0 {
                    mem.write_u32(major_ptr, 1)?; // EGL 1.5
                }
                if minor_ptr.as_u32() != 0 {
                    mem.write_u32(minor_ptr, 5)?;
                }
                cpu.set_reg(Reg::R0, 1); // EGL_TRUE
            }
            GlesFuncId::EglChooseConfig => {
                let configs_ptr = GuestAddr::new(cpu.reg(Reg::R2));
                let num_config_ptr = GuestAddr::new(cpu.reg(Reg::R4));
                if configs_ptr.as_u32() != 0 {
                    mem.write_u32(configs_ptr, 0x2001)?; // Valid EGLConfig handle
                }
                if num_config_ptr.as_u32() != 0 {
                    mem.write_u32(num_config_ptr, 1)?;
                }
                cpu.set_reg(Reg::R0, 1);
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
                        native_window,
                        width: 1920,
                        height: 1080,
                    },
                );
                cpu.set_reg(Reg::R0, surface_id);
            }
            GlesFuncId::EglCreateContext => {
                let context_id = self.next_resource_id;
                self.next_resource_id += 1;
                self.egl_contexts.insert(
                    context_id,
                    EglContextState {
                        context_id,
                        client_version: 3,
                    },
                );
                cpu.set_reg(Reg::R0, context_id);
            }
            GlesFuncId::EglMakeCurrent => {
                self.active_draw_surface = cpu.reg(Reg::R1);
                self.active_read_surface = cpu.reg(Reg::R2);
                self.active_context = cpu.reg(Reg::R3);
                cpu.set_reg(Reg::R0, 1);
            }
            GlesFuncId::EglSwapBuffers => {
                self.swap_count += 1;
                cpu.set_reg(Reg::R0, 1);
            }
            GlesFuncId::EglQueryString => {
                let name = cpu.reg(Reg::R1);
                let string_val = match name {
                    0x308D => "OpenGL_ES\0", // EGL_CLIENT_APIS
                    0x3053 => "Google DeepMind / Transd\0", // EGL_VENDOR
                    0x3054 => "1.4 Transd Android\0", // EGL_VERSION
                    0x3055 => "EGL_KHR_image_base EGL_KHR_gl_texture_2D_image EGL_ANDROID_native_fence_sync EGL_KHR_fence_sync\0",
                    _ => "Transd EGL\0",
                };
                let addr = self.string_heap;
                mem.write_bytes(addr, string_val.as_bytes())?;
                self.string_heap = addr.add((string_val.len() as u32 + 3) & !3);
                cpu.set_reg(Reg::R0, addr.as_u32());
            }

            // --- GLES State ---
            GlesFuncId::GlClearColor => {
                // glClearColor(red, green, blue, alpha)
                // In ARM AAPCS, float arguments passed in s0-s3 or r0-r3
                let r = f32::from_bits(cpu.reg(Reg::R0));
                let g = f32::from_bits(cpu.reg(Reg::R1));
                let b = f32::from_bits(cpu.reg(Reg::R2));
                let a = f32::from_bits(cpu.reg(Reg::R3));
                self.clear_color = [r, g, b, a];
            }
            GlesFuncId::GlClear => {
                // glClear(GLbitfield mask)
            }
            GlesFuncId::GlViewport => {
                // glViewport(x, y, width, height)
                let x = cpu.reg(Reg::R0) as i32;
                let y = cpu.reg(Reg::R1) as i32;
                let w = cpu.reg(Reg::R2) as i32;
                let h = cpu.reg(Reg::R3) as i32;
                self.viewport = [x, y, w, h];
            }

            // --- GLES Shaders & Programs ---
            GlesFuncId::GlCreateShader | GlesFuncId::GlCreateProgram => {
                let id = self.next_resource_id;
                self.next_resource_id += 1;
                cpu.set_reg(Reg::R0, id);
            }
            GlesFuncId::GlGetShaderiv | GlesFuncId::GlGetProgramiv => {
                // Always report compile/link status = 1 (GL_TRUE)
                let params_ptr = GuestAddr::new(cpu.reg(Reg::R2));
                mem.write_u32(params_ptr, 1)?;
            }
            GlesFuncId::GlUseProgram => {
                self.active_program = cpu.reg(Reg::R0);
            }

            // --- GLES Buffers & Textures ---
            GlesFuncId::GlGenBuffers | GlesFuncId::GlGenTextures => {
                let n = cpu.reg(Reg::R0);
                let ptr = GuestAddr::new(cpu.reg(Reg::R1));
                for i in 0..n {
                    let id = self.next_resource_id;
                    self.next_resource_id += 1;
                    mem.write_u32(ptr.add(i * 4), id)?;
                }
            }

            // --- GLES Drawing ---
            GlesFuncId::GlDrawArrays => {
                // glDrawArrays(GLenum mode, GLint first, GLsizei count)
                let mode = cpu.reg(Reg::R0);
                let first = cpu.reg(Reg::R1) as i32;
                let count = cpu.reg(Reg::R2) as i32;

                self.draw_calls.push(DrawCallRecord { mode, first, count });
            }
            GlesFuncId::GlDrawElements => {
                // glDrawElements(GLenum mode, GLsizei count, GLenum type, const void *indices)
                let mode = cpu.reg(Reg::R0);
                let count = cpu.reg(Reg::R1) as i32;

                self.draw_calls.push(DrawCallRecord { mode, first: 0, count });
            }

            // --- GLES Queries ---
            GlesFuncId::GlGetString => {
                let name = cpu.reg(Reg::R0);
                let string_val = match name {
                    GL_VENDOR => "Transd / Google DeepMind\0",
                    GL_RENDERER => "Transd Adreno/Mali Passthrough Engine\0",
                    GL_VERSION => "OpenGL ES 3.2 Transd\0",
                    GL_SHADING_LANGUAGE_VERSION => "OpenGL ES GLSL ES 3.20\0",
                    _ => "Transd Generic\0",
                };

                let addr = self.string_heap;
                mem.write_bytes(addr, string_val.as_bytes())?;
                self.string_heap = addr.add((string_val.len() as u32 + 3) & !3);

                cpu.set_reg(Reg::R0, addr.as_u32());
            }
            GlesFuncId::GlGetError => {
                cpu.set_reg(Reg::R0, 0); // GL_NO_ERROR
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
