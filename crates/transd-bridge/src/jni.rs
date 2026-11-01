use std::collections::HashMap;
use transd_core::{GuestAddr, Memory, MemoryError, Reg};

pub const JNI_SVC_MAGIC: u32 = 0x4A0000; // 'J' << 16

pub const JNI_VERSION_1_1: u32 = 0x00010001;
pub const JNI_VERSION_1_2: u32 = 0x00010002;
pub const JNI_VERSION_1_4: u32 = 0x00010004;
pub const JNI_VERSION_1_6: u32 = 0x00010006;

pub const JNI_OK: u32 = 0;
pub const JNI_ERR: u32 = 0xFFFF_FFFF;
pub const JNI_TRUE: u8 = 1;
pub const JNI_FALSE: u8 = 0;

/// Standard JNI Function Table Indices (per Oracle JNI / Android AOSP spec)
pub mod jni_idx {
    pub const GET_VERSION: u32 = 4;
    pub const DEFINE_CLASS: u32 = 5;
    pub const FIND_CLASS: u32 = 6;
    pub const FROM_REFLECTED_METHOD: u32 = 7;
    pub const FROM_REFLECTED_FIELD: u32 = 8;
    pub const TO_REFLECTED_METHOD: u32 = 9;
    pub const GET_SUPERCLASS: u32 = 10;
    pub const IS_ASSIGNABLE_FROM: u32 = 11;
    pub const TO_REFLECTED_FIELD: u32 = 12;
    pub const THROW: u32 = 13;
    pub const THROW_NEW: u32 = 14;
    pub const EXCEPTION_OCCURRED: u32 = 15;
    pub const EXCEPTION_DESCRIBE: u32 = 16;
    pub const EXCEPTION_CLEAR: u32 = 17;
    pub const FATAL_ERROR: u32 = 18;
    pub const PUSH_LOCAL_FRAME: u32 = 19;
    pub const POP_LOCAL_FRAME: u32 = 20;
    pub const NEW_GLOBAL_REF: u32 = 21;
    pub const DELETE_GLOBAL_REF: u32 = 22;
    pub const DELETE_LOCAL_REF: u32 = 23;
    pub const IS_SAME_OBJECT: u32 = 24;
    pub const NEW_LOCAL_REF: u32 = 25;
    pub const ENSURE_LOCAL_CAPACITY: u32 = 26;
    pub const ALLOC_OBJECT: u32 = 27;
    pub const NEW_OBJECT: u32 = 28;
    pub const NEW_OBJECT_A: u32 = 30;
    pub const GET_OBJECT_CLASS: u32 = 31;
    pub const IS_INSTANCE_OF: u32 = 32;
    pub const GET_METHOD_ID: u32 = 33;
    pub const CALL_OBJECT_METHOD: u32 = 34;
    pub const CALL_BOOLEAN_METHOD: u32 = 37;
    pub const CALL_BYTE_METHOD: u32 = 40;
    pub const CALL_CHAR_METHOD: u32 = 43;
    pub const CALL_SHORT_METHOD: u32 = 46;
    pub const CALL_INT_METHOD: u32 = 49;
    pub const CALL_INT_METHOD_A: u32 = 51;
    pub const CALL_LONG_METHOD: u32 = 52;
    pub const CALL_LONG_METHOD_A: u32 = 54;
    pub const CALL_FLOAT_METHOD: u32 = 55;
    pub const CALL_DOUBLE_METHOD: u32 = 58;
    pub const CALL_VOID_METHOD: u32 = 61;
    pub const CALL_VOID_METHOD_A: u32 = 63;
    pub const CALL_NONVIRTUAL_OBJECT_METHOD: u32 = 64;
    pub const GET_FIELD_ID: u32 = 94;
    pub const GET_OBJECT_FIELD: u32 = 95;
    pub const GET_BOOLEAN_FIELD: u32 = 96;
    pub const GET_BYTE_FIELD: u32 = 97;
    pub const GET_CHAR_FIELD: u32 = 98;
    pub const GET_SHORT_FIELD: u32 = 99;
    pub const GET_INT_FIELD: u32 = 100;
    pub const GET_LONG_FIELD: u32 = 101;
    pub const GET_FLOAT_FIELD: u32 = 102;
    pub const GET_DOUBLE_FIELD: u32 = 103;
    pub const SET_OBJECT_FIELD: u32 = 104;
    pub const SET_BOOLEAN_FIELD: u32 = 105;
    pub const SET_BYTE_FIELD: u32 = 106;
    pub const SET_CHAR_FIELD: u32 = 107;
    pub const SET_SHORT_FIELD: u32 = 108;
    pub const SET_INT_FIELD: u32 = 109;
    pub const SET_LONG_FIELD: u32 = 110;
    pub const SET_FLOAT_FIELD: u32 = 111;
    pub const SET_DOUBLE_FIELD: u32 = 112;
    pub const GET_STATIC_METHOD_ID: u32 = 113;
    pub const CALL_STATIC_OBJECT_METHOD: u32 = 114;
    pub const CALL_STATIC_BOOLEAN_METHOD: u32 = 117;
    pub const CALL_STATIC_BYTE_METHOD: u32 = 120;
    pub const CALL_STATIC_CHAR_METHOD: u32 = 123;
    pub const CALL_STATIC_SHORT_METHOD: u32 = 126;
    pub const CALL_STATIC_INT_METHOD: u32 = 129;
    pub const CALL_STATIC_LONG_METHOD: u32 = 132;
    pub const CALL_STATIC_FLOAT_METHOD: u32 = 135;
    pub const CALL_STATIC_DOUBLE_METHOD: u32 = 138;
    pub const CALL_STATIC_VOID_METHOD: u32 = 141;
    pub const GET_STATIC_FIELD_ID: u32 = 144;
    pub const GET_STATIC_OBJECT_FIELD: u32 = 145;
    pub const GET_STATIC_BOOLEAN_FIELD: u32 = 146;
    pub const GET_STATIC_BYTE_FIELD: u32 = 147;
    pub const GET_STATIC_CHAR_FIELD: u32 = 148;
    pub const GET_STATIC_SHORT_FIELD: u32 = 149;
    pub const GET_STATIC_INT_FIELD: u32 = 150;
    pub const GET_STATIC_LONG_FIELD: u32 = 151;
    pub const GET_STATIC_FLOAT_FIELD: u32 = 152;
    pub const GET_STATIC_DOUBLE_FIELD: u32 = 153;
    pub const SET_STATIC_OBJECT_FIELD: u32 = 154;
    pub const SET_STATIC_BOOLEAN_FIELD: u32 = 155;
    pub const SET_STATIC_INT_FIELD: u32 = 159;
    pub const SET_STATIC_LONG_FIELD: u32 = 160;
    pub const NEW_STRING: u32 = 163;
    pub const GET_STRING_LENGTH: u32 = 164;
    pub const GET_STRING_CHARS: u32 = 165;
    pub const RELEASE_STRING_CHARS: u32 = 166;
    pub const NEW_STRING_UTF: u32 = 167;
    pub const GET_STRING_UTF_LENGTH: u32 = 168;
    pub const GET_STRING_UTF_CHARS: u32 = 169;
    pub const RELEASE_STRING_UTF_CHARS: u32 = 170;
    pub const GET_ARRAY_LENGTH: u32 = 171;
    pub const NEW_OBJECT_ARRAY: u32 = 172;
    pub const GET_OBJECT_ARRAY_ELEMENT: u32 = 173;
    pub const SET_OBJECT_ARRAY_ELEMENT: u32 = 174;
    pub const NEW_BOOLEAN_ARRAY: u32 = 175;
    pub const NEW_BYTE_ARRAY: u32 = 176;
    pub const NEW_CHAR_ARRAY: u32 = 177;
    pub const NEW_SHORT_ARRAY: u32 = 178;
    pub const NEW_INT_ARRAY: u32 = 179;
    pub const NEW_LONG_ARRAY: u32 = 180;
    pub const NEW_FLOAT_ARRAY: u32 = 181;
    pub const NEW_DOUBLE_ARRAY: u32 = 182;
    pub const GET_BOOLEAN_ARRAY_ELEMENTS: u32 = 183;
    pub const GET_BYTE_ARRAY_ELEMENTS: u32 = 184;
    pub const GET_CHAR_ARRAY_ELEMENTS: u32 = 185;
    pub const GET_SHORT_ARRAY_ELEMENTS: u32 = 186;
    pub const GET_INT_ARRAY_ELEMENTS: u32 = 187;
    pub const GET_LONG_ARRAY_ELEMENTS: u32 = 188;
    pub const GET_FLOAT_ARRAY_ELEMENTS: u32 = 189;
    pub const GET_DOUBLE_ARRAY_ELEMENTS: u32 = 190;
    pub const RELEASE_BOOLEAN_ARRAY_ELEMENTS: u32 = 191;
    pub const RELEASE_BYTE_ARRAY_ELEMENTS: u32 = 192;
    pub const RELEASE_CHAR_ARRAY_ELEMENTS: u32 = 193;
    pub const RELEASE_SHORT_ARRAY_ELEMENTS: u32 = 194;
    pub const RELEASE_INT_ARRAY_ELEMENTS: u32 = 195;
    pub const RELEASE_LONG_ARRAY_ELEMENTS: u32 = 196;
    pub const RELEASE_FLOAT_ARRAY_ELEMENTS: u32 = 197;
    pub const RELEASE_DOUBLE_ARRAY_ELEMENTS: u32 = 198;
    pub const GET_BOOLEAN_ARRAY_REGION: u32 = 199;
    pub const GET_BYTE_ARRAY_REGION: u32 = 200;
    pub const GET_INT_ARRAY_REGION: u32 = 203;
    pub const SET_BOOLEAN_ARRAY_REGION: u32 = 207;
    pub const SET_BYTE_ARRAY_REGION: u32 = 208;
    pub const SET_INT_ARRAY_REGION: u32 = 211;
    pub const REGISTER_NATIVES: u32 = 215;
    pub const UNREGISTER_NATIVES: u32 = 216;
    pub const MONITOR_ENTER: u32 = 217;
    pub const MONITOR_EXIT: u32 = 218;
    pub const GET_JAVA_VM: u32 = 219;
    pub const GET_PRIMITIVE_ARRAY_CRITICAL: u32 = 222;
    pub const RELEASE_PRIMITIVE_ARRAY_CRITICAL: u32 = 223;
    pub const GET_STRING_CRITICAL: u32 = 224;
    pub const RELEASE_STRING_CRITICAL: u32 = 225;
    pub const NEW_WEAK_GLOBAL_REF: u32 = 226;
    pub const DELETE_WEAK_GLOBAL_REF: u32 = 227;
    pub const EXCEPTION_CHECK: u32 = 228;
    pub const NEW_DIRECT_BYTE_BUFFER: u32 = 229;
    pub const GET_DIRECT_BUFFER_ADDRESS: u32 = 230;
    pub const GET_DIRECT_BUFFER_CAPACITY: u32 = 231;
}

/// JavaVM Function Table Indices
pub mod vm_idx {
    pub const DESTROY_JAVA_VM: u32 = 3;
    pub const ATTACH_CURRENT_THREAD: u32 = 4;
    pub const DETACH_CURRENT_THREAD: u32 = 5;
    pub const GET_ENV: u32 = 6;
    pub const ATTACH_CURRENT_THREAD_AS_DAEMON: u32 = 7;
}

#[derive(Debug, Clone)]
pub struct RegisteredNativeMethod {
    pub name: String,
    pub signature: String,
    pub fn_ptr: GuestAddr,
}

#[derive(Debug, Clone, PartialEq)]
pub enum JniValue {
    Boolean(bool),
    Byte(i8),
    Char(u16),
    Short(i16),
    Int(i32),
    Long(i64),
    Float(f32),
    Double(f64),
    Object(u32),
}

#[derive(Debug, Clone)]
pub struct MethodDescriptor {
    pub class_handle: u32,
    pub name: String,
    pub signature: String,
    pub is_static: bool,
}

#[derive(Debug, Clone)]
pub struct FieldDescriptor {
    pub class_handle: u32,
    pub name: String,
    pub signature: String,
    pub is_static: bool,
}

#[derive(Debug, Clone)]
pub struct DirectBufferInfo {
    pub addr: GuestAddr,
    pub capacity: usize,
}

/// Manages JNI 32-bit environment, object handles, and JNI function trampolines
pub struct JniBridge {
    pub env_ptr: GuestAddr,
    pub interface_table_addr: GuestAddr,
    pub jni_stubs_addr: GuestAddr,

    pub vm_ptr: GuestAddr,
    pub vm_table_addr: GuestAddr,
    pub vm_stubs_addr: GuestAddr,

    /// Handle tables for objects, classes, strings, and methods
    pub next_handle: u32,
    pub strings: HashMap<u32, String>,
    pub string_addrs: HashMap<u32, GuestAddr>,
    pub classes: HashMap<String, u32>,
    pub methods: HashMap<u32, MethodDescriptor>,
    pub field_descriptors: HashMap<u32, FieldDescriptor>,
    pub field_values: HashMap<(u32, u32), JniValue>,
    pub global_refs: HashMap<u32, u32>,
    pub registered_natives: Vec<RegisteredNativeMethod>,
    pub string_heap_cur: GuestAddr,
    pub pending_exception: u32,
    /// Byte/Primitive arrays: handle -> (GuestAddr, element_count, element_size)
    pub arrays: HashMap<u32, (GuestAddr, usize, usize)>,
    pub direct_buffers: HashMap<u32, DirectBufferInfo>,
    pub local_frames: Vec<Vec<u32>>,
    pub weak_global_refs: HashMap<u32, u32>,
    pub package_name: String,
    pub app_data_dir: String,
}

impl JniBridge {
    pub fn new(base: GuestAddr) -> Self {
        let env_ptr = base;
        let interface_table_addr = base.add(4);
        let jni_stubs_addr = base.add(1024);

        let vm_ptr = base.add(3072);
        let vm_table_addr = base.add(3076);
        let vm_stubs_addr = base.add(3140);

        let string_heap_cur = base.add(4096);

        let mut bridge = Self {
            env_ptr,
            interface_table_addr,
            jni_stubs_addr,
            vm_ptr,
            vm_table_addr,
            vm_stubs_addr,
            next_handle: 100,
            strings: HashMap::new(),
            string_addrs: HashMap::new(),
            classes: HashMap::new(),
            methods: HashMap::new(),
            field_descriptors: HashMap::new(),
            field_values: HashMap::new(),
            global_refs: HashMap::new(),
            local_frames: vec![Vec::new()],
            weak_global_refs: HashMap::new(),
            registered_natives: Vec::new(),
            string_heap_cur,
            pending_exception: 0,
            arrays: HashMap::new(),
            direct_buffers: HashMap::new(),
            package_name: "com.transd.app".to_string(),
            app_data_dir: "/data/data/com.transd.app/files".to_string(),
        };

        bridge.init_default_environment();
        bridge
    }

    fn init_default_environment(&mut self) {
        // Pre-intern standard Android/Java classes
        self.intern_class("java/lang/Class".to_string());
        self.intern_class("java/lang/String".to_string());
        self.intern_class("java/lang/Object".to_string());
        self.intern_class("android/app/Activity".to_string());
        self.intern_class("android/content/Context".to_string());
        self.intern_class("android/os/Build".to_string());
        self.intern_class("android/os/Build$VERSION".to_string());
    }

    /// Initializes JNIEnv and JavaVM tables in guest memory
    pub fn install(&self, mem: &mut impl Memory) -> Result<(), MemoryError> {
        // 1. Write env_ptr -> interface_table_addr
        mem.write_u32(self.env_ptr, self.interface_table_addr.as_u32())?;

        // 2. Populate 250 JNI function entries
        for idx in 0..250u32 {
            let stub_addr = self.jni_stubs_addr.add(idx * 8);
            let table_entry = self.interface_table_addr.add(idx * 4);

            mem.write_u32(table_entry, stub_addr.as_u32())?;

            // Stub: SVC #(JNI_SVC_MAGIC | idx); BX lr
            let svc_code = 0xEF00_0000 | (JNI_SVC_MAGIC | idx);
            let bx_lr = 0xE12F_FF1E;
            mem.write_u32(stub_addr, svc_code)?;
            mem.write_u32(stub_addr.add(4), bx_lr)?;
        }

        // 3. Write vm_ptr -> vm_table_addr
        mem.write_u32(self.vm_ptr, self.vm_table_addr.as_u32())?;

        // 4. Populate JavaVM entries
        for idx in 0..16u32 {
            let stub_addr = self.vm_stubs_addr.add(idx * 8);
            let table_entry = self.vm_table_addr.add(idx * 4);

            mem.write_u32(table_entry, stub_addr.as_u32())?;

            // Stub: SVC #(JNI_SVC_MAGIC | 0x8000 | idx); BX lr
            let svc_code = 0xEF00_0000 | (JNI_SVC_MAGIC | 0x8000 | idx);
            let bx_lr = 0xE12F_FF1E;
            mem.write_u32(stub_addr, svc_code)?;
            mem.write_u32(stub_addr.add(4), bx_lr)?;
        }

        Ok(())
    }

    /// Registers a field value on an object or class
    pub fn set_field_value(&mut self, target: u32, field_id: u32, value: JniValue) {
        self.field_values.insert((target, field_id), value);
    }

    /// Retrieves a field value
    pub fn get_field_value(&self, target: u32, field_id: u32) -> Option<&JniValue> {
        self.field_values.get(&(target, field_id))
    }

    /// Handles a JNI or JavaVM SVC call
    pub fn handle_svc(
        &mut self,
        svc_imm: u32,
        cpu: &mut transd_core::CpuState,
        mem: &mut impl Memory,
    ) -> Result<bool, MemoryError> {
        if (svc_imm & 0xFF0000) != JNI_SVC_MAGIC {
            return Ok(false);
        }

        let is_vm = (svc_imm & 0x8000) != 0;
        let func_idx = svc_imm & 0x7FFF;

        if is_vm {
            self.handle_vm_call(func_idx, cpu, mem)
        } else {
            self.handle_jni_call(func_idx, cpu, mem)
        }
    }

    fn handle_vm_call(
        &mut self,
        func_idx: u32,
        cpu: &mut transd_core::CpuState,
        mem: &mut impl Memory,
    ) -> Result<bool, MemoryError> {
        match func_idx {
            vm_idx::GET_ENV => {
                let env_out_ptr = GuestAddr::new(cpu.reg(Reg::R1));
                if env_out_ptr.as_u32() != 0 {
                    mem.write_u32(env_out_ptr, self.env_ptr.as_u32())?;
                }
                cpu.set_reg(Reg::R0, JNI_OK);
            }
            vm_idx::ATTACH_CURRENT_THREAD | vm_idx::ATTACH_CURRENT_THREAD_AS_DAEMON => {
                let env_out_ptr = GuestAddr::new(cpu.reg(Reg::R1));
                if env_out_ptr.as_u32() != 0 {
                    mem.write_u32(env_out_ptr, self.env_ptr.as_u32())?;
                }
                cpu.set_reg(Reg::R0, JNI_OK);
            }
            vm_idx::DETACH_CURRENT_THREAD => {
                cpu.set_reg(Reg::R0, JNI_OK);
            }
            _ => {
                cpu.set_reg(Reg::R0, JNI_OK);
            }
        }
        Ok(true)
    }

    fn handle_jni_call(
        &mut self,
        func_idx: u32,
        cpu: &mut transd_core::CpuState,
        mem: &mut impl Memory,
    ) -> Result<bool, MemoryError> {
        match func_idx {
            // ── Version & JavaVM ───────────────────────────────────────────────
            jni_idx::GET_VERSION => {
                cpu.set_reg(Reg::R0, JNI_VERSION_1_6);
            }
            jni_idx::GET_JAVA_VM => {
                let vm_out_ptr = GuestAddr::new(cpu.reg(Reg::R1));
                if vm_out_ptr.as_u32() != 0 {
                    mem.write_u32(vm_out_ptr, self.vm_ptr.as_u32())?;
                }
                cpu.set_reg(Reg::R0, JNI_OK);
            }

            // ── Class lookup ───────────────────────────────────────────────────
            jni_idx::FIND_CLASS => {
                let name_addr = GuestAddr::new(cpu.reg(Reg::R1));
                let name = Self::read_c_string(mem, name_addr)?;
                let handle = self.intern_class(name);
                cpu.set_reg(Reg::R0, handle);
            }
            jni_idx::GET_OBJECT_CLASS => {
                let handle = self.next_handle;
                self.next_handle += 1;
                cpu.set_reg(Reg::R0, handle);
            }
            jni_idx::IS_ASSIGNABLE_FROM | jni_idx::IS_INSTANCE_OF => {
                cpu.set_reg(Reg::R0, 1); // JNI_TRUE
            }

            // ── Method IDs ────────────────────────────────────────────────────
            jni_idx::GET_METHOD_ID | jni_idx::GET_STATIC_METHOD_ID => {
                let clazz = cpu.reg(Reg::R1);
                let name_addr = GuestAddr::new(cpu.reg(Reg::R2));
                let sig_addr = GuestAddr::new(cpu.reg(Reg::R3));

                let name = Self::read_c_string(mem, name_addr)?;
                let signature = Self::read_c_string(mem, sig_addr)?;

                let method_id = self.next_handle;
                self.next_handle += 1;

                self.methods.insert(
                    method_id,
                    MethodDescriptor {
                        class_handle: clazz,
                        name,
                        signature,
                        is_static: func_idx == jni_idx::GET_STATIC_METHOD_ID,
                    },
                );

                cpu.set_reg(Reg::R0, method_id);
            }

            // ── Method Invocation Thunks ──────────────────────────────────────
            jni_idx::CALL_OBJECT_METHOD | jni_idx::CALL_STATIC_OBJECT_METHOD => {
                let method_id = cpu.reg(Reg::R2);
                let result = if let Some(desc) = self.methods.get(&method_id) {
                    if desc.name == "getPackageName" {
                        let text = self.package_name.clone();
                        let handle = self.intern_string(text);
                        handle
                    } else if desc.name == "getAbsolutePath" || desc.name == "getPath" {
                        let text = self.app_data_dir.clone();
                        let handle = self.intern_string(text);
                        handle
                    } else {
                        // Return dummy valid object handle
                        let handle = self.next_handle;
                        self.next_handle += 1;
                        handle
                    }
                } else {
                    let handle = self.next_handle;
                    self.next_handle += 1;
                    handle
                };
                cpu.set_reg(Reg::R0, result);
            }
            jni_idx::CALL_BOOLEAN_METHOD | jni_idx::CALL_STATIC_BOOLEAN_METHOD => {
                cpu.set_reg(Reg::R0, 1); // JNI_TRUE
            }
            jni_idx::CALL_BYTE_METHOD | jni_idx::CALL_CHAR_METHOD | jni_idx::CALL_SHORT_METHOD => {
                cpu.set_reg(Reg::R0, 0);
            }
            jni_idx::CALL_INT_METHOD | jni_idx::CALL_INT_METHOD_A | jni_idx::CALL_STATIC_INT_METHOD => {
                cpu.set_reg(Reg::R0, 0);
            }
            jni_idx::CALL_LONG_METHOD | jni_idx::CALL_LONG_METHOD_A | jni_idx::CALL_STATIC_LONG_METHOD => {
                cpu.set_reg(Reg::R0, 0);
                cpu.set_reg(Reg::R1, 0);
            }
            jni_idx::CALL_FLOAT_METHOD | jni_idx::CALL_STATIC_FLOAT_METHOD => {
                cpu.set_reg(Reg::R0, 0);
            }
            jni_idx::CALL_DOUBLE_METHOD | jni_idx::CALL_STATIC_DOUBLE_METHOD => {
                cpu.set_reg(Reg::R0, 0);
                cpu.set_reg(Reg::R1, 0);
            }
            jni_idx::CALL_VOID_METHOD | jni_idx::CALL_VOID_METHOD_A | jni_idx::CALL_STATIC_VOID_METHOD => {
                cpu.set_reg(Reg::R0, 0);
            }

            // ── Object lifecycle & Local Frames ──────────────────────────────
            jni_idx::NEW_OBJECT | jni_idx::NEW_OBJECT_A | jni_idx::ALLOC_OBJECT => {
                let handle = self.next_handle;
                self.next_handle += 1;
                if let Some(frame) = self.local_frames.last_mut() {
                    frame.push(handle);
                }
                cpu.set_reg(Reg::R0, handle);
            }
            jni_idx::PUSH_LOCAL_FRAME => {
                let _capacity = cpu.reg(Reg::R1);
                self.local_frames.push(Vec::new());
                cpu.set_reg(Reg::R0, JNI_OK);
            }
            jni_idx::POP_LOCAL_FRAME => {
                let result = cpu.reg(Reg::R1);
                if self.local_frames.len() > 1 {
                    self.local_frames.pop();
                    if result != 0 {
                        if let Some(frame) = self.local_frames.last_mut() {
                            frame.push(result);
                        }
                    }
                }
                cpu.set_reg(Reg::R0, result);
            }
            jni_idx::ENSURE_LOCAL_CAPACITY => {
                cpu.set_reg(Reg::R0, JNI_OK);
            }
            jni_idx::NEW_LOCAL_REF => {
                let obj = cpu.reg(Reg::R1);
                if obj == 0 {
                    cpu.set_reg(Reg::R0, 0);
                } else {
                    let handle = self.next_handle;
                    self.next_handle += 1;
                    if let Some(frame) = self.local_frames.last_mut() {
                        frame.push(handle);
                    }
                    self.global_refs.insert(handle, obj);
                    cpu.set_reg(Reg::R0, handle);
                }
            }
            jni_idx::DELETE_LOCAL_REF => {
                let obj = cpu.reg(Reg::R1);
                if let Some(frame) = self.local_frames.last_mut() {
                    frame.retain(|&x| x != obj);
                }
                cpu.set_reg(Reg::R0, 0);
            }
            jni_idx::NEW_GLOBAL_REF => {
                let obj = cpu.reg(Reg::R1);
                if obj == 0 {
                    cpu.set_reg(Reg::R0, 0);
                } else {
                    self.global_refs.insert(obj, obj);
                    cpu.set_reg(Reg::R0, obj);
                }
            }
            jni_idx::DELETE_GLOBAL_REF => {
                let obj = cpu.reg(Reg::R1);
                self.global_refs.remove(&obj);
                cpu.set_reg(Reg::R0, 0);
            }
            jni_idx::NEW_WEAK_GLOBAL_REF => {
                let obj = cpu.reg(Reg::R1);
                if obj == 0 {
                    cpu.set_reg(Reg::R0, 0);
                } else {
                    let weak_handle = self.next_handle;
                    self.next_handle += 1;
                    self.weak_global_refs.insert(weak_handle, obj);
                    cpu.set_reg(Reg::R0, weak_handle);
                }
            }
            jni_idx::DELETE_WEAK_GLOBAL_REF => {
                let weak_handle = cpu.reg(Reg::R1);
                self.weak_global_refs.insert(weak_handle, 0);
                cpu.set_reg(Reg::R0, 0);
            }
            jni_idx::IS_SAME_OBJECT => {
                let ref1 = cpu.reg(Reg::R1);
                let ref2 = cpu.reg(Reg::R2);

                let obj1 = self.weak_global_refs.get(&ref1).copied()
                    .or_else(|| self.global_refs.get(&ref1).copied())
                    .unwrap_or(ref1);
                let obj2 = self.weak_global_refs.get(&ref2).copied()
                    .or_else(|| self.global_refs.get(&ref2).copied())
                    .unwrap_or(ref2);

                let same = (obj1 == obj2) || (ref1 == ref2);
                cpu.set_reg(Reg::R0, if same { 1 } else { 0 });
            }

            // ── String & Array Critical (Zero-Copy Pinning) ───────────────────
            jni_idx::GET_STRING_CRITICAL => {
                let string_handle = cpu.reg(Reg::R1);
                let is_copy_ptr = GuestAddr::new(cpu.reg(Reg::R2));
                if is_copy_ptr.as_u32() != 0 {
                    mem.write_u8(is_copy_ptr, JNI_FALSE)?;
                }
                if let Some(&addr) = self.string_addrs.get(&string_handle) {
                    cpu.set_reg(Reg::R0, addr.as_u32());
                } else if let Some(text) = self.strings.get(&string_handle).cloned() {
                    let guest_str_addr = self.string_heap_cur;
                    for (i, c) in text.encode_utf16().enumerate() {
                        mem.write_u16(guest_str_addr.add((i * 2) as u32), c)?;
                    }
                    let utf16_len = text.encode_utf16().count();
                    mem.write_u16(guest_str_addr.add((utf16_len * 2) as u32), 0)?;
                    self.string_heap_cur = guest_str_addr.add(((utf16_len * 2 + 7) & !3) as u32);
                    self.string_addrs.insert(string_handle, guest_str_addr);
                    cpu.set_reg(Reg::R0, guest_str_addr.as_u32());
                } else {
                    cpu.set_reg(Reg::R0, 0);
                }
            }
            jni_idx::RELEASE_STRING_CRITICAL => {
                cpu.set_reg(Reg::R0, 0);
            }
            jni_idx::GET_PRIMITIVE_ARRAY_CRITICAL => {
                let arr_handle = cpu.reg(Reg::R1);
                let is_copy_ptr = GuestAddr::new(cpu.reg(Reg::R2));
                if is_copy_ptr.as_u32() != 0 {
                    mem.write_u8(is_copy_ptr, JNI_FALSE)?;
                }
                let addr = if let Some(&(ptr, _, _)) = self.arrays.get(&arr_handle) {
                    ptr.as_u32()
                } else {
                    0
                };
                cpu.set_reg(Reg::R0, addr);
            }
            jni_idx::RELEASE_PRIMITIVE_ARRAY_CRITICAL => {
                cpu.set_reg(Reg::R0, 0);
            }

            // ── Field IDs ─────────────────────────────────────────────────────
            jni_idx::GET_FIELD_ID | jni_idx::GET_STATIC_FIELD_ID => {
                let clazz = cpu.reg(Reg::R1);
                let name_addr = GuestAddr::new(cpu.reg(Reg::R2));
                let sig_addr = GuestAddr::new(cpu.reg(Reg::R3));

                let name = Self::read_c_string(mem, name_addr)?;
                let signature = Self::read_c_string(mem, sig_addr)?;

                let field_id = self.next_handle;
                self.next_handle += 1;

                self.field_descriptors.insert(
                    field_id,
                    FieldDescriptor {
                        class_handle: clazz,
                        name,
                        signature,
                        is_static: func_idx == jni_idx::GET_STATIC_FIELD_ID,
                    },
                );

                cpu.set_reg(Reg::R0, field_id);
            }

            // ── Field access (Instance & Static) ──────────────────────────────
            jni_idx::GET_OBJECT_FIELD | jni_idx::GET_STATIC_OBJECT_FIELD => {
                let target = cpu.reg(Reg::R1);
                let field_id = cpu.reg(Reg::R2);
                let val = match self.field_values.get(&(target, field_id)) {
                    Some(JniValue::Object(v)) => *v,
                    _ => 0,
                };
                cpu.set_reg(Reg::R0, val);
            }
            jni_idx::SET_OBJECT_FIELD | jni_idx::SET_STATIC_OBJECT_FIELD => {
                let target = cpu.reg(Reg::R1);
                let field_id = cpu.reg(Reg::R2);
                let val = cpu.reg(Reg::R3);
                self.field_values.insert((target, field_id), JniValue::Object(val));
                cpu.set_reg(Reg::R0, 0);
            }
            jni_idx::GET_BOOLEAN_FIELD | jni_idx::GET_STATIC_BOOLEAN_FIELD => {
                let target = cpu.reg(Reg::R1);
                let field_id = cpu.reg(Reg::R2);
                let val = match self.field_values.get(&(target, field_id)) {
                    Some(JniValue::Boolean(b)) => if *b { 1 } else { 0 },
                    _ => 0,
                };
                cpu.set_reg(Reg::R0, val);
            }
            jni_idx::SET_BOOLEAN_FIELD | jni_idx::SET_STATIC_BOOLEAN_FIELD => {
                let target = cpu.reg(Reg::R1);
                let field_id = cpu.reg(Reg::R2);
                let val = cpu.reg(Reg::R3);
                self.field_values.insert((target, field_id), JniValue::Boolean(val != 0));
                cpu.set_reg(Reg::R0, 0);
            }
            jni_idx::GET_INT_FIELD | jni_idx::GET_STATIC_INT_FIELD => {
                let target = cpu.reg(Reg::R1);
                let field_id = cpu.reg(Reg::R2);
                let val = match self.field_values.get(&(target, field_id)) {
                    Some(JniValue::Int(v)) => *v as u32,
                    _ => 0,
                };
                cpu.set_reg(Reg::R0, val);
            }
            jni_idx::SET_INT_FIELD | jni_idx::SET_STATIC_INT_FIELD => {
                let target = cpu.reg(Reg::R1);
                let field_id = cpu.reg(Reg::R2);
                let val = cpu.reg(Reg::R3);
                self.field_values.insert((target, field_id), JniValue::Int(val as i32));
                cpu.set_reg(Reg::R0, 0);
            }
            jni_idx::GET_LONG_FIELD | jni_idx::GET_STATIC_LONG_FIELD => {
                let target = cpu.reg(Reg::R1);
                let field_id = cpu.reg(Reg::R2);
                let val = match self.field_values.get(&(target, field_id)) {
                    Some(JniValue::Long(v)) => *v,
                    _ => 0,
                };
                cpu.set_reg(Reg::R0, (val & 0xFFFF_FFFF) as u32);
                cpu.set_reg(Reg::R1, (val >> 32) as u32);
            }
            jni_idx::SET_LONG_FIELD | jni_idx::SET_STATIC_LONG_FIELD => {
                let target = cpu.reg(Reg::R1);
                let field_id = cpu.reg(Reg::R2);
                let sp = GuestAddr::new(cpu.sp());
                let val_lo = cpu.reg(Reg::R3);
                let val_hi = mem.read_u32(sp)?;
                let val = ((val_hi as i64) << 32) | (val_lo as i64);
                self.field_values.insert((target, field_id), JniValue::Long(val));
                cpu.set_reg(Reg::R0, 0);
            }

            // ── Strings ────────────────────────────────────────────────────────
            jni_idx::NEW_STRING_UTF => {
                let bytes_addr = GuestAddr::new(cpu.reg(Reg::R1));
                let text = Self::read_c_string(mem, bytes_addr)?;
                let handle = self.intern_string(text);
                cpu.set_reg(Reg::R0, handle);
            }
            jni_idx::GET_STRING_UTF_LENGTH => {
                let handle = cpu.reg(Reg::R1);
                let len = self.strings.get(&handle).map(|s| s.len() as u32).unwrap_or(0);
                cpu.set_reg(Reg::R0, len);
            }
            jni_idx::GET_STRING_LENGTH => {
                let handle = cpu.reg(Reg::R1);
                let len = self.strings.get(&handle).map(|s| s.chars().count() as u32).unwrap_or(0);
                cpu.set_reg(Reg::R0, len);
            }
            jni_idx::GET_STRING_UTF_CHARS => {
                let handle = cpu.reg(Reg::R1);
                let is_copy_ptr = GuestAddr::new(cpu.reg(Reg::R2));

                if let Some(text) = self.strings.get(&handle).cloned() {
                    let guest_str_addr = self.string_heap_cur;
                    let bytes = text.as_bytes();
                    mem.write_bytes(guest_str_addr, bytes)?;
                    mem.write_u8(guest_str_addr.add(bytes.len() as u32), 0)?; // NUL

                    self.string_heap_cur = guest_str_addr.add((bytes.len() as u32 + 7) & !3);
                    self.string_addrs.insert(handle, guest_str_addr);

                    if is_copy_ptr.as_u32() != 0 {
                        mem.write_u8(is_copy_ptr, JNI_TRUE)?;
                    }

                    cpu.set_reg(Reg::R0, guest_str_addr.as_u32());
                } else {
                    cpu.set_reg(Reg::R0, 0);
                }
            }
            jni_idx::RELEASE_STRING_UTF_CHARS => {
                cpu.set_reg(Reg::R0, 0);
            }

            // ── Arrays ─────────────────────────────────────────────────────────
            jni_idx::GET_ARRAY_LENGTH => {
                let handle = cpu.reg(Reg::R1);
                let len = self.arrays.get(&handle).map(|&(_, l, _)| l as u32).unwrap_or(0);
                cpu.set_reg(Reg::R0, len);
            }
            jni_idx::NEW_BYTE_ARRAY => {
                let len = cpu.reg(Reg::R1) as usize;
                let handle = self.next_handle;
                self.next_handle += 1;
                let arr_addr = self.string_heap_cur;
                let zeros = vec![0u8; len];
                mem.write_bytes(arr_addr, &zeros)?;
                self.string_heap_cur = arr_addr.add((len as u32 + 7) & !3);
                self.arrays.insert(handle, (arr_addr, len, 1));
                cpu.set_reg(Reg::R0, handle);
            }
            jni_idx::GET_BYTE_ARRAY_ELEMENTS => {
                let handle = cpu.reg(Reg::R1);
                let addr = self.arrays.get(&handle).map(|&(a, _, _)| a.as_u32()).unwrap_or(0);
                cpu.set_reg(Reg::R0, addr);
            }
            jni_idx::RELEASE_BYTE_ARRAY_ELEMENTS => {
                cpu.set_reg(Reg::R0, 0);
            }
            jni_idx::NEW_INT_ARRAY => {
                let len = cpu.reg(Reg::R1) as usize;
                let handle = self.next_handle;
                self.next_handle += 1;
                let arr_addr = self.string_heap_cur;
                let zeros = vec![0u8; len * 4];
                mem.write_bytes(arr_addr, &zeros)?;
                self.string_heap_cur = arr_addr.add(((len * 4) as u32 + 7) & !3);
                self.arrays.insert(handle, (arr_addr, len, 4));
                cpu.set_reg(Reg::R0, handle);
            }
            jni_idx::GET_INT_ARRAY_ELEMENTS => {
                let handle = cpu.reg(Reg::R1);
                let addr = self.arrays.get(&handle).map(|&(a, _, _)| a.as_u32()).unwrap_or(0);
                cpu.set_reg(Reg::R0, addr);
            }
            jni_idx::RELEASE_INT_ARRAY_ELEMENTS => {
                cpu.set_reg(Reg::R0, 0);
            }
            jni_idx::NEW_FLOAT_ARRAY => {
                let len = cpu.reg(Reg::R1) as usize;
                let handle = self.next_handle;
                self.next_handle += 1;
                let arr_addr = self.string_heap_cur;
                let zeros = vec![0u8; len * 4];
                mem.write_bytes(arr_addr, &zeros)?;
                self.string_heap_cur = arr_addr.add(((len * 4) as u32 + 7) & !3);
                self.arrays.insert(handle, (arr_addr, len, 4));
                cpu.set_reg(Reg::R0, handle);
            }
            jni_idx::GET_FLOAT_ARRAY_ELEMENTS => {
                let handle = cpu.reg(Reg::R1);
                let addr = self.arrays.get(&handle).map(|&(a, _, _)| a.as_u32()).unwrap_or(0);
                cpu.set_reg(Reg::R0, addr);
            }
            jni_idx::RELEASE_FLOAT_ARRAY_ELEMENTS => {
                cpu.set_reg(Reg::R0, 0);
            }
            jni_idx::GET_BYTE_ARRAY_REGION => {
                let handle = cpu.reg(Reg::R1);
                let start = cpu.reg(Reg::R2) as usize;
                let len = cpu.reg(Reg::R3) as usize;
                let sp = GuestAddr::new(cpu.sp());
                let buf_ptr = GuestAddr::new(mem.read_u32(sp)?);

                if let Some(&(arr_addr, arr_len, _)) = self.arrays.get(&handle) {
                    if start + len <= arr_len {
                        let mut temp = vec![0u8; len];
                        mem.read_bytes(arr_addr.add(start as u32), &mut temp)?;
                        mem.write_bytes(buf_ptr, &temp)?;
                    }
                }
                cpu.set_reg(Reg::R0, 0);
            }
            jni_idx::SET_BYTE_ARRAY_REGION => {
                let handle = cpu.reg(Reg::R1);
                let start = cpu.reg(Reg::R2) as usize;
                let len = cpu.reg(Reg::R3) as usize;
                let sp = GuestAddr::new(cpu.sp());
                let buf_ptr = GuestAddr::new(mem.read_u32(sp)?);

                if let Some(&(arr_addr, arr_len, _)) = self.arrays.get(&handle) {
                    if start + len <= arr_len {
                        let mut temp = vec![0u8; len];
                        mem.read_bytes(buf_ptr, &mut temp)?;
                        mem.write_bytes(arr_addr.add(start as u32), &temp)?;
                    }
                }
                cpu.set_reg(Reg::R0, 0);
            }

            // ── Direct Byte Buffers ────────────────────────────────────────────
            jni_idx::NEW_DIRECT_BYTE_BUFFER => {
                let addr = GuestAddr::new(cpu.reg(Reg::R1));
                let cap_lo = cpu.reg(Reg::R2);
                let handle = self.next_handle;
                self.next_handle += 1;

                self.direct_buffers.insert(
                    handle,
                    DirectBufferInfo {
                        addr,
                        capacity: cap_lo as usize,
                    },
                );

                cpu.set_reg(Reg::R0, handle);
            }
            jni_idx::GET_DIRECT_BUFFER_ADDRESS => {
                let handle = cpu.reg(Reg::R1);
                let addr = self.direct_buffers.get(&handle).map(|b| b.addr.as_u32()).unwrap_or(0);
                cpu.set_reg(Reg::R0, addr);
            }
            jni_idx::GET_DIRECT_BUFFER_CAPACITY => {
                let handle = cpu.reg(Reg::R1);
                let cap = self.direct_buffers.get(&handle).map(|b| b.capacity as u32).unwrap_or(0);
                cpu.set_reg(Reg::R0, cap);
                cpu.set_reg(Reg::R1, 0); // High 32 bits of jlong
            }

            // ── Exceptions ─────────────────────────────────────────────────────
            jni_idx::EXCEPTION_CHECK => {
                cpu.set_reg(Reg::R0, if self.pending_exception != 0 { 1 } else { 0 });
            }
            jni_idx::EXCEPTION_OCCURRED => {
                cpu.set_reg(Reg::R0, self.pending_exception);
            }
            jni_idx::EXCEPTION_CLEAR => {
                self.pending_exception = 0;
                cpu.set_reg(Reg::R0, 0);
            }
            jni_idx::THROW_NEW => {
                let exc_handle = self.next_handle;
                self.next_handle += 1;
                self.pending_exception = exc_handle;
                cpu.set_reg(Reg::R0, JNI_OK);
            }

            // ── Synchronization ────────────────────────────────────────────────
            jni_idx::MONITOR_ENTER | jni_idx::MONITOR_EXIT => {
                cpu.set_reg(Reg::R0, JNI_OK);
            }

            // ── RegisterNatives ────────────────────────────────────────────────
            jni_idx::REGISTER_NATIVES => {
                let methods_addr = GuestAddr::new(cpu.reg(Reg::R2));
                let n_methods = cpu.reg(Reg::R3);

                for i in 0..n_methods {
                    let entry_addr = methods_addr.add(i * 12);
                    let name_addr = GuestAddr::new(mem.read_u32(entry_addr)?);
                    let sig_addr = GuestAddr::new(mem.read_u32(entry_addr.add(4))?);
                    let fn_ptr = GuestAddr::new(mem.read_u32(entry_addr.add(8))?);

                    let name = Self::read_c_string(mem, name_addr)?;
                    let signature = Self::read_c_string(mem, sig_addr)?;

                    self.registered_natives.push(RegisteredNativeMethod {
                        name,
                        signature,
                        fn_ptr,
                    });
                }

                cpu.set_reg(Reg::R0, JNI_OK);
            }
            jni_idx::UNREGISTER_NATIVES => {
                cpu.set_reg(Reg::R0, JNI_OK);
            }

            _ => {
                cpu.set_reg(Reg::R0, 0);
            }
        }

        Ok(true)
    }

    /// Intern a class name and return its handle
    pub fn intern_class(&mut self, name: String) -> u32 {
        if let Some(&h) = self.classes.get(&name) {
            return h;
        }
        let h = self.next_handle;
        self.next_handle += 1;
        self.classes.insert(name, h);
        h
    }

    /// Intern a string and return its jstring handle
    pub fn intern_string(&mut self, text: String) -> u32 {
        let handle = self.next_handle;
        self.next_handle += 1;
        self.strings.insert(handle, text);
        handle
    }

    fn read_c_string(mem: &impl Memory, addr: GuestAddr) -> Result<String, MemoryError> {
        let mut bytes = Vec::new();
        let mut cur = addr;
        loop {
            let b = mem.read_u8(cur)?;
            if b == 0 {
                break;
            }
            bytes.push(b);
            cur = cur.add(1);
        }
        Ok(String::from_utf8_lossy(&bytes).to_string())
    }
}
