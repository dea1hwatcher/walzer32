use std::collections::HashMap;
use transd_core::{GuestAddr, Memory, MemoryError, Reg};

pub const JNI_SVC_MAGIC: u32 = 0x4A0000; // 'J' << 16

pub const JNI_VERSION_1_1: u32 = 0x00010001;
pub const JNI_VERSION_1_2: u32 = 0x00010002;
pub const JNI_VERSION_1_4: u32 = 0x00010004;
pub const JNI_VERSION_1_6: u32 = 0x00010006;

pub const JNI_OK: u32 = 0;
pub const JNI_ERR: u32 = 0xFFFF_FFFF;

/// Standard JNI Function Table Indices (per JNI spec table jni.h)
pub mod jni_idx {
    pub const GET_VERSION: u32 = 4;
    pub const FIND_CLASS: u32 = 6;
    pub const THROW_NEW: u32 = 14;
    pub const EXCEPTION_CHECK: u32 = 228;
    pub const EXCEPTION_CLEAR: u32 = 17;
    pub const EXCEPTION_OCCURRED: u32 = 15;
    pub const NEW_OBJECT: u32 = 28;
    pub const GET_OBJECT_CLASS: u32 = 31;
    pub const GET_METHOD_ID: u32 = 33;
    pub const CALL_OBJECT_METHOD: u32 = 34;
    pub const CALL_BOOL_METHOD: u32 = 37;
    pub const CALL_INT_METHOD: u32 = 52;
    pub const CALL_VOID_METHOD: u32 = 64;
    pub const GET_STATIC_METHOD_ID: u32 = 113;
    pub const CALL_STATIC_OBJECT_METHOD: u32 = 114;
    pub const CALL_STATIC_INT_METHOD: u32 = 120;
    pub const CALL_STATIC_VOID_METHOD: u32 = 126;
    pub const GET_FIELD_ID: u32 = 94;
    pub const GET_OBJECT_FIELD: u32 = 95;
    pub const GET_BOOL_FIELD: u32 = 96;
    pub const GET_INT_FIELD: u32 = 100;
    pub const SET_INT_FIELD: u32 = 106;
    pub const SET_OBJECT_FIELD: u32 = 104;
    pub const GET_STATIC_FIELD_ID: u32 = 144;
    pub const GET_STATIC_INT_FIELD: u32 = 150;
    pub const NEW_GLOBAL_REF: u32 = 21;
    pub const DELETE_GLOBAL_REF: u32 = 22;
    pub const DELETE_LOCAL_REF: u32 = 23;
    pub const NEW_STRING_UTF: u32 = 166;
    pub const GET_STRING_UTF_CHARS: u32 = 168;
    pub const RELEASE_STRING_UTF_CHARS: u32 = 169;
    pub const GET_ARRAY_LENGTH: u32 = 171;
    pub const NEW_BYTE_ARRAY: u32 = 176;
    pub const GET_BYTE_ARRAY_ELEMENTS: u32 = 184;
    pub const RELEASE_BYTE_ARRAY_ELEMENTS: u32 = 192;
    pub const REGISTER_NATIVES: u32 = 215;
}

/// JavaVM Function Table Indices
pub mod vm_idx {
    pub const DESTROY_JAVA_VM: u32 = 3;
    pub const ATTACH_CURRENT_THREAD: u32 = 4;
    pub const DETACH_CURRENT_THREAD: u32 = 5;
    pub const GET_ENV: u32 = 6;
}

#[derive(Debug, Clone)]
pub struct RegisteredNativeMethod {
    pub name: String,
    pub signature: String,
    pub fn_ptr: GuestAddr,
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
    pub global_refs: HashMap<u32, u32>,
    pub registered_natives: Vec<RegisteredNativeMethod>,
    pub string_heap_cur: GuestAddr,
    /// Pending exception handle (0 = no exception)
    pub pending_exception: u32,
    /// Byte arrays: handle -> guest address
    pub byte_arrays: HashMap<u32, (GuestAddr, usize)>,
}

impl JniBridge {
    pub fn new(base: GuestAddr) -> Self {
        // Layout at base:
        // base + 0:    env_ptr (points to base + 4)
        // base + 4:    interface table (250 entries * 4 = 1000 bytes)
        // base + 1024: jni stubs (250 stubs * 8 = 2000 bytes)
        // base + 3072: vm_ptr (points to base + 3076)
        // base + 3076: vm table (16 entries * 4 = 64 bytes)
        // base + 3140: vm stubs (16 stubs * 8 = 128 bytes)
        // base + 4096: string heap
        let env_ptr = base;
        let interface_table_addr = base.add(4);
        let jni_stubs_addr = base.add(1024);

        let vm_ptr = base.add(3072);
        let vm_table_addr = base.add(3076);
        let vm_stubs_addr = base.add(3140);

        let string_heap_cur = base.add(4096);

        Self {
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
            global_refs: HashMap::new(),
            registered_natives: Vec::new(),
            string_heap_cur,
            pending_exception: 0,
            byte_arrays: HashMap::new(),
        }
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
                // jint GetEnv(JavaVM *vm, void **env, jint version)
                // r0 = vm, r1 = &env, r2 = version
                let env_out_ptr = GuestAddr::new(cpu.reg(Reg::R1));
                mem.write_u32(env_out_ptr, self.env_ptr.as_u32())?;
                cpu.set_reg(Reg::R0, JNI_OK);
            }
            vm_idx::ATTACH_CURRENT_THREAD => {
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
            // ── Version ────────────────────────────────────────────────────────
            jni_idx::GET_VERSION => {
                cpu.set_reg(Reg::R0, JNI_VERSION_1_6);
            }

            // ── Class lookup ───────────────────────────────────────────────────
            jni_idx::FIND_CLASS => {
                // jclass FindClass(JNIEnv *env, const char *name)
                let name_addr = GuestAddr::new(cpu.reg(Reg::R1));
                let name = Self::read_c_string(mem, name_addr)?;
                let handle = self.intern_class(name);
                cpu.set_reg(Reg::R0, handle);
            }
            jni_idx::GET_OBJECT_CLASS => {
                // jclass GetObjectClass(JNIEnv *env, jobject obj)
                // We don't track obj->class mapping; return a generic handle
                let handle = self.next_handle;
                self.next_handle += 1;
                cpu.set_reg(Reg::R0, handle);
            }

            // ── Method IDs ────────────────────────────────────────────────────
            jni_idx::GET_METHOD_ID | jni_idx::GET_STATIC_METHOD_ID => {
                // jmethodID GetMethodID(JNIEnv, jclass, name, sig)
                let handle = self.next_handle;
                self.next_handle += 1;
                cpu.set_reg(Reg::R0, handle);
            }

            // ── Method calls (stub: return 0 on dev host) ─────────────────────
            jni_idx::CALL_OBJECT_METHOD | jni_idx::CALL_STATIC_OBJECT_METHOD => {
                cpu.set_reg(Reg::R0, 0);
            }
            jni_idx::CALL_BOOL_METHOD => {
                cpu.set_reg(Reg::R0, 0);
            }
            jni_idx::CALL_INT_METHOD | jni_idx::CALL_STATIC_INT_METHOD => {
                cpu.set_reg(Reg::R0, 0);
            }
            jni_idx::CALL_VOID_METHOD | jni_idx::CALL_STATIC_VOID_METHOD => {
                cpu.set_reg(Reg::R0, 0);
            }

            // ── Object lifecycle ──────────────────────────────────────────────
            jni_idx::NEW_OBJECT => {
                // jobject NewObject(JNIEnv, jclass, jmethodID, ...)
                let handle = self.next_handle;
                self.next_handle += 1;
                cpu.set_reg(Reg::R0, handle);
            }
            jni_idx::NEW_GLOBAL_REF => {
                // jobject NewGlobalRef(JNIEnv *env, jobject obj)
                let obj = cpu.reg(Reg::R1);
                // In our model, global refs share the same handle space.
                // Just record the mapping and return the same handle.
                self.global_refs.insert(obj, obj);
                cpu.set_reg(Reg::R0, obj);
            }
            jni_idx::DELETE_GLOBAL_REF => {
                let obj = cpu.reg(Reg::R1);
                self.global_refs.remove(&obj);
                cpu.set_reg(Reg::R0, 0);
            }
            jni_idx::DELETE_LOCAL_REF => {
                // Local refs are stack-scoped; we don't track them — no-op.
                cpu.set_reg(Reg::R0, 0);
            }

            // ── Field IDs ─────────────────────────────────────────────────────
            jni_idx::GET_FIELD_ID | jni_idx::GET_STATIC_FIELD_ID => {
                let handle = self.next_handle;
                self.next_handle += 1;
                cpu.set_reg(Reg::R0, handle);
            }

            // ── Field access (stub: memory not backed, return 0) ───────────────
            jni_idx::GET_OBJECT_FIELD | jni_idx::SET_OBJECT_FIELD => {
                cpu.set_reg(Reg::R0, 0);
            }
            jni_idx::GET_BOOL_FIELD => {
                cpu.set_reg(Reg::R0, 0);
            }
            jni_idx::GET_INT_FIELD | jni_idx::GET_STATIC_INT_FIELD => {
                cpu.set_reg(Reg::R0, 0);
            }
            jni_idx::SET_INT_FIELD => {
                // void SetIntField(JNIEnv, jobject, jfieldID, jint value)
                // r3 = value — we accept it but don't store in a real Java heap
                cpu.set_reg(Reg::R0, 0);
            }

            // ── Strings ────────────────────────────────────────────────────────
            jni_idx::NEW_STRING_UTF => {
                // jstring NewStringUTF(JNIEnv *env, const char *bytes)
                let bytes_addr = GuestAddr::new(cpu.reg(Reg::R1));
                let text = Self::read_c_string(mem, bytes_addr)?;
                let handle = self.next_handle;
                self.next_handle += 1;
                self.strings.insert(handle, text);
                cpu.set_reg(Reg::R0, handle);
            }
            jni_idx::GET_STRING_UTF_CHARS => {
                // const char* GetStringUTFChars(JNIEnv *env, jstring string, jboolean *isCopy)
                let handle = cpu.reg(Reg::R1);
                let is_copy_ptr = GuestAddr::new(cpu.reg(Reg::R2));

                if let Some(text) = self.strings.get(&handle).cloned() {
                    let guest_str_addr = self.string_heap_cur;
                    let bytes = text.as_bytes();
                    mem.write_bytes(guest_str_addr, bytes)?;
                    mem.write_u8(guest_str_addr.add(bytes.len() as u32), 0)?; // NUL terminator

                    self.string_heap_cur = guest_str_addr.add((bytes.len() as u32) + 4);
                    self.string_addrs.insert(handle, guest_str_addr);

                    if is_copy_ptr.as_u32() != 0 {
                        mem.write_u8(is_copy_ptr, 1)?; // isCopy = JNI_TRUE
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
                let len = self.byte_arrays.get(&handle).map(|&(_, l)| l as u32).unwrap_or(0);
                cpu.set_reg(Reg::R0, len);
            }
            jni_idx::NEW_BYTE_ARRAY => {
                // jbyteArray NewByteArray(JNIEnv *env, jsize length)
                let len = cpu.reg(Reg::R1) as usize;
                let handle = self.next_handle;
                self.next_handle += 1;
                // Allocate space in string heap (reuse for simplicity)
                let arr_addr = self.string_heap_cur;
                let zeros = vec![0u8; len];
                mem.write_bytes(arr_addr, &zeros)?;
                self.string_heap_cur = arr_addr.add(len as u32 + 4);
                self.byte_arrays.insert(handle, (arr_addr, len));
                cpu.set_reg(Reg::R0, handle);
            }
            jni_idx::GET_BYTE_ARRAY_ELEMENTS => {
                // jbyte* GetByteArrayElements(JNIEnv, jbyteArray, jboolean *isCopy)
                let handle = cpu.reg(Reg::R1);
                let addr = self.byte_arrays.get(&handle).map(|&(a, _)| a.as_u32()).unwrap_or(0);
                cpu.set_reg(Reg::R0, addr);
            }
            jni_idx::RELEASE_BYTE_ARRAY_ELEMENTS => {
                cpu.set_reg(Reg::R0, 0);
            }

            // ── Exceptions ─────────────────────────────────────────────────────
            jni_idx::EXCEPTION_CHECK => {
                // jboolean ExceptionCheck(JNIEnv *env) — returns JNI_TRUE if pending
                cpu.set_reg(Reg::R0, if self.pending_exception != 0 { 1 } else { 0 });
            }
            jni_idx::EXCEPTION_OCCURRED => {
                // jthrowable ExceptionOccurred(JNIEnv *env)
                cpu.set_reg(Reg::R0, self.pending_exception);
            }
            jni_idx::EXCEPTION_CLEAR => {
                self.pending_exception = 0;
                cpu.set_reg(Reg::R0, 0);
            }
            jni_idx::THROW_NEW => {
                // jint ThrowNew(JNIEnv *env, jclass clazz, const char *message)
                let exc_handle = self.next_handle;
                self.next_handle += 1;
                self.pending_exception = exc_handle;
                cpu.set_reg(Reg::R0, JNI_OK);
            }

            // ── RegisterNatives ────────────────────────────────────────────────
            jni_idx::REGISTER_NATIVES => {
                // jint RegisterNatives(JNIEnv *env, jclass clazz, JNINativeMethod *methods, jint n)
                let methods_addr = GuestAddr::new(cpu.reg(Reg::R2));
                let n_methods = cpu.reg(Reg::R3);

                // Each JNINativeMethod32: name(u32), signature(u32), fnPtr(u32) = 12 bytes
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

            _ => {
                // Unhandled JNI function — return 0 (null/ok stub)
                cpu.set_reg(Reg::R0, 0);
            }
        }

        Ok(true)
    }

    /// Intern a class name and return its handle (creating one if needed).
    fn intern_class(&mut self, name: String) -> u32 {
        if let Some(&h) = self.classes.get(&name) {
            return h;
        }
        let h = self.next_handle;
        self.next_handle += 1;
        self.classes.insert(name, h);
        h
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
