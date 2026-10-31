use std::collections::HashMap;
use transd_core::{GuestAddr, Memory, MemoryError, Reg};

pub const JNI_SVC_MAGIC: u32 = 0x4A0000; // 'J' << 16

pub const JNI_VERSION_1_1: u32 = 0x00010001;
pub const JNI_VERSION_1_2: u32 = 0x00010002;
pub const JNI_VERSION_1_4: u32 = 0x00010004;
pub const JNI_VERSION_1_6: u32 = 0x00010006;

pub const JNI_OK: u32 = 0;
pub const JNI_ERR: u32 = 0xFFFF_FFFF;

/// Standard JNI Function Table Indices
pub mod jni_idx {
    pub const GET_VERSION: u32 = 4;
    pub const FIND_CLASS: u32 = 6;
    pub const GET_METHOD_ID: u32 = 33;
    pub const CALL_INT_METHOD: u32 = 52;
    pub const CALL_VOID_METHOD: u32 = 64;
    pub const GET_STATIC_METHOD_ID: u32 = 113;
    pub const NEW_STRING_UTF: u32 = 166;
    pub const GET_STRING_UTF_CHARS: u32 = 168;
    pub const RELEASE_STRING_UTF_CHARS: u32 = 169;
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
    pub registered_natives: Vec<RegisteredNativeMethod>,
    pub string_heap_cur: GuestAddr,
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
            registered_natives: Vec::new(),
            string_heap_cur,
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
            jni_idx::GET_VERSION => {
                // jint GetVersion(JNIEnv *env)
                cpu.set_reg(Reg::R0, JNI_VERSION_1_6);
            }
            jni_idx::FIND_CLASS => {
                // jclass FindClass(JNIEnv *env, const char *name)
                // r0 = env, r1 = name_ptr
                let name_addr = GuestAddr::new(cpu.reg(Reg::R1));
                let name = Self::read_c_string(mem, name_addr)?;

                let handle = if let Some(&h) = self.classes.get(&name) {
                    h
                } else {
                    let h = self.next_handle;
                    self.next_handle += 1;
                    self.classes.insert(name, h);
                    h
                };
                cpu.set_reg(Reg::R0, handle);
            }
            jni_idx::GET_METHOD_ID | jni_idx::GET_STATIC_METHOD_ID => {
                // jmethodID GetMethodID(JNIEnv *env, jclass clazz, const char *name, const char *sig)
                let handle = self.next_handle;
                self.next_handle += 1;
                cpu.set_reg(Reg::R0, handle);
            }
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
                    mem.write_u8(guest_str_addr.add(bytes.len() as u32), 0)?; // null terminator

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
                // void ReleaseStringUTFChars(JNIEnv *env, jstring string, const char *utf)
                cpu.set_reg(Reg::R0, 0);
            }
            jni_idx::REGISTER_NATIVES => {
                // jint RegisterNatives(JNIEnv *env, jclass clazz, const JNINativeMethod *methods, jint nMethods)
                // r0 = env, r1 = clazz, r2 = methods, r3 = nMethods
                let methods_addr = GuestAddr::new(cpu.reg(Reg::R2));
                let n_methods = cpu.reg(Reg::R3);

                // Each JNINativeMethod32 is:
                // name: u32 (char*)
                // signature: u32 (char*)
                // fnPtr: u32 (void*)
                // Total size: 12 bytes
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
                // Default fallback returns 0
                cpu.set_reg(Reg::R0, 0);
            }
        }

        Ok(true)
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
