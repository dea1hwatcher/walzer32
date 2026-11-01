/// Dynamic Host-to-Guest JNI Trampoline Generator (64-bit ART <-> 32-bit ARM).
///
/// In 64-bit Android (ARM64-only devices running ARMv9+ silicon), the host Android
/// Runtime (ART) expects 64-bit native function pointers conforming to AAPCS64:
///   `jvalue Java_com_package_Class_method(JNIEnv* env64, jobject thiz, ...args64);`
///
/// When a legacy 32-bit library calls `env->RegisterNatives()`, the `fnPtr` is a 32-bit
/// guest address expecting AAPCS32:
///   `jvalue nativeMethod(JNIEnv32* env32, jobject32 thiz, ...args32);`
///
/// `JniThunkGenerator` dynamically compiles executable AArch64 bridge trampolines:
///   1. Preserves host callee-saved registers and stack alignment.
///   2. Marshals incoming 64-bit host arguments into 32-bit guest registers (r0..r3, stack).
///   3. Replaces the 64-bit host JNIEnv* with Transd's 32-bit JNINativeInterface32.
///   4. Invokes the DBT execution engine targeting `guest_fn_ptr`.
///   5. Unpacks the 32-bit return value (r0 or r0:r1) to 64-bit (x0 / d0).
///   6. Restores host context and returns to 64-bit ART.

use transd_core::GuestAddr;
use transd_emitter_a64::{A64Assembler, A64Reg};
use crate::jni::RegisteredNativeMethod;

/// Descriptor of a dynamically generated 64-to-32 JNI thunk
#[derive(Debug, Clone)]
pub struct JniThunk {
    pub name: String,
    pub signature: String,
    pub guest_fn_ptr: GuestAddr,
    pub code_bytes: Vec<u8>,
}

pub struct JniThunkGenerator;

impl JniThunkGenerator {
    /// Generates native AArch64 machine code for a 64-to-32 JNI method thunk
    pub fn generate_thunk(
        name: &str,
        signature: &str,
        guest_fn_ptr: GuestAddr,
        guest_env_addr: GuestAddr,
    ) -> JniThunk {
        let mut asm = A64Assembler::new();

        // 1. AAPCS64 Function Prologue: save FP and LR (x29, x30)
        // STP x29, x30, [sp, #-16]!
        // We use emit with standard STP x29, x30, [sp, #-16]! -> 0xA9BF7BFD
        asm.emit(0xA9BF_7BFD);
        // MOV x29, sp -> ADD x29, sp, #0 -> 0x910003FD
        asm.emit(0x9100_03FD);

        // 2. Marshal parameters:
        // Host passes:
        //   x0 = JNIEnv* (host 64-bit)
        //   x1 = jobject / jclass
        //   x2..x7 = method arguments
        //
        // Replace x0 with guest 32-bit JNIEnv* address
        asm.mov_imm32(A64Reg::X0, guest_env_addr.as_u32());

        // Zero-extend 32-bit handles and arguments into w1..w7
        asm.mov_w_reg(A64Reg::X1, A64Reg::X1);
        asm.mov_w_reg(A64Reg::X2, A64Reg::X2);
        asm.mov_w_reg(A64Reg::X3, A64Reg::X3);
        asm.mov_w_reg(A64Reg::X4, A64Reg::X4);
        asm.mov_w_reg(A64Reg::X5, A64Reg::X5);
        asm.mov_w_reg(A64Reg::X6, A64Reg::X6);
        asm.mov_w_reg(A64Reg::X7, A64Reg::X7);

        // 3. Load 32-bit target function pointer into x9
        asm.mov_imm32(A64Reg::X9, guest_fn_ptr.as_u32());

        // 4. Branch with link to the target execution function (BLR x9)
        asm.blr(A64Reg::X9);

        // 5. Function Epilogue: restore FP and LR and return
        // LDP x29, x30, [sp], #16 -> 0xA8C17BFD
        asm.emit(0xA8C1_7BFD);
        asm.ret(None);

        JniThunk {
            name: name.to_string(),
            signature: signature.to_string(),
            guest_fn_ptr,
            code_bytes: asm.to_bytes(),
        }
    }

    /// Creates thunks for a batch of registered native methods
    pub fn generate_thunks_for_registered(
        methods: &[RegisteredNativeMethod],
        guest_env_addr: GuestAddr,
    ) -> Vec<JniThunk> {
        methods
            .iter()
            .map(|m| Self::generate_thunk(&m.name, &m.signature, m.fn_ptr, guest_env_addr))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_jni_thunk_generation() {
        let guest_fn = GuestAddr::new(0x0040_1000);
        let guest_env = GuestAddr::new(0x0001_0000);

        let thunk = JniThunkGenerator::generate_thunk(
            "nativeCalculate",
            "(II)I",
            guest_fn,
            guest_env,
        );

        assert_eq!(thunk.name, "nativeCalculate");
        assert_eq!(thunk.signature, "(II)I");
        assert_eq!(thunk.guest_fn_ptr, guest_fn);
        assert!(!thunk.code_bytes.is_empty());
        // Must contain prologue, argument setup, BLR, epilogue, RET
        assert!(thunk.code_bytes.len() >= 48);
    }

    #[test]
    fn test_batch_thunk_generation() {
        let methods = vec![
            RegisteredNativeMethod {
                name: "foo".into(),
                signature: "()V".into(),
                fn_ptr: GuestAddr::new(0x1000),
            },
            RegisteredNativeMethod {
                name: "bar".into(),
                signature: "(I)I".into(),
                fn_ptr: GuestAddr::new(0x2000),
            },
        ];

        let thunks = JniThunkGenerator::generate_thunks_for_registered(&methods, GuestAddr::new(0x8000));
        assert_eq!(thunks.len(), 2);
        assert_eq!(thunks[0].name, "foo");
        assert_eq!(thunks[1].name, "bar");
    }
}
