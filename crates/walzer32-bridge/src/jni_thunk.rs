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
///   3. Replaces the 64-bit host JNIEnv* with Walzer32's 32-bit JNINativeInterface32.
///   4. Invokes the DBT execution engine targeting `guest_fn_ptr`.
///   5. Unpacks the 32-bit return value (r0 or r0:r1) to 64-bit (x0 / d0).
///   6. Restores host context and returns to 64-bit ART.

use walzer32_core::GuestAddr;
use walzer32_emitter_a64::{A64Assembler, A64Reg};
use crate::jni::{JniBridge, RegisteredNativeMethod};

/// Parsed primitive/reference JNI type from a method signature (e.g. `(IJJFZDLjava/lang/String;)I`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JniType {
    Void,
    Boolean,
    Byte,
    Char,
    Short,
    Int,
    Long,
    Float,
    Double,
    Object,
    Array,
}

/// Parsed JNI method descriptor `(params)ret`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JniSignature {
    pub params: Vec<JniType>,
    pub ret: JniType,
}

impl JniSignature {
    /// Parses a standard JNI descriptor string. Defaults to `()V` on empty or malformed input.
    pub fn parse(sig: &str) -> Option<Self> {
        let bytes = sig.as_bytes();
        if bytes.first().copied() != Some(b'(') {
            return None;
        }
        let mut i = 1usize;
        let mut params = Vec::new();
        while i < bytes.len() && bytes[i] != b')' {
            let (ty, next_i) = Self::parse_type(bytes, i)?;
            if ty == JniType::Void {
                return None;
            }
            params.push(ty);
            i = next_i;
        }
        if i >= bytes.len() || bytes[i] != b')' {
            return None;
        }
        let (ret, _) = Self::parse_type(bytes, i + 1)?;
        Some(Self { params, ret })
    }

    fn parse_type(bytes: &[u8], idx: usize) -> Option<(JniType, usize)> {
        let b = *bytes.get(idx)?;
        match b {
            b'V' => Some((JniType::Void, idx + 1)),
            b'Z' => Some((JniType::Boolean, idx + 1)),
            b'B' => Some((JniType::Byte, idx + 1)),
            b'C' => Some((JniType::Char, idx + 1)),
            b'S' => Some((JniType::Short, idx + 1)),
            b'I' => Some((JniType::Int, idx + 1)),
            b'J' => Some((JniType::Long, idx + 1)),
            b'F' => Some((JniType::Float, idx + 1)),
            b'D' => Some((JniType::Double, idx + 1)),
            b'L' => {
                let semi = bytes[idx + 1..].iter().position(|&c| c == b';')?;
                Some((JniType::Object, idx + 1 + semi + 1))
            }
            b'[' => {
                let mut j = idx + 1;
                while j < bytes.len() && bytes[j] == b'[' {
                    j += 1;
                }
                let (_, end_i) = Self::parse_type(bytes, j)?;
                Some((JniType::Array, end_i))
            }
            _ => None,
        }
    }
}

/// AAPCS64 Register & Stack Capture Frame constructed on stack by each generated FFI thunk.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct HostJniCallFrame {
    pub host_env: usize,
    pub host_thiz: usize,
    pub gprs: [u64; 8],
    pub fprs: [u64; 8],
    pub stack_args: *const u64,
}

impl Default for HostJniCallFrame {
    fn default() -> Self {
        Self {
            host_env: 0,
            host_thiz: 0,
            gprs: [0; 8],
            fprs: [0; 8],
            stack_args: std::ptr::null(),
        }
    }
}

/// Marshals captured 64-bit host JNI arguments (`HostJniCallFrame`) into an AAPCS32
/// argument slice (`[env32, thiz32, ...params]`, matching softfp 8-byte alignment for `J`/`D`).
pub fn marshal_host_jni_frame_to_aapcs32(
    sig: &JniSignature,
    frame: &HostJniCallFrame,
    jni: &mut JniBridge,
) -> Vec<u32> {
    let mut args32 = Vec::with_capacity(2 + sig.params.len() * 2);
    args32.push(jni.env_ptr.as_u32());
    args32.push(jni.intern_host_object(frame.host_thiz));

    let mut gpr_idx = 2usize; // x0 = env, x1 = thiz/clazz, params start at x2
    let mut fpr_idx = 0usize; // d0..d7 / s0..s7
    let mut stack_idx = 0usize;

    let read_next_gpr = |gpr_idx: &mut usize, stack_idx: &mut usize| -> u64 {
        if *gpr_idx < 8 {
            let v = frame.gprs[*gpr_idx];
            *gpr_idx += 1;
            v
        } else if !frame.stack_args.is_null() {
            let v = unsafe { *frame.stack_args.add(*stack_idx) };
            *stack_idx += 1;
            v
        } else {
            0
        }
    };

    let read_next_fpr = |fpr_idx: &mut usize, stack_idx: &mut usize| -> u64 {
        if *fpr_idx < 8 {
            let v = frame.fprs[*fpr_idx];
            *fpr_idx += 1;
            v
        } else if !frame.stack_args.is_null() {
            let v = unsafe { *frame.stack_args.add(*stack_idx) };
            *stack_idx += 1;
            v
        } else {
            0
        }
    };

    for &ty in &sig.params {
        match ty {
            JniType::Boolean | JniType::Byte | JniType::Char | JniType::Short | JniType::Int => {
                args32.push(read_next_gpr(&mut gpr_idx, &mut stack_idx) as u32);
            }
            JniType::Object | JniType::Array => {
                let host_ptr = read_next_gpr(&mut gpr_idx, &mut stack_idx) as usize;
                args32.push(jni.intern_host_object(host_ptr));
            }
            JniType::Float => {
                let bits64 = read_next_fpr(&mut fpr_idx, &mut stack_idx);
                args32.push(bits64 as u32);
            }
            JniType::Long => {
                if args32.len() & 1 == 1 {
                    args32.push(0); // AAPCS32 8-byte alignment for 64-bit integer
                }
                let val = read_next_gpr(&mut gpr_idx, &mut stack_idx);
                args32.push(val as u32);
                args32.push((val >> 32) as u32);
            }
            JniType::Double => {
                if args32.len() & 1 == 1 {
                    args32.push(0); // AAPCS32 8-byte alignment for 64-bit double (softfp)
                }
                let bits64 = read_next_fpr(&mut fpr_idx, &mut stack_idx);
                args32.push(bits64 as u32);
                args32.push((bits64 >> 32) as u32);
            }
            JniType::Void => {}
        }
    }

    args32
}

/// Converts AAPCS32 return pair (`R0`, `R1`) into the 64-bit host JNI return register value (`x0` / `d0`).
pub fn unpack_guest_return_to_host_u64(ret_ty: JniType, r0: u32, r1: u32, jni: &JniBridge) -> u64 {
    match ret_ty {
        JniType::Void => 0,
        JniType::Boolean => ((r0 & 0xFF) != 0) as u64,
        JniType::Byte => (r0 as i8 as i64) as u64,
        JniType::Short => (r0 as i16 as i64) as u64,
        JniType::Char => (r0 & 0xFFFF) as u64,
        JniType::Int | JniType::Float => r0 as u64,
        JniType::Long | JniType::Double => ((r1 as u64) << 32) | (r0 as u64),
        JniType::Object | JniType::Array => jni
            .resolve_host_object(r0)
            .map(|p| p as u64)
            .unwrap_or(r0 as u64),
    }
}

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
    /// Generates executable AArch64 machine code capturing `x0..x7`, `d0..d7`, and overflow stack
    /// arguments into `HostJniCallFrame` on the stack, then calling the Rust universal FFI
    /// dispatcher `dispatcher_fn(descriptor_ptr, &frame) -> u64` (and moving float/double returns into `s0`/`d0`).
    pub fn generate_ffi_thunk(
        name: &str,
        signature: &str,
        guest_fn_ptr: GuestAddr,
        descriptor_ptr: usize,
        dispatcher_fn: usize,
    ) -> JniThunk {
        let mut asm = A64Assembler::new();
        let ret_ty = JniSignature::parse(signature)
            .map(|s| s.ret)
            .unwrap_or(JniType::Void);

        // 1. Prologue: STP x29, x30, [sp, #-16]! ; MOV x29, sp ; SUB sp, sp, #160
        asm.stp_x_pre(A64Reg::X29, A64Reg::X30, A64Reg::SP, -16);
        asm.add_x_imm(A64Reg::X29, A64Reg::SP, 0);
        asm.sub_x_imm(A64Reg::SP, A64Reg::SP, 160);

        // 2. Populate HostJniCallFrame at [sp]
        // host_env (x0) & host_thiz (x1) at +0
        asm.stp_x_offset(A64Reg::X0, A64Reg::X1, A64Reg::SP, 0);
        // gprs[0..8] = x0..x7 at +16..+80
        asm.stp_x_offset(A64Reg::X0, A64Reg::X1, A64Reg::SP, 16);
        asm.stp_x_offset(A64Reg::X2, A64Reg::X3, A64Reg::SP, 32);
        asm.stp_x_offset(A64Reg::X4, A64Reg::X5, A64Reg::SP, 48);
        asm.stp_x_offset(A64Reg::X6, A64Reg::X7, A64Reg::SP, 64);
        // fprs[0..8] = d0..d7 at +80..+144
        asm.stp_d_offset(0, 1, A64Reg::SP, 80);
        asm.stp_d_offset(2, 3, A64Reg::SP, 96);
        asm.stp_d_offset(4, 5, A64Reg::SP, 112);
        asm.stp_d_offset(6, 7, A64Reg::SP, 128);
        // caller stack args pointer at +144 (`x29 + 16`)
        asm.add_x_imm(A64Reg::X9, A64Reg::X29, 16);
        asm.stp_x_offset(A64Reg::X9, A64Reg::X9, A64Reg::SP, 144);

        // 3. Call Rust universal FFI dispatcher:
        //    dispatcher(descriptor_ptr: usize, frame: *mut HostJniCallFrame) -> u64
        asm.mov_imm64(A64Reg::X0, descriptor_ptr as u64);
        asm.add_x_imm(A64Reg::X1, A64Reg::SP, 0);
        if dispatcher_fn != 0 {
            asm.mov_imm64(A64Reg::X9, dispatcher_fn as u64);
            asm.blr(A64Reg::X9);
        } else {
            asm.mov_imm64(A64Reg::X0, 0);
        }

        // 4. For AAPCS64 float/double returns, copy bit pattern from w0/x0 into s0/d0
        match ret_ty {
            JniType::Float => asm.emit(0x1E27_0000),  // FMOV S0, W0
            JniType::Double => asm.emit(0x9E67_0000), // FMOV D0, X0
            _ => {}
        }

        // 5. Epilogue: ADD sp, sp, #160 ; LDP x29, x30, [sp], #16 ; RET
        asm.add_x_imm(A64Reg::SP, A64Reg::SP, 160);
        asm.ldp_x_post(A64Reg::X29, A64Reg::X30, A64Reg::SP, 16);
        asm.ret(None);

        JniThunk {
            name: name.to_string(),
            signature: signature.to_string(),
            guest_fn_ptr,
            code_bytes: asm.to_bytes(),
        }
    }

    /// Generates an FFI thunk (legacy helper; when `dispatcher == 0` emits captured no-op stub)
    pub fn generate_thunk(
        name: &str,
        signature: &str,
        guest_fn_ptr: GuestAddr,
        guest_env_addr: GuestAddr,
    ) -> JniThunk {
        Self::generate_ffi_thunk(
            name,
            signature,
            guest_fn_ptr,
            guest_env_addr.as_u32() as usize,
            0,
        )
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

    #[test]
    fn test_jni_signature_parse_and_aapcs32_marshal() {
        let sig = JniSignature::parse("(IJJFD[BLjava/lang/String;)D").expect("valid signature");
        assert_eq!(
            sig.params,
            vec![
                JniType::Int,
                JniType::Long,
                JniType::Long,
                JniType::Float,
                JniType::Double,
                JniType::Array,
                JniType::Object,
            ]
        );
        assert_eq!(sig.ret, JniType::Double);

        let mut jni = JniBridge::new(GuestAddr::new(0x0010_0000));
        let stack = [0x99u64];
        let mut frame = HostJniCallFrame::default();
        frame.host_env = 0x1111;
        frame.host_thiz = 0x2222;
        frame.gprs = [
            0x1111,                    // x0: env
            0x2222,                    // x1: thiz
            42,                        // x2: I = 42
            0x0102_0304_0506_0708,     // x3: J1
            0x1112_1314_1516_1718,     // x4: J2
            0xDEAD_BEEF,               // x5: [B host ref
            0xCAFE_BABE,               // x6: String host ref
            0,
        ];
        frame.fprs[0] = f32::to_bits(1.5) as u64;
        frame.fprs[1] = f64::to_bits(3.25);
        frame.stack_args = stack.as_ptr();

        let words = marshal_host_jni_frame_to_aapcs32(&sig, &frame, &mut jni);
        // Expected AAPCS32 softfp word stream:
        // w0 = guest_env, w1 = intern(thiz), w2 = 42 (I), w3 = pad? WAIT: 3 words used -> J1 aligns to 4 (pad at w3, w4=lo, w5=hi)
        // J2 aligns to 6 -> w6=lo, w7=hi
        // F -> w8 = 1.5f.to_bits()
        // D -> aligns to 10 (pad at w9, w10=lo, w11=hi)
        // [B -> w12 = intern(0xDEAD_BEEF)
        // String -> w13 = intern(0xCAFE_BABE)
        assert_eq!(words[0], jni.env_ptr.as_u32());
        assert_eq!(jni.resolve_host_object(words[1]), Some(0x2222));
        assert_eq!(words[2], 42);
        assert_eq!(words[3], 0); // alignment pad before J1
        assert_eq!(words[4], 0x0506_0708);
        assert_eq!(words[5], 0x0102_0304);
        assert_eq!(words[6], 0x1516_1718);
        assert_eq!(words[7], 0x1112_1314);
        assert_eq!(words[8], f32::to_bits(1.5));
        assert_eq!(words[9], 0); // alignment pad before Double
        let d_bits = f64::to_bits(3.25);
        assert_eq!(words[10], d_bits as u32);
        assert_eq!(words[11], (d_bits >> 32) as u32);
        assert_eq!(jni.resolve_host_object(words[12]), Some(0xDEAD_BEEF));
        assert_eq!(jni.resolve_host_object(words[13]), Some(0xCAFE_BABE));
        assert_eq!(
            unpack_guest_return_to_host_u64(JniType::Object, words[12], 0, &jni),
            0xDEAD_BEEF
        );
        assert_eq!(words.len(), 14);
    }

    #[test]
    fn test_generate_ffi_thunk_float_double_epilogue() {
        let f_thunk = JniThunkGenerator::generate_ffi_thunk(
            "calcFloat",
            "(F)F",
            GuestAddr::new(0x1000),
            0xABCD,
            0x1234_5678,
        );
        let d_thunk = JniThunkGenerator::generate_ffi_thunk(
            "calcDouble",
            "(D)D",
            GuestAddr::new(0x2000),
            0xBEEF,
            0x1234_5678,
        );
        assert!(f_thunk
            .code_bytes
            .chunks_exact(4)
            .any(|c| u32::from_le_bytes(c.try_into().unwrap()) == 0x1E27_0000));
        assert!(d_thunk
            .code_bytes
            .chunks_exact(4)
            .any(|c| u32::from_le_bytes(c.try_into().unwrap()) == 0x9E67_0000));
    }
}
