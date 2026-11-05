//! Stage 64 integration tests: String & Printf family
//! Tests: printf, fprintf, sscanf, vprintf, vfprintf, vsprintf, vsnprintf,
//! asprintf, vasprintf, strtof, strtod, strtold, strdup, strndup,
//! strtok, strtok_r, strpbrk, strcspn, strspn, memmem

use walzer32_bridge::bionic::{BionicBridge, BionicFuncId, BIONIC_SVC_MAGIC};
use walzer32_core::{ArenaMemory, CpuState, GuestAddr, Memory, MemoryError, Reg};

const STUB_BASE: u32 = 0x0001_0000;
const HEAP_START: u32 = 0x0002_0000;

fn call_bionic(
    bridge: &mut BionicBridge,
    func_id: BionicFuncId,
    cpu: &mut CpuState,
    mem: &mut impl Memory,
) -> Result<bool, MemoryError> {
    bridge.handle_svc(BIONIC_SVC_MAGIC | (func_id as u32), cpu, mem)
}

fn setup() -> (BionicBridge, ArenaMemory, CpuState) {
    let mut mem = ArenaMemory::new().expect("arena");
    let stub_base = GuestAddr::new(STUB_BASE);
    let heap_start = GuestAddr::new(HEAP_START);

    mem.commit_range(stub_base, 0x0001_0000).unwrap();
    mem.commit_range(heap_start, 0x0010_0000).unwrap();

    let bridge = BionicBridge::new(stub_base, heap_start, 512 * 1024);
    bridge.install_stubs(&mut mem).unwrap();
    let cpu = CpuState::new();
    (bridge, mem, cpu)
}

fn scratch(offset: u32) -> GuestAddr {
    GuestAddr::new(HEAP_START + 0x8000 + offset)
}

fn write_str(mem: &mut impl Memory, addr: GuestAddr, s: &str) {
    let bytes = s.as_bytes();
    for (i, b) in bytes.iter().enumerate() {
        mem.write_u8(addr.add(i as u32), *b).unwrap();
    }
    mem.write_u8(addr.add(bytes.len() as u32), 0).unwrap();
}

fn read_str(mem: &impl Memory, addr: GuestAddr) -> String {
    let mut bytes = Vec::new();
    let mut i = 0u32;
    loop {
        let b = mem.read_u8(addr.add(i)).unwrap_or(0);
        if b == 0 {
            break;
        }
        bytes.push(b);
        i += 1;
    }
    String::from_utf8_lossy(&bytes).into_owned()
}

// ── printf & fprintf ─────────────────────────────────────────────────────────

#[test]
fn test_printf_and_fprintf() {
    let (mut bridge, mut mem, mut cpu) = setup();

    let str_addr = scratch(0);
    write_str(&mut mem, str_addr, "Hello from printf!\n");

    cpu.set_reg(Reg::R0, str_addr.as_u32());
    call_bionic(&mut bridge, BionicFuncId::Printf, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 19);
    assert_eq!(bridge.logs.len(), 1);
    assert_eq!(bridge.logs[0].tag, "stdout");
    assert_eq!(bridge.logs[0].text, "Hello from printf!\n");

    // fprintf to stderr (stream in R0, fmt in R1)
    cpu.set_reg(Reg::R0, 2); // stderr stream
    cpu.set_reg(Reg::R1, str_addr.as_u32());
    call_bionic(&mut bridge, BionicFuncId::Fprintf, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 19);
    assert_eq!(bridge.logs.len(), 2);
    assert_eq!(bridge.logs[1].tag, "stderr");
    assert_eq!(bridge.logs[1].text, "Hello from printf!\n");
}

#[test]
fn test_sscanf_stub() {
    let (mut bridge, mut mem, mut cpu) = setup();
    call_bionic(&mut bridge, BionicFuncId::Sscanf, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);
}

// ── vsprintf & vsnprintf ─────────────────────────────────────────────────────

#[test]
fn test_vsprintf_copies_string() {
    let (mut bridge, mut mem, mut cpu) = setup();
    let buf_addr = scratch(0);
    let fmt_addr = scratch(0x100);
    write_str(&mut mem, fmt_addr, "Formatted 123");

    cpu.set_reg(Reg::R0, buf_addr.as_u32());
    cpu.set_reg(Reg::R1, fmt_addr.as_u32());
    call_bionic(&mut bridge, BionicFuncId::Vsprintf, &mut cpu, &mut mem).unwrap();

    assert_eq!(cpu.reg(Reg::R0), 13);
    assert_eq!(read_str(&mem, buf_addr), "Formatted 123");
}

#[test]
fn test_vsnprintf_truncates() {
    let (mut bridge, mut mem, mut cpu) = setup();
    let buf_addr = scratch(0);
    let fmt_addr = scratch(0x100);
    write_str(&mut mem, fmt_addr, "0123456789");

    // size = 6 (writes 5 chars + null)
    cpu.set_reg(Reg::R0, buf_addr.as_u32());
    cpu.set_reg(Reg::R1, 6);
    cpu.set_reg(Reg::R2, fmt_addr.as_u32());
    call_bionic(&mut bridge, BionicFuncId::Vsnprintf, &mut cpu, &mut mem).unwrap();

    // Returns full string length (10) per POSIX
    assert_eq!(cpu.reg(Reg::R0), 10);
    assert_eq!(read_str(&mem, buf_addr), "01234");
}

// ── asprintf ─────────────────────────────────────────────────────────────────

#[test]
fn test_asprintf_allocates_buffer() {
    let (mut bridge, mut mem, mut cpu) = setup();
    let strp_addr = scratch(0);
    let fmt_addr = scratch(0x100);
    write_str(&mut mem, fmt_addr, "Dynamic String");

    cpu.set_reg(Reg::R0, strp_addr.as_u32());
    cpu.set_reg(Reg::R1, fmt_addr.as_u32());
    call_bionic(&mut bridge, BionicFuncId::Asprintf, &mut cpu, &mut mem).unwrap();

    assert_eq!(cpu.reg(Reg::R0), 14);
    let allocated_ptr = GuestAddr::new(mem.read_u32(strp_addr).unwrap());
    assert_ne!(allocated_ptr.as_u32(), 0);
    assert_eq!(read_str(&mem, allocated_ptr), "Dynamic String");
}

// ── strtof & strtod ──────────────────────────────────────────────────────────

#[test]
fn test_strtof_positive_and_negative() {
    let (mut bridge, mut mem, mut cpu) = setup();
    let str_addr = scratch(0);
    let endptr_addr = scratch(0x100);

    write_str(&mut mem, str_addr, "  -42.5f_rest");

    cpu.set_reg(Reg::R0, str_addr.as_u32());
    cpu.set_reg(Reg::R1, endptr_addr.as_u32());
    call_bionic(&mut bridge, BionicFuncId::Strtof, &mut cpu, &mut mem).unwrap();

    let res_f32 = f32::from_bits(cpu.reg(Reg::R0));
    assert_eq!(res_f32, -42.5);
    assert_eq!(cpu.s_reg(0), -42.5);

    let end_ptr = mem.read_u32(endptr_addr).unwrap();
    // "  -42.5" is 7 bytes
    assert_eq!(end_ptr, str_addr.as_u32() + 7);
}

#[test]
fn test_strtod_scientific_and_endptr() {
    let (mut bridge, mut mem, mut cpu) = setup();
    let str_addr = scratch(0);
    let endptr_addr = scratch(0x100);

    write_str(&mut mem, str_addr, "1.25e3extra");

    cpu.set_reg(Reg::R0, str_addr.as_u32());
    cpu.set_reg(Reg::R1, endptr_addr.as_u32());
    call_bionic(&mut bridge, BionicFuncId::Strtod, &mut cpu, &mut mem).unwrap();

    let bits = (cpu.reg(Reg::R0) as u64) | ((cpu.reg(Reg::R1) as u64) << 32);
    let res_f64 = f64::from_bits(bits);
    assert_eq!(res_f64, 1250.0);
    assert_eq!(cpu.d_reg(0), 1250.0);

    let end_ptr = mem.read_u32(endptr_addr).unwrap();
    // "1.25e3" is 6 bytes
    assert_eq!(end_ptr, str_addr.as_u32() + 6);
}

#[test]
fn test_strtod_infinity_and_nan() {
    let (mut bridge, mut mem, mut cpu) = setup();
    let str_addr = scratch(0);

    // Inf
    write_str(&mut mem, str_addr, "-infinity");
    cpu.set_reg(Reg::R0, str_addr.as_u32());
    cpu.set_reg(Reg::R1, 0); // null endptr
    call_bionic(&mut bridge, BionicFuncId::Strtod, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.d_reg(0), f64::NEG_INFINITY);

    // NaN
    write_str(&mut mem, str_addr, "nan");
    cpu.set_reg(Reg::R0, str_addr.as_u32());
    cpu.set_reg(Reg::R1, 0);
    call_bionic(&mut bridge, BionicFuncId::Strtod, &mut cpu, &mut mem).unwrap();
    assert!(cpu.d_reg(0).is_nan());
}

// ── strdup & strndup ─────────────────────────────────────────────────────────

#[test]
fn test_strdup() {
    let (mut bridge, mut mem, mut cpu) = setup();
    let str_addr = scratch(0);
    write_str(&mut mem, str_addr, "Hello Duplicate");

    cpu.set_reg(Reg::R0, str_addr.as_u32());
    call_bionic(&mut bridge, BionicFuncId::Strdup, &mut cpu, &mut mem).unwrap();

    let dup_ptr = GuestAddr::new(cpu.reg(Reg::R0));
    assert_ne!(dup_ptr.as_u32(), 0);
    assert_ne!(dup_ptr, str_addr);
    assert_eq!(read_str(&mem, dup_ptr), "Hello Duplicate");
}

#[test]
fn test_strndup() {
    let (mut bridge, mut mem, mut cpu) = setup();
    let str_addr = scratch(0);
    write_str(&mut mem, str_addr, "Substring Copy");

    cpu.set_reg(Reg::R0, str_addr.as_u32());
    cpu.set_reg(Reg::R1, 4); // copy 4 bytes
    call_bionic(&mut bridge, BionicFuncId::Strndup, &mut cpu, &mut mem).unwrap();

    let dup_ptr = GuestAddr::new(cpu.reg(Reg::R0));
    assert_ne!(dup_ptr.as_u32(), 0);
    assert_eq!(read_str(&mem, dup_ptr), "Subs");
}

// ── strtok & strtok_r ────────────────────────────────────────────────────────

#[test]
fn test_strtok_multi_tokens() {
    let (mut bridge, mut mem, mut cpu) = setup();
    let str_addr = scratch(0);
    let delim_addr = scratch(0x100);

    write_str(&mut mem, str_addr, "one,two;three");
    write_str(&mut mem, delim_addr, ",;");

    // Token 1: "one"
    cpu.set_reg(Reg::R0, str_addr.as_u32());
    cpu.set_reg(Reg::R1, delim_addr.as_u32());
    call_bionic(&mut bridge, BionicFuncId::Strtok, &mut cpu, &mut mem).unwrap();
    let tok1_ptr = GuestAddr::new(cpu.reg(Reg::R0));
    assert_eq!(read_str(&mem, tok1_ptr), "one");

    // Token 2: "two" (R0 = 0)
    cpu.set_reg(Reg::R0, 0);
    cpu.set_reg(Reg::R1, delim_addr.as_u32());
    call_bionic(&mut bridge, BionicFuncId::Strtok, &mut cpu, &mut mem).unwrap();
    let tok2_ptr = GuestAddr::new(cpu.reg(Reg::R0));
    assert_eq!(read_str(&mem, tok2_ptr), "two");

    // Token 3: "three" (R0 = 0)
    cpu.set_reg(Reg::R0, 0);
    cpu.set_reg(Reg::R1, delim_addr.as_u32());
    call_bionic(&mut bridge, BionicFuncId::Strtok, &mut cpu, &mut mem).unwrap();
    let tok3_ptr = GuestAddr::new(cpu.reg(Reg::R0));
    assert_eq!(read_str(&mem, tok3_ptr), "three");

    // End of tokens
    cpu.set_reg(Reg::R0, 0);
    cpu.set_reg(Reg::R1, delim_addr.as_u32());
    call_bionic(&mut bridge, BionicFuncId::Strtok, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);
}

#[test]
fn test_strtok_r_reentrant() {
    let (mut bridge, mut mem, mut cpu) = setup();
    let str_addr = scratch(0);
    let delim_addr = scratch(0x100);
    let save_addr = scratch(0x200);

    write_str(&mut mem, str_addr, "alpha:beta");
    write_str(&mut mem, delim_addr, ":");
    mem.write_u32(save_addr, 0).unwrap();

    // First call
    cpu.set_reg(Reg::R0, str_addr.as_u32());
    cpu.set_reg(Reg::R1, delim_addr.as_u32());
    cpu.set_reg(Reg::R2, save_addr.as_u32());
    call_bionic(&mut bridge, BionicFuncId::StrtokR, &mut cpu, &mut mem).unwrap();
    let tok1 = GuestAddr::new(cpu.reg(Reg::R0));
    assert_eq!(read_str(&mem, tok1), "alpha");

    // Second call
    cpu.set_reg(Reg::R0, 0);
    cpu.set_reg(Reg::R1, delim_addr.as_u32());
    cpu.set_reg(Reg::R2, save_addr.as_u32());
    call_bionic(&mut bridge, BionicFuncId::StrtokR, &mut cpu, &mut mem).unwrap();
    let tok2 = GuestAddr::new(cpu.reg(Reg::R0));
    assert_eq!(read_str(&mem, tok2), "beta");

    // Third call -> NULL
    cpu.set_reg(Reg::R0, 0);
    cpu.set_reg(Reg::R1, delim_addr.as_u32());
    cpu.set_reg(Reg::R2, save_addr.as_u32());
    call_bionic(&mut bridge, BionicFuncId::StrtokR, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);
}

// ── strpbrk, strcspn, strspn, memmem ─────────────────────────────────────────

#[test]
fn test_strpbrk() {
    let (mut bridge, mut mem, mut cpu) = setup();
    let str_addr = scratch(0);
    let accept_addr = scratch(0x100);

    write_str(&mut mem, str_addr, "abcdef");
    write_str(&mut mem, accept_addr, "xydz");

    cpu.set_reg(Reg::R0, str_addr.as_u32());
    cpu.set_reg(Reg::R1, accept_addr.as_u32());
    call_bionic(&mut bridge, BionicFuncId::Strpbrk, &mut cpu, &mut mem).unwrap();

    let ptr = GuestAddr::new(cpu.reg(Reg::R0));
    assert_eq!(ptr, str_addr.add(3)); // points to 'd'
    assert_eq!(read_str(&mem, ptr), "def");
}

#[test]
fn test_strcspn_and_strspn() {
    let (mut bridge, mut mem, mut cpu) = setup();
    let str_addr = scratch(0);
    let charset_addr = scratch(0x100);

    write_str(&mut mem, str_addr, "12345abcde");
    write_str(&mut mem, charset_addr, "0123456789");

    // strspn counts leading digits -> 5
    cpu.set_reg(Reg::R0, str_addr.as_u32());
    cpu.set_reg(Reg::R1, charset_addr.as_u32());
    call_bionic(&mut bridge, BionicFuncId::Strspn, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 5);

    // strcspn counts characters until first match in "abc" -> 5
    write_str(&mut mem, charset_addr, "abc");
    cpu.set_reg(Reg::R0, str_addr.as_u32());
    cpu.set_reg(Reg::R1, charset_addr.as_u32());
    call_bionic(&mut bridge, BionicFuncId::Strcspn, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 5);
}

#[test]
fn test_memmem() {
    let (mut bridge, mut mem, mut cpu) = setup();
    let hay_addr = scratch(0);
    let ndl_addr = scratch(0x100);

    let hay = b"Quick brown fox jumps";
    let ndl = b"brown";

    for (i, &b) in hay.iter().enumerate() {
        mem.write_u8(hay_addr.add(i as u32), b).unwrap();
    }
    for (i, &b) in ndl.iter().enumerate() {
        mem.write_u8(ndl_addr.add(i as u32), b).unwrap();
    }

    cpu.set_reg(Reg::R0, hay_addr.as_u32());
    cpu.set_reg(Reg::R1, hay.len() as u32);
    cpu.set_reg(Reg::R2, ndl_addr.as_u32());
    cpu.set_reg(Reg::R3, ndl.len() as u32);
    call_bionic(&mut bridge, BionicFuncId::Memmem, &mut cpu, &mut mem).unwrap();

    let found_ptr = GuestAddr::new(cpu.reg(Reg::R0));
    assert_eq!(found_ptr, hay_addr.add(6)); // offset of "brown"
}
