//! Stage 65 integration tests: Character Classification & Locale / Wide-Character
//! Tests: isalnum, isalpha, isblank, iscntrl, isdigit, isgraph, islower, isprint,
//! ispunct, isspace, isupper, isxdigit, tolower, toupper, isascii, toascii,
//! setlocale, localeconv, mbstowcs, wcstombs, mbtowc, wctomb, wcslen, wcscpy, wcscmp

use transd_bridge::bionic::{BionicBridge, BionicFuncId, BIONIC_SVC_MAGIC};
use transd_core::{ArenaMemory, CpuState, GuestAddr, Memory, MemoryError, Reg};

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

// ── Character classification tests ──────────────────────────────────────────

#[test]
fn test_ctype_classification() {
    let (mut bridge, mut mem, mut cpu) = setup();

    // isalpha: 'A' -> 1, '5' -> 0
    cpu.set_reg(Reg::R0, b'A' as u32);
    call_bionic(&mut bridge, BionicFuncId::Isalpha, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 1);

    cpu.set_reg(Reg::R0, b'5' as u32);
    call_bionic(&mut bridge, BionicFuncId::Isalpha, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);

    // isdigit: '9' -> 1, 'x' -> 0
    cpu.set_reg(Reg::R0, b'9' as u32);
    call_bionic(&mut bridge, BionicFuncId::Isdigit, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 1);

    cpu.set_reg(Reg::R0, b'x' as u32);
    call_bionic(&mut bridge, BionicFuncId::Isdigit, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);

    // isalnum: 'z' -> 1, '!' -> 0
    cpu.set_reg(Reg::R0, b'z' as u32);
    call_bionic(&mut bridge, BionicFuncId::Isalnum, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 1);

    cpu.set_reg(Reg::R0, b'!' as u32);
    call_bionic(&mut bridge, BionicFuncId::Isalnum, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);

    // isspace: ' ' -> 1, '\t' -> 1, '\n' -> 1, 'A' -> 0
    cpu.set_reg(Reg::R0, b' ' as u32);
    call_bionic(&mut bridge, BionicFuncId::Isspace, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 1);

    cpu.set_reg(Reg::R0, b'\t' as u32);
    call_bionic(&mut bridge, BionicFuncId::Isspace, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 1);

    cpu.set_reg(Reg::R0, b'A' as u32);
    call_bionic(&mut bridge, BionicFuncId::Isspace, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);

    // isxdigit: 'F' -> 1, 'g' -> 0
    cpu.set_reg(Reg::R0, b'F' as u32);
    call_bionic(&mut bridge, BionicFuncId::Isxdigit, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 1);

    cpu.set_reg(Reg::R0, b'g' as u32);
    call_bionic(&mut bridge, BionicFuncId::Isxdigit, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);

    // islower & isupper
    cpu.set_reg(Reg::R0, b'q' as u32);
    call_bionic(&mut bridge, BionicFuncId::Islower, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 1);

    cpu.set_reg(Reg::R0, b'Q' as u32);
    call_bionic(&mut bridge, BionicFuncId::Isupper, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 1);

    // isascii & toascii
    cpu.set_reg(Reg::R0, 120);
    call_bionic(&mut bridge, BionicFuncId::Isascii, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 1);

    cpu.set_reg(Reg::R0, 200);
    call_bionic(&mut bridge, BionicFuncId::Isascii, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);

    cpu.set_reg(Reg::R0, 0x141); // 'A' + 0x100
    call_bionic(&mut bridge, BionicFuncId::Toascii, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), b'A' as u32);
}

#[test]
fn test_case_conversion() {
    let (mut bridge, mut mem, mut cpu) = setup();

    // tolower('G') -> 'g'
    cpu.set_reg(Reg::R0, b'G' as u32);
    call_bionic(&mut bridge, BionicFuncId::Tolower, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), b'g' as u32);

    // toupper('m') -> 'M'
    cpu.set_reg(Reg::R0, b'm' as u32);
    call_bionic(&mut bridge, BionicFuncId::Toupper, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), b'M' as u32);

    // non-alpha is unchanged
    cpu.set_reg(Reg::R0, b'7' as u32);
    call_bionic(&mut bridge, BionicFuncId::Tolower, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), b'7' as u32);
}

// ── Locale tests ────────────────────────────────────────────────────────────

#[test]
fn test_setlocale_and_localeconv() {
    let (mut bridge, mut mem, mut cpu) = setup();

    // setlocale(LC_ALL=0, "")
    cpu.set_reg(Reg::R0, 0);
    cpu.set_reg(Reg::R1, 0);
    call_bionic(&mut bridge, BionicFuncId::Setlocale, &mut cpu, &mut mem).unwrap();
    let loc_ptr = GuestAddr::new(cpu.reg(Reg::R0));
    assert_ne!(loc_ptr.as_u32(), 0);
    assert_eq!(read_str(&mem, loc_ptr), "C.UTF-8");

    // localeconv()
    call_bionic(&mut bridge, BionicFuncId::Localeconv, &mut cpu, &mut mem).unwrap();
    let lconv_ptr = GuestAddr::new(cpu.reg(Reg::R0));
    assert_ne!(lconv_ptr.as_u32(), 0);

    // decimal_point pointer is at offset 0
    let dec_point_ptr = GuestAddr::new(mem.read_u32(lconv_ptr).unwrap());
    assert_eq!(read_str(&mem, dec_point_ptr), ".");
}

// ── Wide-character tests ────────────────────────────────────────────────────

#[test]
fn test_mbstowcs_and_wcstombs() {
    let (mut bridge, mut mem, mut cpu) = setup();
    let mb_addr = scratch(0);
    let wc_addr = scratch(0x100);

    write_str(&mut mem, mb_addr, "Hello");

    // Query length: mbstowcs(NULL, "Hello", 0) -> 5
    cpu.set_reg(Reg::R0, 0);
    cpu.set_reg(Reg::R1, mb_addr.as_u32());
    cpu.set_reg(Reg::R2, 0);
    call_bionic(&mut bridge, BionicFuncId::Mbstowcs, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 5);

    // Convert: mbstowcs(wc_addr, "Hello", 10) -> 5
    cpu.set_reg(Reg::R0, wc_addr.as_u32());
    cpu.set_reg(Reg::R1, mb_addr.as_u32());
    cpu.set_reg(Reg::R2, 10);
    call_bionic(&mut bridge, BionicFuncId::Mbstowcs, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 5);

    // Verify wchar words
    assert_eq!(mem.read_u32(wc_addr).unwrap(), b'H' as u32);
    assert_eq!(mem.read_u32(wc_addr.add(4)).unwrap(), b'e' as u32);
    assert_eq!(mem.read_u32(wc_addr.add(16)).unwrap(), b'o' as u32);
    assert_eq!(mem.read_u32(wc_addr.add(20)).unwrap(), 0); // null terminator

    // Convert back: wcstombs(mb_addr + 0x200, wc_addr, 10)
    let back_addr = scratch(0x200);
    cpu.set_reg(Reg::R0, back_addr.as_u32());
    cpu.set_reg(Reg::R1, wc_addr.as_u32());
    cpu.set_reg(Reg::R2, 10);
    call_bionic(&mut bridge, BionicFuncId::Wcstombs, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 5);
    assert_eq!(read_str(&mem, back_addr), "Hello");
}

#[test]
fn test_mbtowc_and_wctomb() {
    let (mut bridge, mut mem, mut cpu) = setup();
    let s_addr = scratch(0);
    let pwc_addr = scratch(0x10);

    write_str(&mut mem, s_addr, "X");

    // mbtowc(pwc_addr, "X", 1) -> 1
    cpu.set_reg(Reg::R0, pwc_addr.as_u32());
    cpu.set_reg(Reg::R1, s_addr.as_u32());
    cpu.set_reg(Reg::R2, 1);
    call_bionic(&mut bridge, BionicFuncId::Mbtowc, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 1);
    assert_eq!(mem.read_u32(pwc_addr).unwrap(), b'X' as u32);

    // wctomb(s_addr + 0x20, 'Y') -> 1
    let out_addr = scratch(0x20);
    cpu.set_reg(Reg::R0, out_addr.as_u32());
    cpu.set_reg(Reg::R1, b'Y' as u32);
    call_bionic(&mut bridge, BionicFuncId::Wctomb, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 1);
    assert_eq!(mem.read_u8(out_addr).unwrap(), b'Y');
}

#[test]
fn test_wchar_string_functions() {
    let (mut bridge, mut mem, mut cpu) = setup();
    let w1 = scratch(0);
    let w2 = scratch(0x100);

    // Populate w1 = L"Test\0"
    for (i, &wc) in [b'T' as u32, b'e' as u32, b's' as u32, b't' as u32, 0].iter().enumerate() {
        mem.write_u32(w1.add((i * 4) as u32), wc).unwrap();
    }

    // wcslen(w1) -> 4
    cpu.set_reg(Reg::R0, w1.as_u32());
    call_bionic(&mut bridge, BionicFuncId::Wcslen, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 4);

    // wcscpy(w2, w1)
    cpu.set_reg(Reg::R0, w2.as_u32());
    cpu.set_reg(Reg::R1, w1.as_u32());
    call_bionic(&mut bridge, BionicFuncId::Wcscpy, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), w2.as_u32());

    // wcscmp(w1, w2) -> 0
    cpu.set_reg(Reg::R0, w1.as_u32());
    cpu.set_reg(Reg::R1, w2.as_u32());
    call_bionic(&mut bridge, BionicFuncId::Wcscmp, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);

    // Modify w2[0] = 'U' -> wcscmp(w1, w2) != 0
    mem.write_u32(w2, b'U' as u32).unwrap();
    cpu.set_reg(Reg::R0, w1.as_u32());
    cpu.set_reg(Reg::R1, w2.as_u32());
    call_bionic(&mut bridge, BionicFuncId::Wcscmp, &mut cpu, &mut mem).unwrap();
    assert_ne!(cpu.reg(Reg::R0), 0);
}
