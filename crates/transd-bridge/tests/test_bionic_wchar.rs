//! Stage 92 integration tests: Extended Multibyte & Wide Character POSIX APIs
//! Tests: mbrtowc, wcrtomb, mbsrtowcs, wcsrtombs, wcsncmp, wcsncpy, wmemcpy, wmemset,
//!        wmemmove, wmemchr, wcscat, wcsncat, wcschr, wcsrchr

use transd_bridge::bionic::{BionicBridge, BionicFuncId, BIONIC_SVC_MAGIC};
use transd_core::{ArenaMemory, CpuState, GuestAddr, Memory, MemoryError, Reg};
use transd_elf::loader::SymbolResolver;

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

    mem.commit_range(stub_base, 0x0008_0000).expect("commit stub");
    mem.commit_range(heap_start, 0x0010_0000).expect("commit heap");

    let bridge = BionicBridge::new(stub_base, heap_start, 0x0010_0000);
    bridge.install_stubs(&mut mem).expect("stubs");

    let mut cpu = CpuState::new();
    cpu.set_reg(Reg::SP, HEAP_START + 0x0008_0000);

    (bridge, mem, cpu)
}

#[test]
fn test_wchar_symbols() {
    let (bridge, _mem, _cpu) = setup();

    let symbols = [
        "mbrtowc",
        "wcrtomb",
        "mbsrtowcs",
        "wcsrtombs",
        "wcsncmp",
        "wcsncpy",
        "wmemcpy",
        "wmemset",
        "wmemmove",
        "wmemchr",
        "wcscat",
        "wcsncat",
        "wcschr",
        "wcsrchr",
    ];

    for sym in symbols {
        assert!(
            bridge.resolve(sym).is_some(),
            "Symbol {} not resolved by BionicBridge",
            sym
        );
    }
}

#[test]
fn test_mbrtowc_wcrtomb() {
    let (mut bridge, mut mem, mut cpu) = setup();

    let s_addr = GuestAddr::new(HEAP_START + 0x0100);
    let pwc_addr = GuestAddr::new(HEAP_START + 0x0200);
    let out_mb_addr = GuestAddr::new(HEAP_START + 0x0300);

    // 1. Single byte ASCII: 'A' (0x41)
    mem.write_u8(s_addr, b'A').unwrap();
    cpu.set_reg(Reg::R0, pwc_addr.as_u32());
    cpu.set_reg(Reg::R1, s_addr.as_u32());
    cpu.set_reg(Reg::R2, 4); // n
    cpu.set_reg(Reg::R3, 0); // ps
    call_bionic(&mut bridge, BionicFuncId::Mbrtowc, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 1); // 1 byte consumed
    assert_eq!(mem.read_u32(pwc_addr).unwrap(), 0x41);

    // wcrtomb roundtrip for 'A'
    cpu.set_reg(Reg::R0, out_mb_addr.as_u32());
    cpu.set_reg(Reg::R1, 0x41);
    call_bionic(&mut bridge, BionicFuncId::Wcrtomb, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 1);
    assert_eq!(mem.read_u8(out_mb_addr).unwrap(), b'A');

    // 2. 2-byte UTF-8: 'é' (0xC3, 0xA9 -> U+00E9)
    mem.write_u8(s_addr, 0xC3).unwrap();
    mem.write_u8(s_addr.add(1), 0xA9).unwrap();
    cpu.set_reg(Reg::R0, pwc_addr.as_u32());
    cpu.set_reg(Reg::R1, s_addr.as_u32());
    cpu.set_reg(Reg::R2, 4);
    call_bionic(&mut bridge, BionicFuncId::Mbrtowc, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 2);
    assert_eq!(mem.read_u32(pwc_addr).unwrap(), 0x00E9);

    // wcrtomb roundtrip for 'é'
    cpu.set_reg(Reg::R0, out_mb_addr.as_u32());
    cpu.set_reg(Reg::R1, 0x00E9);
    call_bionic(&mut bridge, BionicFuncId::Wcrtomb, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 2);
    assert_eq!(mem.read_u8(out_mb_addr).unwrap(), 0xC3);
    assert_eq!(mem.read_u8(out_mb_addr.add(1)).unwrap(), 0xA9);

    // 3. 3-byte UTF-8: '€' (0xE2, 0x82, 0xAC -> U+20AC)
    mem.write_u8(s_addr, 0xE2).unwrap();
    mem.write_u8(s_addr.add(1), 0x82).unwrap();
    mem.write_u8(s_addr.add(2), 0xAC).unwrap();
    cpu.set_reg(Reg::R0, pwc_addr.as_u32());
    cpu.set_reg(Reg::R1, s_addr.as_u32());
    cpu.set_reg(Reg::R2, 4);
    call_bionic(&mut bridge, BionicFuncId::Mbrtowc, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 3);
    assert_eq!(mem.read_u32(pwc_addr).unwrap(), 0x20AC);

    // wcrtomb roundtrip for '€'
    cpu.set_reg(Reg::R0, out_mb_addr.as_u32());
    cpu.set_reg(Reg::R1, 0x20AC);
    call_bionic(&mut bridge, BionicFuncId::Wcrtomb, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 3);
    assert_eq!(mem.read_u8(out_mb_addr).unwrap(), 0xE2);
    assert_eq!(mem.read_u8(out_mb_addr.add(1)).unwrap(), 0x82);
    assert_eq!(mem.read_u8(out_mb_addr.add(2)).unwrap(), 0xAC);

    // 4. 4-byte UTF-8: 🦀 (0xF0, 0x9F, 0xA6, 0x80 -> U+1F980)
    mem.write_u8(s_addr, 0xF0).unwrap();
    mem.write_u8(s_addr.add(1), 0x9F).unwrap();
    mem.write_u8(s_addr.add(2), 0xA6).unwrap();
    mem.write_u8(s_addr.add(3), 0x80).unwrap();
    cpu.set_reg(Reg::R0, pwc_addr.as_u32());
    cpu.set_reg(Reg::R1, s_addr.as_u32());
    cpu.set_reg(Reg::R2, 4);
    call_bionic(&mut bridge, BionicFuncId::Mbrtowc, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 4);
    assert_eq!(mem.read_u32(pwc_addr).unwrap(), 0x1F980);

    // wcrtomb roundtrip for 🦀
    cpu.set_reg(Reg::R0, out_mb_addr.as_u32());
    cpu.set_reg(Reg::R1, 0x1F980);
    call_bionic(&mut bridge, BionicFuncId::Wcrtomb, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 4);
    assert_eq!(mem.read_u8(out_mb_addr).unwrap(), 0xF0);
    assert_eq!(mem.read_u8(out_mb_addr.add(1)).unwrap(), 0x9F);
    assert_eq!(mem.read_u8(out_mb_addr.add(2)).unwrap(), 0xA6);
    assert_eq!(mem.read_u8(out_mb_addr.add(3)).unwrap(), 0x80);

    // 5. Incomplete sequence (n = 2 for 4-byte sequence) -> (size_t)-2
    cpu.set_reg(Reg::R0, pwc_addr.as_u32());
    cpu.set_reg(Reg::R1, s_addr.as_u32());
    cpu.set_reg(Reg::R2, 2); // n = 2
    call_bionic(&mut bridge, BionicFuncId::Mbrtowc, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), u32::MAX - 1);

    // 6. Null terminator
    mem.write_u8(s_addr, 0).unwrap();
    cpu.set_reg(Reg::R0, pwc_addr.as_u32());
    cpu.set_reg(Reg::R1, s_addr.as_u32());
    cpu.set_reg(Reg::R2, 4);
    call_bionic(&mut bridge, BionicFuncId::Mbrtowc, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);
    assert_eq!(mem.read_u32(pwc_addr).unwrap(), 0);
}

#[test]
fn test_mbsrtowcs_wcsrtombs() {
    let (mut bridge, mut mem, mut cpu) = setup();

    // Source UTF-8 string: "Hi €!" (b'H', b'i', b' ', 0xE2, 0x82, 0xAC, b'!', 0)
    let src_bytes = [b'H', b'i', b' ', 0xE2, 0x82, 0xAC, b'!', 0u8];
    let src_str_addr = GuestAddr::new(HEAP_START + 0x0100);
    for (i, &b) in src_bytes.iter().enumerate() {
        mem.write_u8(src_str_addr.add(i as u32), b).unwrap();
    }

    let src_pptr = GuestAddr::new(HEAP_START + 0x0200);
    mem.write_u32(src_pptr, src_str_addr.as_u32()).unwrap();

    let dest_wcs_addr = GuestAddr::new(HEAP_START + 0x0300);

    // 1. mbsrtowcs(dest, &src, len=10, ps=NULL)
    cpu.set_reg(Reg::R0, dest_wcs_addr.as_u32());
    cpu.set_reg(Reg::R1, src_pptr.as_u32());
    cpu.set_reg(Reg::R2, 10);
    call_bionic(&mut bridge, BionicFuncId::Mbsrtowcs, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 5); // 'H', 'i', ' ', '€', '!' = 5 wide chars
    assert_eq!(mem.read_u32(src_pptr).unwrap(), 0); // *src should be set to NULL on completion

    // Verify wide characters in dest
    assert_eq!(mem.read_u32(dest_wcs_addr).unwrap(), b'H' as u32);
    assert_eq!(mem.read_u32(dest_wcs_addr.add(4)).unwrap(), b'i' as u32);
    assert_eq!(mem.read_u32(dest_wcs_addr.add(8)).unwrap(), b' ' as u32);
    assert_eq!(mem.read_u32(dest_wcs_addr.add(12)).unwrap(), 0x20AC);
    assert_eq!(mem.read_u32(dest_wcs_addr.add(16)).unwrap(), b'!' as u32);
    assert_eq!(mem.read_u32(dest_wcs_addr.add(20)).unwrap(), 0); // null terminator

    // 2. wcsrtombs(dest_mb, &wcs_src, len=20, ps=NULL)
    let dest_mb_addr = GuestAddr::new(HEAP_START + 0x0400);
    let wcs_pptr = GuestAddr::new(HEAP_START + 0x0500);
    mem.write_u32(wcs_pptr, dest_wcs_addr.as_u32()).unwrap();

    cpu.set_reg(Reg::R0, dest_mb_addr.as_u32());
    cpu.set_reg(Reg::R1, wcs_pptr.as_u32());
    cpu.set_reg(Reg::R2, 20);
    call_bionic(&mut bridge, BionicFuncId::Wcsrtombs, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 7); // 1 + 1 + 1 + 3 + 1 = 7 bytes
    assert_eq!(mem.read_u32(wcs_pptr).unwrap(), 0);

    for (i, &expected_b) in src_bytes.iter().enumerate() {
        assert_eq!(
            mem.read_u8(dest_mb_addr.add(i as u32)).unwrap(),
            expected_b
        );
    }
}

#[test]
fn test_wmemcpy_wmemset_wmemmove_wmemchr() {
    let (mut bridge, mut mem, mut cpu) = setup();

    let buf1 = GuestAddr::new(HEAP_START + 0x0100);
    let buf2 = GuestAddr::new(HEAP_START + 0x0200);

    // 1. wmemset(buf1, 0x1234, 5)
    cpu.set_reg(Reg::R0, buf1.as_u32());
    cpu.set_reg(Reg::R1, 0x1234);
    cpu.set_reg(Reg::R2, 5);
    call_bionic(&mut bridge, BionicFuncId::Wmemset, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), buf1.as_u32());
    for i in 0..5 {
        assert_eq!(mem.read_u32(buf1.add(i * 4)).unwrap(), 0x1234);
    }

    // 2. wmemcpy(buf2, buf1, 5)
    cpu.set_reg(Reg::R0, buf2.as_u32());
    cpu.set_reg(Reg::R1, buf1.as_u32());
    cpu.set_reg(Reg::R2, 5);
    call_bionic(&mut bridge, BionicFuncId::Wmemcpy, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), buf2.as_u32());
    for i in 0..5 {
        assert_eq!(mem.read_u32(buf2.add(i * 4)).unwrap(), 0x1234);
    }

    // 3. wmemmove(buf1 + 4, buf1, 4)
    mem.write_u32(buf1, 10).unwrap();
    mem.write_u32(buf1.add(4), 20).unwrap();
    mem.write_u32(buf1.add(8), 30).unwrap();
    mem.write_u32(buf1.add(12), 40).unwrap();

    cpu.set_reg(Reg::R0, buf1.add(4).as_u32());
    cpu.set_reg(Reg::R1, buf1.as_u32());
    cpu.set_reg(Reg::R2, 3); // move 3 words: [10, 20, 30] into [buf1+4 .. buf1+16]
    call_bionic(&mut bridge, BionicFuncId::Wmemmove, &mut cpu, &mut mem).unwrap();
    assert_eq!(mem.read_u32(buf1).unwrap(), 10);
    assert_eq!(mem.read_u32(buf1.add(4)).unwrap(), 10);
    assert_eq!(mem.read_u32(buf1.add(8)).unwrap(), 20);
    assert_eq!(mem.read_u32(buf1.add(12)).unwrap(), 30);

    // 4. wmemchr(buf1, 20, 4) -> finds at buf1 + 8
    cpu.set_reg(Reg::R0, buf1.as_u32());
    cpu.set_reg(Reg::R1, 20);
    cpu.set_reg(Reg::R2, 4);
    call_bionic(&mut bridge, BionicFuncId::Wmemchr, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), buf1.add(8).as_u32());

    // wmemchr not found -> 0
    cpu.set_reg(Reg::R0, buf1.as_u32());
    cpu.set_reg(Reg::R1, 999);
    cpu.set_reg(Reg::R2, 4);
    call_bionic(&mut bridge, BionicFuncId::Wmemchr, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);
}

#[test]
fn test_wcs_string_operations() {
    let (mut bridge, mut mem, mut cpu) = setup();

    let s1 = GuestAddr::new(HEAP_START + 0x0100);
    let s2 = GuestAddr::new(HEAP_START + 0x0200);
    let s3 = GuestAddr::new(HEAP_START + 0x0300);

    // Write "ABC" to s1: [0x41, 0x42, 0x43, 0]
    mem.write_u32(s1, 0x41).unwrap();
    mem.write_u32(s1.add(4), 0x42).unwrap();
    mem.write_u32(s1.add(8), 0x43).unwrap();
    mem.write_u32(s1.add(12), 0).unwrap();

    // Write "ABD" to s2: [0x41, 0x42, 0x44, 0]
    mem.write_u32(s2, 0x41).unwrap();
    mem.write_u32(s2.add(4), 0x42).unwrap();
    mem.write_u32(s2.add(8), 0x44).unwrap();
    mem.write_u32(s2.add(12), 0).unwrap();

    // 1. wcsncmp
    // First 2 chars: equal
    cpu.set_reg(Reg::R0, s1.as_u32());
    cpu.set_reg(Reg::R1, s2.as_u32());
    cpu.set_reg(Reg::R2, 2);
    call_bionic(&mut bridge, BionicFuncId::Wcsncmp, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);

    // 3 chars: s1 < s2
    cpu.set_reg(Reg::R0, s1.as_u32());
    cpu.set_reg(Reg::R1, s2.as_u32());
    cpu.set_reg(Reg::R2, 3);
    call_bionic(&mut bridge, BionicFuncId::Wcsncmp, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0) as i32, -1);

    // 2. wcsncpy(s3, s1, 4)
    cpu.set_reg(Reg::R0, s3.as_u32());
    cpu.set_reg(Reg::R1, s1.as_u32());
    cpu.set_reg(Reg::R2, 4);
    call_bionic(&mut bridge, BionicFuncId::Wcsncpy, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), s3.as_u32());
    assert_eq!(mem.read_u32(s3).unwrap(), 0x41);
    assert_eq!(mem.read_u32(s3.add(4)).unwrap(), 0x42);
    assert_eq!(mem.read_u32(s3.add(8)).unwrap(), 0x43);
    assert_eq!(mem.read_u32(s3.add(12)).unwrap(), 0);

    // 3. wcscat(s3, s2) -> s3 becomes "ABCABD"
    cpu.set_reg(Reg::R0, s3.as_u32());
    cpu.set_reg(Reg::R1, s2.as_u32());
    call_bionic(&mut bridge, BionicFuncId::Wcscat, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), s3.as_u32());
    assert_eq!(mem.read_u32(s3.add(12)).unwrap(), 0x41);
    assert_eq!(mem.read_u32(s3.add(16)).unwrap(), 0x42);
    assert_eq!(mem.read_u32(s3.add(20)).unwrap(), 0x44);
    assert_eq!(mem.read_u32(s3.add(24)).unwrap(), 0);

    // 4. wcschr & wcsrchr
    // s3 = [0x41('A'), 0x42('B'), 0x43('C'), 0x41('A'), 0x42('B'), 0x44('D'), 0]
    // wcschr for 'B' -> s3 + 4
    cpu.set_reg(Reg::R0, s3.as_u32());
    cpu.set_reg(Reg::R1, 0x42);
    call_bionic(&mut bridge, BionicFuncId::Wcschr, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), s3.add(4).as_u32());

    // wcsrchr for 'B' -> s3 + 16
    cpu.set_reg(Reg::R0, s3.as_u32());
    cpu.set_reg(Reg::R1, 0x42);
    call_bionic(&mut bridge, BionicFuncId::Wcsrchr, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), s3.add(16).as_u32());

    // wcsncat: concatenate at most 2 characters
    let s4 = GuestAddr::new(HEAP_START + 0x0400);
    mem.write_u32(s4, 0x58).unwrap(); // 'X'
    mem.write_u32(s4.add(4), 0).unwrap();

    cpu.set_reg(Reg::R0, s4.as_u32());
    cpu.set_reg(Reg::R1, s1.as_u32()); // "ABC"
    cpu.set_reg(Reg::R2, 2); // only take 2 -> "AB"
    call_bionic(&mut bridge, BionicFuncId::Wcsncat, &mut cpu, &mut mem).unwrap();
    assert_eq!(mem.read_u32(s4).unwrap(), 0x58); // 'X'
    assert_eq!(mem.read_u32(s4.add(4)).unwrap(), 0x41); // 'A'
    assert_eq!(mem.read_u32(s4.add(8)).unwrap(), 0x42); // 'B'
    assert_eq!(mem.read_u32(s4.add(12)).unwrap(), 0);
}
