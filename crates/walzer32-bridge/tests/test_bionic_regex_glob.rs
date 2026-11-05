//! Stage 87 integration tests: POSIX Regular Expressions & Pattern Matching APIs
//! Tests: regcomp, regexec, regerror, regfree, fnmatch, glob, globfree, wordexp, wordfree

use walzer32_bridge::bionic::{BionicBridge, BionicFuncId, BIONIC_SVC_MAGIC};
use walzer32_core::{ArenaMemory, CpuState, GuestAddr, Memory, MemoryError, Reg};
use walzer32_elf::loader::SymbolResolver;

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
fn test_regcomp_regexec_submatches_and_regfree() {
    let (mut bridge, mut mem, mut cpu) = setup();

    let preg_addr = GuestAddr::new(HEAP_START + 0x0100);
    let pat_addr = GuestAddr::new(HEAP_START + 0x0200);
    let str_addr = GuestAddr::new(HEAP_START + 0x0300);
    let pmatch_addr = GuestAddr::new(HEAP_START + 0x0400);

    // Pattern: ^([a-z]+):([0-9]+)$
    mem.write_bytes(pat_addr, b"^([a-z]+):([0-9]+)$\0").unwrap();

    // 1. regcomp
    cpu.set_reg(Reg::R0, preg_addr.as_u32());
    cpu.set_reg(Reg::R1, pat_addr.as_u32());
    cpu.set_reg(Reg::R2, 1); // REG_EXTENDED
    call_bionic(&mut bridge, BionicFuncId::Regcomp, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0); // REG_OK

    // Verify preg.re_nsub == 2
    let re_magic = mem.read_u32(preg_addr).unwrap();
    let re_nsub = mem.read_u32(preg_addr.add(4)).unwrap();
    let handle = mem.read_u32(preg_addr.add(12)).unwrap();
    assert_eq!(re_magic, 0x0283);
    assert_eq!(re_nsub, 2);
    assert_ne!(handle, 0);

    // 2. regexec match: "port:8080"
    mem.write_bytes(str_addr, b"port:8080\0").unwrap();

    cpu.set_reg(Reg::R0, preg_addr.as_u32());
    cpu.set_reg(Reg::R1, str_addr.as_u32());
    cpu.set_reg(Reg::R2, 3); // nmatch = 3 (full, group 1, group 2)
    cpu.set_reg(Reg::R3, pmatch_addr.as_u32());
    call_bionic(&mut bridge, BionicFuncId::Regexec, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0); // REG_OK

    // pmatch[0]: full match "port:8080" => (0, 9)
    let so0 = mem.read_u32(pmatch_addr).unwrap();
    let eo0 = mem.read_u32(pmatch_addr.add(4)).unwrap();
    assert_eq!(so0, 0);
    assert_eq!(eo0, 9);

    // pmatch[1]: group 1 "port" => (0, 4)
    let so1 = mem.read_u32(pmatch_addr.add(8)).unwrap();
    let eo1 = mem.read_u32(pmatch_addr.add(12)).unwrap();
    assert_eq!(so1, 0);
    assert_eq!(eo1, 4);

    // pmatch[2]: group 2 "8080" => (5, 9)
    let so2 = mem.read_u32(pmatch_addr.add(16)).unwrap();
    let eo2 = mem.read_u32(pmatch_addr.add(20)).unwrap();
    assert_eq!(so2, 5);
    assert_eq!(eo2, 9);

    // 3. regexec mismatch: "invalid"
    let fail_str_addr = GuestAddr::new(HEAP_START + 0x0500);
    mem.write_bytes(fail_str_addr, b"invalid\0").unwrap();

    cpu.set_reg(Reg::R0, preg_addr.as_u32());
    cpu.set_reg(Reg::R1, fail_str_addr.as_u32());
    cpu.set_reg(Reg::R2, 0);
    cpu.set_reg(Reg::R3, 0);
    call_bionic(&mut bridge, BionicFuncId::Regexec, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 1); // REG_NOMATCH

    // 4. regerror
    let errbuf_addr = GuestAddr::new(HEAP_START + 0x0600);
    cpu.set_reg(Reg::R0, 1); // errcode = 1 (REG_NOMATCH)
    cpu.set_reg(Reg::R1, preg_addr.as_u32());
    cpu.set_reg(Reg::R2, errbuf_addr.as_u32());
    cpu.set_reg(Reg::R3, 64);
    call_bionic(&mut bridge, BionicFuncId::Regerror, &mut cpu, &mut mem).unwrap();
    assert!(cpu.reg(Reg::R0) > 0);

    let mut err_msg = [0u8; 8];
    mem.read_bytes(errbuf_addr, &mut err_msg).unwrap();
    assert_eq!(&err_msg, b"No match");

    // 5. regfree
    cpu.set_reg(Reg::R0, preg_addr.as_u32());
    call_bionic(&mut bridge, BionicFuncId::Regfree, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);
    assert_eq!(mem.read_u32(preg_addr.add(12)).unwrap(), 0);
}

#[test]
fn test_fnmatch() {
    let (mut bridge, mut mem, mut cpu) = setup();

    let pat_addr = GuestAddr::new(HEAP_START + 0x0100);
    let str_addr = GuestAddr::new(HEAP_START + 0x0200);

    // "*.png" vs "sprite.png" -> Match (0)
    mem.write_bytes(pat_addr, b"*.png\0").unwrap();
    mem.write_bytes(str_addr, b"sprite.png\0").unwrap();

    cpu.set_reg(Reg::R0, pat_addr.as_u32());
    cpu.set_reg(Reg::R1, str_addr.as_u32());
    cpu.set_reg(Reg::R2, 0);
    call_bionic(&mut bridge, BionicFuncId::Fnmatch, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);

    // "*.png" vs "sprite.jpg" -> No match (1)
    mem.write_bytes(str_addr, b"sprite.jpg\0").unwrap();
    cpu.set_reg(Reg::R0, pat_addr.as_u32());
    cpu.set_reg(Reg::R1, str_addr.as_u32());
    cpu.set_reg(Reg::R2, 0);
    call_bionic(&mut bridge, BionicFuncId::Fnmatch, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 1);

    // "[0-9]*" vs "42abc" -> Match (0)
    mem.write_bytes(pat_addr, b"[0-9]*\0").unwrap();
    mem.write_bytes(str_addr, b"42abc\0").unwrap();
    cpu.set_reg(Reg::R0, pat_addr.as_u32());
    cpu.set_reg(Reg::R1, str_addr.as_u32());
    cpu.set_reg(Reg::R2, 0);
    call_bionic(&mut bridge, BionicFuncId::Fnmatch, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);
}

#[test]
fn test_glob_and_globfree() {
    let (mut bridge, mut mem, mut cpu) = setup();

    // Register test files in VFS
    bridge.vfs.register_file("/assets/img/hero.png", vec![1]);
    bridge.vfs.register_file("/assets/img/bg.png", vec![2]);
    bridge.vfs.register_file("/assets/audio/theme.ogg", vec![3]);

    let pat_addr = GuestAddr::new(HEAP_START + 0x0100);
    let pglob_addr = GuestAddr::new(HEAP_START + 0x0200);

    mem.write_bytes(pat_addr, b"/assets/img/*.png\0").unwrap();

    cpu.set_reg(Reg::R0, pat_addr.as_u32());
    cpu.set_reg(Reg::R1, 0); // flags = 0
    cpu.set_reg(Reg::R2, 0); // errfunc = NULL
    cpu.set_reg(Reg::R3, pglob_addr.as_u32());
    call_bionic(&mut bridge, BionicFuncId::Glob, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);

    let pathc = mem.read_u32(pglob_addr).unwrap();
    let pathv = GuestAddr::new(mem.read_u32(pglob_addr.add(4)).unwrap());
    assert_eq!(pathc, 2);

    // Read path 0 (sorted: "/assets/img/bg.png")
    let p0 = GuestAddr::new(mem.read_u32(pathv).unwrap());
    let mut p0_bytes = [0u8; 18];
    mem.read_bytes(p0, &mut p0_bytes).unwrap();
    assert_eq!(&p0_bytes, b"/assets/img/bg.png");

    // Read path 1 (sorted: "/assets/img/hero.png")
    let p1 = GuestAddr::new(mem.read_u32(pathv.add(4)).unwrap());
    let mut p1_bytes = [0u8; 20];
    mem.read_bytes(p1, &mut p1_bytes).unwrap();
    assert_eq!(&p1_bytes, b"/assets/img/hero.png");

    // NULL-terminator
    assert_eq!(mem.read_u32(pathv.add(8)).unwrap(), 0);

    // globfree
    cpu.set_reg(Reg::R0, pglob_addr.as_u32());
    call_bionic(&mut bridge, BionicFuncId::Globfree, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);
    assert_eq!(mem.read_u32(pglob_addr).unwrap(), 0);
}

#[test]
fn test_wordexp_and_wordfree() {
    let (mut bridge, mut mem, mut cpu) = setup();

    bridge.env_vars.insert("USER".to_string(), "android_app".to_string());

    let words_addr = GuestAddr::new(HEAP_START + 0x0100);
    let pwordexp_addr = GuestAddr::new(HEAP_START + 0x0200);

    mem.write_bytes(words_addr, b"run $USER --debug\0").unwrap();

    cpu.set_reg(Reg::R0, words_addr.as_u32());
    cpu.set_reg(Reg::R1, pwordexp_addr.as_u32());
    cpu.set_reg(Reg::R2, 0); // flags
    call_bionic(&mut bridge, BionicFuncId::Wordexp, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);

    let wordc = mem.read_u32(pwordexp_addr).unwrap();
    let wordv = GuestAddr::new(mem.read_u32(pwordexp_addr.add(4)).unwrap());
    assert_eq!(wordc, 3);

    // Word 0: "run"
    let w0 = GuestAddr::new(mem.read_u32(wordv).unwrap());
    let mut b0 = [0u8; 3];
    mem.read_bytes(w0, &mut b0).unwrap();
    assert_eq!(&b0, b"run");

    // Word 1: "android_app"
    let w1 = GuestAddr::new(mem.read_u32(wordv.add(4)).unwrap());
    let mut b1 = [0u8; 11];
    mem.read_bytes(w1, &mut b1).unwrap();
    assert_eq!(&b1, b"android_app");

    // Word 2: "--debug"
    let w2 = GuestAddr::new(mem.read_u32(wordv.add(8)).unwrap());
    let mut b2 = [0u8; 7];
    mem.read_bytes(w2, &mut b2).unwrap();
    assert_eq!(&b2, b"--debug");

    // wordfree
    cpu.set_reg(Reg::R0, pwordexp_addr.as_u32());
    call_bionic(&mut bridge, BionicFuncId::Wordfree, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);
}

#[test]
fn test_symbol_resolution() {
    let (bridge, _mem, _cpu) = setup();

    let symbols = [
        "regcomp",
        "regexec",
        "regerror",
        "regfree",
        "fnmatch",
        "glob",
        "globfree",
        "wordexp",
        "wordfree",
    ];

    for sym in symbols {
        let addr = bridge.resolve(sym);
        assert!(addr.is_some(), "Symbol {} must be resolved", sym);
        assert_ne!(addr.unwrap().as_u32(), 0);
    }
}
