//! Stage 88 integration tests: POSIX File Tree Walk, Directory Scanning & Standard Sorting APIs
//! Tests: scandir, scandir64, scandirat, alphasort, alphasort64, versionsort, versionsort64,
//!        ftw, ftw64, nftw, nftw64, qsort, bsearch

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
fn test_scandir_and_alphasort() {
    let (mut bridge, mut mem, mut cpu) = setup();

    bridge.vfs.register_file("/assets/configs/c.json", vec![1]);
    bridge.vfs.register_file("/assets/configs/a.json", vec![2]);
    bridge.vfs.register_file("/assets/configs/b.json", vec![3]);

    let dirp_addr = GuestAddr::new(HEAP_START + 0x0100);
    let namelist_ptr_addr = GuestAddr::new(HEAP_START + 0x0200);

    mem.write_bytes(dirp_addr, b"/assets/configs\0").unwrap();

    // 1. scandir
    cpu.set_reg(Reg::R0, dirp_addr.as_u32());
    cpu.set_reg(Reg::R1, namelist_ptr_addr.as_u32());
    cpu.set_reg(Reg::R2, 0); // filter = NULL
    cpu.set_reg(Reg::R3, 0); // compar = alphasort (default sorted)
    call_bionic(&mut bridge, BionicFuncId::Scandir, &mut cpu, &mut mem).unwrap();
    let count = cpu.reg(Reg::R0) as i32;
    assert_eq!(count, 3);

    // Read array of pointers
    let namelist_addr = GuestAddr::new(mem.read_u32(namelist_ptr_addr).unwrap());
    let d0_addr = GuestAddr::new(mem.read_u32(namelist_addr).unwrap());
    let d1_addr = GuestAddr::new(mem.read_u32(namelist_addr.add(4)).unwrap());
    let d2_addr = GuestAddr::new(mem.read_u32(namelist_addr.add(8)).unwrap());

    // d_name is at offset 19
    let mut name0 = [0u8; 6];
    mem.read_bytes(d0_addr.add(19), &mut name0).unwrap();
    assert_eq!(&name0, b"a.json");

    let mut name1 = [0u8; 6];
    mem.read_bytes(d1_addr.add(19), &mut name1).unwrap();
    assert_eq!(&name1, b"b.json");

    let mut name2 = [0u8; 6];
    mem.read_bytes(d2_addr.add(19), &mut name2).unwrap();
    assert_eq!(&name2, b"c.json");

    // 2. alphasort
    // a.json vs b.json => -1
    cpu.set_reg(Reg::R0, namelist_addr.as_u32());
    cpu.set_reg(Reg::R1, namelist_addr.add(4).as_u32());
    call_bionic(&mut bridge, BionicFuncId::Alphasort, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0) as i32, -1);

    // b.json vs a.json => 1
    cpu.set_reg(Reg::R0, namelist_addr.add(4).as_u32());
    cpu.set_reg(Reg::R1, namelist_addr.as_u32());
    call_bionic(&mut bridge, BionicFuncId::Alphasort, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0) as i32, 1);

    // a.json vs a.json => 0
    cpu.set_reg(Reg::R0, namelist_addr.as_u32());
    cpu.set_reg(Reg::R1, namelist_addr.as_u32());
    call_bionic(&mut bridge, BionicFuncId::Alphasort, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0) as i32, 0);
}

#[test]
fn test_versionsort() {
    let (mut bridge, mut mem, mut cpu) = setup();

    // Create two dirent structs on heap
    let d0_addr = GuestAddr::new(HEAP_START + 0x0100);
    let d1_addr = GuestAddr::new(HEAP_START + 0x0300);

    mem.write_bytes(d0_addr.add(19), b"file2.txt\0").unwrap();
    mem.write_bytes(d1_addr.add(19), b"file10.txt\0").unwrap();

    let ptr0_addr = GuestAddr::new(HEAP_START + 0x0500);
    let ptr1_addr = GuestAddr::new(HEAP_START + 0x0504);

    mem.write_u32(ptr0_addr, d0_addr.as_u32()).unwrap();
    mem.write_u32(ptr1_addr, d1_addr.as_u32()).unwrap();

    // file2.txt vs file10.txt => -1
    cpu.set_reg(Reg::R0, ptr0_addr.as_u32());
    cpu.set_reg(Reg::R1, ptr1_addr.as_u32());
    call_bionic(&mut bridge, BionicFuncId::Versionsort, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0) as i32, -1);

    // file10.txt vs file2.txt => 1
    cpu.set_reg(Reg::R0, ptr1_addr.as_u32());
    cpu.set_reg(Reg::R1, ptr0_addr.as_u32());
    call_bionic(&mut bridge, BionicFuncId::Versionsort, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0) as i32, 1);
}

#[test]
fn test_ftw_and_nftw() {
    let (mut bridge, mut mem, mut cpu) = setup();

    bridge.vfs.register_file("/data/app/lib.so", vec![1, 2]);

    let valid_path = GuestAddr::new(HEAP_START + 0x0100);
    let invalid_path = GuestAddr::new(HEAP_START + 0x0200);

    mem.write_bytes(valid_path, b"/data/app\0").unwrap();
    mem.write_bytes(invalid_path, b"/nonexistent/path\0").unwrap();

    // ftw on valid path => 0
    cpu.set_reg(Reg::R0, valid_path.as_u32());
    cpu.set_reg(Reg::R1, 0x1234); // fn callback
    cpu.set_reg(Reg::R2, 10);     // nopenfd
    call_bionic(&mut bridge, BionicFuncId::Ftw, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);

    // ftw on invalid path => -1
    cpu.set_reg(Reg::R0, invalid_path.as_u32());
    cpu.set_reg(Reg::R1, 0x1234);
    cpu.set_reg(Reg::R2, 10);
    call_bionic(&mut bridge, BionicFuncId::Ftw, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), u32::MAX);

    // nftw on valid path => 0
    cpu.set_reg(Reg::R0, valid_path.as_u32());
    cpu.set_reg(Reg::R1, 0x1234);
    cpu.set_reg(Reg::R2, 10);
    cpu.set_reg(Reg::R3, 0); // flags
    call_bionic(&mut bridge, BionicFuncId::Nftw, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);
}

#[test]
fn test_qsort_and_bsearch() {
    let (mut bridge, mut mem, mut cpu) = setup();

    let array_addr = GuestAddr::new(HEAP_START + 0x0100);
    let values = [42u32, 10, 99, 3, 25];
    for (i, &v) in values.iter().enumerate() {
        mem.write_u32(array_addr.add((i * 4) as u32), v).unwrap();
    }

    // 1. qsort
    cpu.set_reg(Reg::R0, array_addr.as_u32());
    cpu.set_reg(Reg::R1, 5); // nmemb
    cpu.set_reg(Reg::R2, 4); // size
    cpu.set_reg(Reg::R3, 0); // compar
    call_bionic(&mut bridge, BionicFuncId::Qsort, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);

    // Verify sorted: [3, 10, 25, 42, 99]
    let sorted_vals = [
        mem.read_u32(array_addr).unwrap(),
        mem.read_u32(array_addr.add(4)).unwrap(),
        mem.read_u32(array_addr.add(8)).unwrap(),
        mem.read_u32(array_addr.add(12)).unwrap(),
        mem.read_u32(array_addr.add(16)).unwrap(),
    ];
    assert_eq!(sorted_vals, [3, 10, 25, 42, 99]);

    // 2. bsearch for 25 => found at array_addr + 8
    let key_addr = GuestAddr::new(HEAP_START + 0x0200);
    mem.write_u32(key_addr, 25).unwrap();

    cpu.set_reg(Reg::R0, key_addr.as_u32());
    cpu.set_reg(Reg::R1, array_addr.as_u32());
    cpu.set_reg(Reg::R2, 5);
    cpu.set_reg(Reg::R3, 4);
    call_bionic(&mut bridge, BionicFuncId::Bsearch, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), array_addr.add(8).as_u32());

    // 3. bsearch for 100 => not found (0)
    mem.write_u32(key_addr, 100).unwrap();
    cpu.set_reg(Reg::R0, key_addr.as_u32());
    cpu.set_reg(Reg::R1, array_addr.as_u32());
    cpu.set_reg(Reg::R2, 5);
    cpu.set_reg(Reg::R3, 4);
    call_bionic(&mut bridge, BionicFuncId::Bsearch, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);
}

#[test]
fn test_symbol_resolution() {
    let (bridge, _mem, _cpu) = setup();

    let symbols = [
        "scandir",
        "scandir64",
        "scandirat",
        "alphasort",
        "alphasort64",
        "versionsort",
        "versionsort64",
        "ftw",
        "ftw64",
        "nftw",
        "nftw64",
        "qsort",
        "bsearch",
    ];

    for sym in symbols {
        let addr = bridge.resolve(sym);
        assert!(addr.is_some(), "Symbol {} must be resolved", sym);
        assert_ne!(addr.unwrap().as_u32(), 0);
    }
}
