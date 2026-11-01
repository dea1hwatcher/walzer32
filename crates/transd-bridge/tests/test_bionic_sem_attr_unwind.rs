use std::collections::HashMap;
use transd_bridge::bionic::{BionicBridge, BionicFuncId, BIONIC_SVC_MAGIC};
use transd_core::{ArenaMemory, CpuState, GuestAddr, Memory, MemoryError, Reg};
use transd_elf::LoadedLibrary;

fn call_bionic(
    bridge: &mut BionicBridge,
    func_id: BionicFuncId,
    cpu: &mut CpuState,
    mem: &mut impl Memory,
) -> Result<bool, MemoryError> {
    bridge.handle_svc(BIONIC_SVC_MAGIC | (func_id as u32), cpu, mem)
}

fn setup() -> (BionicBridge, ArenaMemory, CpuState) {
    let mut mem = ArenaMemory::new().expect("Failed to create arena memory");
    let stub_base = GuestAddr::new(0x10000);
    let heap_start = GuestAddr::new(0x20000);
    mem.commit_range(stub_base, 0x10000).unwrap();
    mem.commit_range(heap_start, 0x10000).unwrap();
    mem.commit_range(GuestAddr::new(0x30000), 0x30000).unwrap();

    let bridge = BionicBridge::new(
        stub_base,
        heap_start,
        1024 * 1024,
    );
    bridge.install_stubs(&mut mem).unwrap();
    let cpu = CpuState::new();
    (bridge, mem, cpu)
}

#[test]
fn test_bionic_semaphores() {
    let (mut bridge, mut mem, mut cpu) = setup();
    let sem_addr = GuestAddr::new(0x30000);
    let sval_addr = GuestAddr::new(0x30010);

    // 1. sem_init(&sem, 0, 2)
    cpu.set_reg(Reg::R0, sem_addr.as_u32());
    cpu.set_reg(Reg::R1, 0);
    cpu.set_reg(Reg::R2, 2);
    call_bionic(&mut bridge, BionicFuncId::SemInit, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);

    // 2. sem_getvalue(&sem, &sval) -> sval == 2
    cpu.set_reg(Reg::R0, sem_addr.as_u32());
    cpu.set_reg(Reg::R1, sval_addr.as_u32());
    call_bionic(&mut bridge, BionicFuncId::SemGetvalue, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);
    assert_eq!(mem.read_u32(sval_addr).unwrap(), 2);

    // 3. sem_wait(&sem) -> count 2 -> 1
    cpu.set_reg(Reg::R0, sem_addr.as_u32());
    call_bionic(&mut bridge, BionicFuncId::SemWait, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);

    cpu.set_reg(Reg::R0, sem_addr.as_u32());
    cpu.set_reg(Reg::R1, sval_addr.as_u32());
    call_bionic(&mut bridge, BionicFuncId::SemGetvalue, &mut cpu, &mut mem).unwrap();
    assert_eq!(mem.read_u32(sval_addr).unwrap(), 1);

    // 4. sem_trywait(&sem) -> count 1 -> 0
    cpu.set_reg(Reg::R0, sem_addr.as_u32());
    call_bionic(&mut bridge, BionicFuncId::SemTrywait, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);

    // 5. sem_trywait(&sem) -> count is 0 -> returns -1 (EAGAIN)
    cpu.set_reg(Reg::R0, sem_addr.as_u32());
    call_bionic(&mut bridge, BionicFuncId::SemTrywait, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0xFFFF_FFFF);

    // 6. sem_post(&sem) -> count 0 -> 1
    cpu.set_reg(Reg::R0, sem_addr.as_u32());
    call_bionic(&mut bridge, BionicFuncId::SemPost, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);

    cpu.set_reg(Reg::R0, sem_addr.as_u32());
    cpu.set_reg(Reg::R1, sval_addr.as_u32());
    call_bionic(&mut bridge, BionicFuncId::SemGetvalue, &mut cpu, &mut mem).unwrap();
    assert_eq!(mem.read_u32(sval_addr).unwrap(), 1);

    // 7. sem_destroy(&sem)
    cpu.set_reg(Reg::R0, sem_addr.as_u32());
    call_bionic(&mut bridge, BionicFuncId::SemDestroy, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);
}

#[test]
fn test_bionic_pthread_attributes() {
    let (mut bridge, mut mem, mut cpu) = setup();
    let attr_addr = GuestAddr::new(0x40000);
    let size_out = GuestAddr::new(0x40020);

    // 1. pthread_attr_init(&attr)
    cpu.set_reg(Reg::R0, attr_addr.as_u32());
    call_bionic(&mut bridge, BionicFuncId::PthreadAttrInit, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);

    // Default stack size is 1MB
    cpu.set_reg(Reg::R0, attr_addr.as_u32());
    cpu.set_reg(Reg::R1, size_out.as_u32());
    call_bionic(&mut bridge, BionicFuncId::PthreadAttrGetstacksize, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);
    assert_eq!(mem.read_u32(size_out).unwrap(), 1024 * 1024);

    // Set stack size to 2MB
    cpu.set_reg(Reg::R0, attr_addr.as_u32());
    cpu.set_reg(Reg::R1, 2 * 1024 * 1024);
    call_bionic(&mut bridge, BionicFuncId::PthreadAttrSetstacksize, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);

    cpu.set_reg(Reg::R0, attr_addr.as_u32());
    cpu.set_reg(Reg::R1, size_out.as_u32());
    call_bionic(&mut bridge, BionicFuncId::PthreadAttrGetstacksize, &mut cpu, &mut mem).unwrap();
    assert_eq!(mem.read_u32(size_out).unwrap(), 2 * 1024 * 1024);

    // Set detachstate to 1 (PTHREAD_CREATE_DETACHED)
    cpu.set_reg(Reg::R0, attr_addr.as_u32());
    cpu.set_reg(Reg::R1, 1);
    call_bionic(&mut bridge, BionicFuncId::PthreadAttrSetdetachstate, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);

    // Destroy attr
    cpu.set_reg(Reg::R0, attr_addr.as_u32());
    call_bionic(&mut bridge, BionicFuncId::PthreadAttrDestroy, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);

    // Mutex attributes
    let mattr_addr = GuestAddr::new(0x40030);
    cpu.set_reg(Reg::R0, mattr_addr.as_u32());
    call_bionic(&mut bridge, BionicFuncId::PthreadMutexattrInit, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);

    cpu.set_reg(Reg::R0, mattr_addr.as_u32());
    cpu.set_reg(Reg::R1, 2); // PTHREAD_MUTEX_RECURSIVE
    call_bionic(&mut bridge, BionicFuncId::PthreadMutexattrSettype, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);
    assert_eq!(mem.read_u32(mattr_addr).unwrap(), 2);

    call_bionic(&mut bridge, BionicFuncId::PthreadMutexattrDestroy, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);

    // Detach thread
    cpu.set_reg(Reg::R0, 1);
    call_bionic(&mut bridge, BionicFuncId::PthreadDetach, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);
}

#[test]
fn test_bionic_strerror_and_strerror_r() {
    let (mut bridge, mut mem, mut cpu) = setup();

    // 1. strerror(0) -> "Success"
    cpu.set_reg(Reg::R0, 0);
    call_bionic(&mut bridge, BionicFuncId::Strerror, &mut cpu, &mut mem).unwrap();
    let str_addr = GuestAddr::new(cpu.reg(Reg::R0));
    let mut s = Vec::new();
    let mut cur = str_addr;
    while let Ok(b) = mem.read_u8(cur) {
        if b == 0 {
            break;
        }
        s.push(b);
        cur = cur.add(1);
    }
    assert_eq!(String::from_utf8(s).unwrap(), "Success");

    // 2. strerror(2) -> "No such file or directory"
    cpu.set_reg(Reg::R0, 2);
    call_bionic(&mut bridge, BionicFuncId::Strerror, &mut cpu, &mut mem).unwrap();
    let str_addr = GuestAddr::new(cpu.reg(Reg::R0));
    let mut s = Vec::new();
    let mut cur = str_addr;
    while let Ok(b) = mem.read_u8(cur) {
        if b == 0 {
            break;
        }
        s.push(b);
        cur = cur.add(1);
    }
    assert_eq!(String::from_utf8(s).unwrap(), "No such file or directory");

    // 3. strerror_r(22, buf, 64) -> "Invalid argument"
    let buf_addr = GuestAddr::new(0x50000);
    cpu.set_reg(Reg::R0, 22);
    cpu.set_reg(Reg::R1, buf_addr.as_u32());
    cpu.set_reg(Reg::R2, 64);
    call_bionic(&mut bridge, BionicFuncId::StrerrorR, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);

    let mut s = Vec::new();
    let mut cur = buf_addr;
    while let Ok(b) = mem.read_u8(cur) {
        if b == 0 {
            break;
        }
        s.push(b);
        cur = cur.add(1);
    }
    assert_eq!(String::from_utf8(s).unwrap(), "Invalid argument");
}

#[test]
fn test_gnu_unwind_find_exidx() {
    let (mut bridge, mut mem, mut cpu) = setup();

    let lib = LoadedLibrary {
        load_base: GuestAddr::new(0x6000_0000),
        total_size: 0x8000,
        soname: Some("libnative.so".to_string()),
        needed: Vec::new(),
        entry_point: GuestAddr::new(0x6000_1000),
        init_func: None,
        init_array: Vec::new(),
        fini_array: Vec::new(),
        symbols: HashMap::new(),
        symbol_details: HashMap::new(),
        tls_template: None,
        exidx_addr: Some(GuestAddr::new(0x6000_4000)),
        exidx_count: 24,
        phdr_addr: GuestAddr::new(0x6000_0034),
        phnum: 6,
    };
    bridge.register_library(lib);

    let pcount_addr = GuestAddr::new(0x50000);

    // Query with PC inside libnative.so (0x6000_1500)
    cpu.set_reg(Reg::R0, 0x6000_1500);
    cpu.set_reg(Reg::R1, pcount_addr.as_u32());
    call_bionic(&mut bridge, BionicFuncId::GnuUnwindFindExidx, &mut cpu, &mut mem).unwrap();

    assert_eq!(cpu.reg(Reg::R0), 0x6000_4000);
    assert_eq!(mem.read_u32(pcount_addr).unwrap(), 24);

    // Query with PC outside any library (0x8000_1500)
    cpu.set_reg(Reg::R0, 0x8000_1500);
    cpu.set_reg(Reg::R1, pcount_addr.as_u32());
    call_bionic(&mut bridge, BionicFuncId::GnuUnwindFindExidx, &mut cpu, &mut mem).unwrap();

    assert_eq!(cpu.reg(Reg::R0), 0);
    assert_eq!(mem.read_u32(pcount_addr).unwrap(), 0);
}
