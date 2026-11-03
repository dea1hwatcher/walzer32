//! Tests for core libc fixes: memcmp, strcmp, realloc, malloc_usable_size, and EGL AAPCS stack argument

use transd_bridge::bionic::{BionicBridge, BionicFuncId, BIONIC_SVC_MAGIC};
use transd_bridge::gles::{GlesBridge, GlesFuncId, GLES_SVC_MAGIC, EGL_TRUE};
use transd_core::{ArenaMemory, CpuState, GuestAddr, Memory, Reg};

const STUB_BASE: u32 = 0x0001_0000;
const HEAP_START: u32 = 0x0002_0000;

fn setup() -> (BionicBridge, ArenaMemory, CpuState) {
    let mut mem = ArenaMemory::new().expect("arena");
    let stub_base = GuestAddr::new(STUB_BASE);
    let heap_start = GuestAddr::new(HEAP_START);

    mem.commit_range(stub_base, 0x0001_0000).unwrap();
    mem.commit_range(heap_start, 0x0020_0000).unwrap();

    let bridge = BionicBridge::new(stub_base, heap_start, 512 * 1024);
    bridge.install_stubs(&mut mem).unwrap();
    let cpu = CpuState::new();
    (bridge, mem, cpu)
}

#[test]
fn test_bionic_memcmp() {
    let (mut bridge, mut mem, mut cpu) = setup();

    let buf1 = GuestAddr::new(HEAP_START + 0x1000);
    let buf2 = GuestAddr::new(HEAP_START + 0x2000);

    mem.write_bytes(buf1, b"hello world 1234").unwrap();
    mem.write_bytes(buf2, b"hello world 1234").unwrap();

    // Equal memory comparison
    cpu.set_reg(Reg::R0, buf1.as_u32());
    cpu.set_reg(Reg::R1, buf2.as_u32());
    cpu.set_reg(Reg::R2, 16);
    bridge
        .handle_svc(BIONIC_SVC_MAGIC | (BionicFuncId::Memcmp as u32), &mut cpu, &mut mem)
        .unwrap();
    assert_eq!(cpu.reg(Reg::R0) as i32, 0, "Equal buffers must yield 0 in memcmp");

    // Unequal memory comparison (buf1 < buf2)
    mem.write_bytes(buf2, b"hello world 1235").unwrap();
    cpu.set_reg(Reg::R0, buf1.as_u32());
    cpu.set_reg(Reg::R1, buf2.as_u32());
    cpu.set_reg(Reg::R2, 16);
    bridge
        .handle_svc(BIONIC_SVC_MAGIC | (BionicFuncId::Memcmp as u32), &mut cpu, &mut mem)
        .unwrap();
    assert!(
        (cpu.reg(Reg::R0) as i32) < 0,
        "buf1 < buf2 must yield negative in memcmp"
    );

    // Unequal memory comparison (buf1 > buf2)
    mem.write_bytes(buf2, b"hello world 1233").unwrap();
    cpu.set_reg(Reg::R0, buf1.as_u32());
    cpu.set_reg(Reg::R1, buf2.as_u32());
    cpu.set_reg(Reg::R2, 16);
    bridge
        .handle_svc(BIONIC_SVC_MAGIC | (BionicFuncId::Memcmp as u32), &mut cpu, &mut mem)
        .unwrap();
    assert!(
        (cpu.reg(Reg::R0) as i32) > 0,
        "buf1 > buf2 must yield positive in memcmp"
    );
}

#[test]
fn test_bionic_strcmp() {
    let (mut bridge, mut mem, mut cpu) = setup();

    let s1 = GuestAddr::new(HEAP_START + 0x3000);
    let s2 = GuestAddr::new(HEAP_START + 0x4000);

    mem.write_bytes(s1, b"libtransd.so\0").unwrap();
    mem.write_bytes(s2, b"libtransd.so\0").unwrap();

    // Equal strings
    cpu.set_reg(Reg::R0, s1.as_u32());
    cpu.set_reg(Reg::R1, s2.as_u32());
    bridge
        .handle_svc(BIONIC_SVC_MAGIC | (BionicFuncId::Strcmp as u32), &mut cpu, &mut mem)
        .unwrap();
    assert_eq!(cpu.reg(Reg::R0) as i32, 0, "Equal strings must yield 0 in strcmp");

    // Unequal strings: "libtransd.so" vs "libtransd.a\0"
    mem.write_bytes(s2, b"libtransd.a\0").unwrap();
    cpu.set_reg(Reg::R0, s1.as_u32());
    cpu.set_reg(Reg::R1, s2.as_u32());
    bridge
        .handle_svc(BIONIC_SVC_MAGIC | (BionicFuncId::Strcmp as u32), &mut cpu, &mut mem)
        .unwrap();
    assert!(
        (cpu.reg(Reg::R0) as i32) > 0,
        "Different strings must yield non-zero in strcmp"
    );
}

#[test]
fn test_bionic_realloc_and_usable_size() {
    let (mut bridge, mut mem, mut cpu) = setup();

    // 1. realloc(NULL, 64) == malloc(64)
    cpu.set_reg(Reg::R0, 0);
    cpu.set_reg(Reg::R1, 64);
    bridge
        .handle_svc(BIONIC_SVC_MAGIC | (BionicFuncId::Realloc as u32), &mut cpu, &mut mem)
        .unwrap();
    let ptr = cpu.reg(Reg::R0);
    assert_ne!(ptr, 0, "realloc(NULL, 64) must allocate memory");

    // Write data to verify preservation across realloc
    let test_data = b"Testing realloc data preservation!";
    mem.write_bytes(GuestAddr::new(ptr), test_data).unwrap();

    // Check malloc_usable_size(ptr)
    cpu.set_reg(Reg::R0, ptr);
    bridge
        .handle_svc(BIONIC_SVC_MAGIC | (BionicFuncId::MallocUsableSize as u32), &mut cpu, &mut mem)
        .unwrap();
    assert_eq!(cpu.reg(Reg::R0), 64, "malloc_usable_size must return 64");

    // 2. realloc(ptr, 128) - expand
    cpu.set_reg(Reg::R0, ptr);
    cpu.set_reg(Reg::R1, 128);
    bridge
        .handle_svc(BIONIC_SVC_MAGIC | (BionicFuncId::Realloc as u32), &mut cpu, &mut mem)
        .unwrap();
    let new_ptr = cpu.reg(Reg::R0);
    assert_ne!(new_ptr, 0, "realloc expansion must succeed");

    // Verify data preserved
    let mut read_buf = vec![0u8; test_data.len()];
    mem.read_bytes(GuestAddr::new(new_ptr), &mut read_buf).unwrap();
    assert_eq!(&read_buf, test_data, "Data must be preserved across realloc");

    // 3. realloc(new_ptr, 0) == free(new_ptr)
    cpu.set_reg(Reg::R0, new_ptr);
    cpu.set_reg(Reg::R1, 0);
    bridge
        .handle_svc(BIONIC_SVC_MAGIC | (BionicFuncId::Realloc as u32), &mut cpu, &mut mem)
        .unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0, "realloc(ptr, 0) must return 0");
}

#[test]
fn test_egl_choose_config_aapcs_stack() {
    let mut mem = ArenaMemory::new().expect("arena");
    let gles_stubs = GuestAddr::new(0x0005_0000);
    let gles_heap = GuestAddr::new(0x0006_0000);
    mem.commit_range(gles_stubs, 0x0001_0000).unwrap();
    mem.commit_range(gles_heap, 0x0010_0000).unwrap();

    let mut gles = GlesBridge::new(gles_stubs, gles_heap);
    gles.install_stubs(&mut mem).unwrap();

    let mut cpu = CpuState::new();

    let configs_buf = GuestAddr::new(0x0006_1000);
    let num_config_buf = GuestAddr::new(0x0006_2000);
    let sp_addr = GuestAddr::new(0x0006_F000);

    // Initial state: num_config is 0
    mem.write_u32(num_config_buf, 0).unwrap();

    // Place 5th argument (num_config pointer) on the stack [SP, #0]
    mem.write_u32(sp_addr, num_config_buf.as_u32()).unwrap();
    cpu.set_sp(sp_addr.as_u32());

    // Arguments 1..4 in R0..R3:
    cpu.set_reg(Reg::R0, 0x1000); // dpy
    cpu.set_reg(Reg::R1, 0);      // attrib_list
    cpu.set_reg(Reg::R2, configs_buf.as_u32()); // configs
    cpu.set_reg(Reg::R3, 10);     // config_size
    // Set R4 to garbage to prove it is NOT read!
    cpu.set_reg(Reg::R4, 0xDEAD_BEEF);

    gles.handle_svc(GLES_SVC_MAGIC | (GlesFuncId::EglChooseConfig as u32), &mut cpu, &mut mem)
        .unwrap();

    assert_eq!(cpu.reg(Reg::R0), EGL_TRUE);
    assert_eq!(
        mem.read_u32(num_config_buf).unwrap(),
        1,
        "num_config on stack must receive 1"
    );
    assert_eq!(
        mem.read_u32(configs_buf).unwrap(),
        0x2001,
        "configs must receive valid config handle"
    );
}
