use transd_core::{FlatMemory, GuestAddr, Memory};
use transd_rt::DbtEngine;

#[test]
fn test_vfs_proc_cpuinfo_syscall() {
    let mut mem = FlatMemory::new(GuestAddr::new(0x1000), 0x4000);

    // Place path string "/proc/cpuinfo\0" at 0x1100
    let path = b"/proc/cpuinfo\0";
    mem.write_bytes(GuestAddr::new(0x1100), path).unwrap();

    // Destination read buffer at 0x1200
    let buf_addr = GuestAddr::new(0x1200);

    // Program at 0x1000:
    // 1. OPEN("/proc/cpuinfo", 0) -> sys_open = 5
    // 0x1000: MOV r0, #0x1100  (LDR/MOV imm)
    // 0x1004: MOV r1, #0
    // 0x1008: MOV r7, #5
    // 0x100C: SVC 0
    // 2. READ(fd, 0x1200, 64) -> sys_read = 3
    // 0x1010: MOV r1, #0x1200
    // 0x1014: MOV r2, #64
    // 0x1018: MOV r7, #3
    // 0x101C: SVC 0
    // 3. EXIT(0) -> sys_exit = 1
    // 0x1020: MOV r0, #0
    // 0x1024: MOV r7, #1
    // 0x1028: SVC 0

    // MOV r0, #0x1100 -> MOV r0, #0x11, 12 (0xE3A0_0C11)
    mem.write_u32(GuestAddr::new(0x1000), 0xE3A0_0C11).unwrap();
    // MOV r1, #0 (0xE3A0_1000)
    mem.write_u32(GuestAddr::new(0x1004), 0xE3A0_1000).unwrap();
    // MOV r7, #5 (0xE3A0_7005)
    mem.write_u32(GuestAddr::new(0x1008), 0xE3A0_7005).unwrap();
    // SVC 0 (0xEF00_0000)
    mem.write_u32(GuestAddr::new(0x100C), 0xEF00_0000).unwrap();

    // MOV r1, #0x1200 -> MOV r1, #0x12, 12 (0xE3A0_1C12)
    mem.write_u32(GuestAddr::new(0x1010), 0xE3A0_1C12).unwrap();
    // MOV r2, #64 (0xE3A0_2040)
    mem.write_u32(GuestAddr::new(0x1014), 0xE3A0_2040).unwrap();
    // MOV r7, #3 (0xE3A0_7003)
    mem.write_u32(GuestAddr::new(0x1018), 0xE3A0_7003).unwrap();
    // SVC 0 (0xEF00_0000)
    mem.write_u32(GuestAddr::new(0x101C), 0xEF00_0000).unwrap();

    // MOV r0, #0 (0xE3A0_0000)
    mem.write_u32(GuestAddr::new(0x1020), 0xE3A0_0000).unwrap();
    // MOV r7, #1 (0xE3A0_7001)
    mem.write_u32(GuestAddr::new(0x1024), 0xE3A0_7001).unwrap();
    // SVC 0 (0xEF00_0000)
    mem.write_u32(GuestAddr::new(0x1028), 0xEF00_0000).unwrap();

    let mut engine = DbtEngine::new(mem);
    engine.cpu.set_pc(GuestAddr::new(0x1000));

    let exit_code = engine.run(50).expect("engine run");
    assert_eq!(exit_code, 0);

    // Read buffer at 0x1200
    let mut data = vec![0u8; 64];
    engine.mem.read_bytes(buf_addr, &mut data).unwrap();
    let text = String::from_utf8_lossy(&data);
    assert!(text.contains("processor"));
    assert!(text.contains("ARMv7"));
}

#[test]
fn test_vfs_uname_returns_armv7l() {
    let mut mem = FlatMemory::new(GuestAddr::new(0x2000), 0x2000);

    // Buffer for struct utsname at 0x2100 (needs 390 bytes)
    let uts_addr = GuestAddr::new(0x2100);

    // 0x2000: MOV r0, #0x2100 (0xE3A0_0C21)
    mem.write_u32(GuestAddr::new(0x2000), 0xE3A0_0C21).unwrap();
    // 0x2004: MOV r7, #122 (sys_uname) (0xE3A0_707A)
    mem.write_u32(GuestAddr::new(0x2004), 0xE3A0_707A).unwrap();
    // 0x2008: SVC 0
    mem.write_u32(GuestAddr::new(0x2008), 0xEF00_0000).unwrap();
    // 0x200C: MOV r7, #1 (sys_exit)
    mem.write_u32(GuestAddr::new(0x200C), 0xE3A0_7001).unwrap();
    // 0x2010: SVC 0
    mem.write_u32(GuestAddr::new(0x2010), 0xEF00_0000).unwrap();

    let mut engine = DbtEngine::new(mem);
    engine.cpu.set_pc(GuestAddr::new(0x2000));

    let _ = engine.run(20).expect("run");

    // Verify utsname fields:
    // sysname is at offset 0 (Linux)
    let mut sysname = [0u8; 6];
    engine.mem.read_bytes(uts_addr, &mut sysname).unwrap();
    assert_eq!(&sysname, b"Linux\0");

    // machine is at offset 260 (armv7l)
    let mut machine = [0u8; 7];
    engine.mem.read_bytes(uts_addr.add(260), &mut machine).unwrap();
    assert_eq!(&machine, b"armv7l\0");
}

#[test]
fn test_vfs_custom_file_and_stat() {
    let mem = FlatMemory::new(GuestAddr::new(0x3000), 0x2000);

    let mut engine = DbtEngine::new(mem);

    // Register custom config file in VFS
    if let Some(vfs) = engine.vfs_mut() {
        vfs.register_file("/data/local/tmp/test.cfg", b"CONFIG_KEY=12345\n".to_vec());
    }

    // Direct test of VFS through engine
    let vfs = engine.vfs_mut().unwrap();
    let fd = vfs.open("/data/local/tmp/test.cfg", 0).unwrap();
    let mut buf = vec![0u8; 32];
    let n = vfs.read(fd, &mut buf).unwrap();
    assert_eq!(&buf[..n], b"CONFIG_KEY=12345\n");

    let st = vfs.fstat64(fd).unwrap();
    assert_eq!(st.st_size, 17);
    vfs.close(fd).unwrap();
}
