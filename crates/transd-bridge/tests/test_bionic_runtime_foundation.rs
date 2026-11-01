use transd_bridge::{BionicBridge, BionicFuncId, BIONIC_SVC_MAGIC};
use transd_core::{ArenaMemory, CpuState, GuestAddr, Memory, Reg};

fn setup_bridge() -> (BionicBridge, ArenaMemory, CpuState) {
    let mut arena = ArenaMemory::new().expect("Failed to reserve arena");
    let stub_base = GuestAddr::new(0x10000);
    let heap_start = GuestAddr::new(0x20000);
    let data_base = GuestAddr::new(0x40000);
    arena.commit_range(stub_base, 0x10000).unwrap();
    arena.commit_range(heap_start, 0x10000).unwrap();
    arena.commit_range(data_base, 0x10000).unwrap();

    let bridge = BionicBridge::new(stub_base, heap_start, 0x10000);
    bridge.install_stubs(&mut arena).unwrap();

    let mut cpu = CpuState::new();
    cpu.set_reg(Reg::SP, 0x4F000); // Set guest stack pointer

    (bridge, arena, cpu)
}

#[test]
fn test_stack_chk_guard_and_fail() {
    let (mut bridge, arena, mut cpu) = setup_bridge();

    // Verify __stack_chk_guard symbol resolves
    use transd_elf::SymbolResolver;
    let guard_addr = bridge.resolve("__stack_chk_guard").expect("Must resolve __stack_chk_guard");
    assert_eq!(guard_addr, bridge.stack_chk_guard_addr);

    // Verify canary word value
    let canary = arena.read_u32(guard_addr).unwrap();
    assert_eq!(canary, 0x000A_0DFF);

    // Call __stack_chk_fail
    let fail_svc = BIONIC_SVC_MAGIC | (BionicFuncId::StackChkFail as u32);
    let mut mem = arena;
    let res = bridge.handle_svc(fail_svc, &mut cpu, &mut mem);
    assert!(res.is_err());
    assert!(bridge.stack_chk_failed);
}

#[test]
fn test_cxa_atexit_and_finalize() {
    let (mut bridge, mut arena, mut cpu) = setup_bridge();

    // Register 2 destructors
    let func1 = GuestAddr::new(0x21000);
    let func2 = GuestAddr::new(0x22000);
    let dso1 = GuestAddr::new(0x90000);
    let dso2 = GuestAddr::new(0x91000);

    // __cxa_atexit(func1, 42, dso1)
    cpu.set_reg(Reg::R0, func1.as_u32());
    cpu.set_reg(Reg::R1, 42);
    cpu.set_reg(Reg::R2, dso1.as_u32());
    let atexit_svc = BIONIC_SVC_MAGIC | (BionicFuncId::CxaAtexit as u32);
    bridge.handle_svc(atexit_svc, &mut cpu, &mut arena).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);

    // __cxa_atexit(func2, 84, dso2)
    cpu.set_reg(Reg::R0, func2.as_u32());
    cpu.set_reg(Reg::R1, 84);
    cpu.set_reg(Reg::R2, dso2.as_u32());
    bridge.handle_svc(atexit_svc, &mut cpu, &mut arena).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);

    assert_eq!(bridge.atexit_handlers.len(), 2);

    // Finalize dso1 only
    let finalize_svc = BIONIC_SVC_MAGIC | (BionicFuncId::CxaFinalize as u32);
    cpu.set_reg(Reg::R0, dso1.as_u32());
    bridge.handle_svc(finalize_svc, &mut cpu, &mut arena).unwrap();
    assert_eq!(bridge.atexit_handlers.len(), 1);
    assert_eq!(bridge.atexit_handlers[0].2, dso2);

    // Finalize all (dso = NULL)
    cpu.set_reg(Reg::R0, 0);
    bridge.handle_svc(finalize_svc, &mut cpu, &mut arena).unwrap();
    assert!(bridge.atexit_handlers.is_empty());
}

#[test]
fn test_memmove_and_string_functions() {
    let (mut bridge, mut arena, mut cpu) = setup_bridge();
    let data = GuestAddr::new(0x40000);

    // 1. memmove: overlapping memory
    // Initialize [10, 20, 30, 40] at 0x40000
    arena.write_bytes(data, &[10, 20, 30, 40]).unwrap();
    // memmove(data + 1, data, 3) -> should result in [10, 10, 20, 30]
    cpu.set_reg(Reg::R0, data.add(1).as_u32());
    cpu.set_reg(Reg::R1, data.as_u32());
    cpu.set_reg(Reg::R2, 3);
    let memmove_svc = BIONIC_SVC_MAGIC | (BionicFuncId::Memmove as u32);
    bridge.handle_svc(memmove_svc, &mut cpu, &mut arena).unwrap();
    assert_eq!(cpu.reg(Reg::R0), data.add(1).as_u32());

    let mut buf = [0u8; 4];
    arena.read_bytes(data, &mut buf).unwrap();
    assert_eq!(buf, [10, 10, 20, 30]);

    // 2. strncmp
    let s1 = GuestAddr::new(0x40100);
    let s2 = GuestAddr::new(0x40120);
    arena.write_bytes(s1, b"hello_world\0").unwrap();
    arena.write_bytes(s2, b"hello_space\0").unwrap();

    // Compare first 5 bytes ("hello") -> 0
    cpu.set_reg(Reg::R0, s1.as_u32());
    cpu.set_reg(Reg::R1, s2.as_u32());
    cpu.set_reg(Reg::R2, 5);
    let strncmp_svc = BIONIC_SVC_MAGIC | (BionicFuncId::Strncmp as u32);
    bridge.handle_svc(strncmp_svc, &mut cpu, &mut arena).unwrap();
    assert_eq!(cpu.reg(Reg::R0) as i32, 0);

    // Compare 7 bytes ("hello_w" vs "hello_s") -> > 0
    cpu.set_reg(Reg::R0, s1.as_u32());
    cpu.set_reg(Reg::R1, s2.as_u32());
    cpu.set_reg(Reg::R2, 7);
    bridge.handle_svc(strncmp_svc, &mut cpu, &mut arena).unwrap();
    assert!((cpu.reg(Reg::R0) as i32) > 0);

    // 3. strncpy with zero-padding
    let dst = GuestAddr::new(0x40200);
    arena.write_bytes(dst, &[0xFF; 8]).unwrap();
    cpu.set_reg(Reg::R0, dst.as_u32());
    cpu.set_reg(Reg::R1, s1.as_u32()); // "hello_world\0"
    cpu.set_reg(Reg::R2, 4);
    let strncpy_svc = BIONIC_SVC_MAGIC | (BionicFuncId::Strncpy as u32);
    bridge.handle_svc(strncpy_svc, &mut cpu, &mut arena).unwrap();
    let mut dst_buf = [0u8; 8];
    arena.read_bytes(dst, &mut dst_buf).unwrap();
    assert_eq!(&dst_buf[..4], b"hell");
    assert_eq!(dst_buf[4], 0xFF); // Unmodified past n

    // 4. strchr and strrchr
    let strchr_svc = BIONIC_SVC_MAGIC | (BionicFuncId::Strchr as u32);
    let strrchr_svc = BIONIC_SVC_MAGIC | (BionicFuncId::Strrchr as u32);
    cpu.set_reg(Reg::R0, s1.as_u32()); // "hello_world\0"
    cpu.set_reg(Reg::R1, b'l' as u32);
    bridge.handle_svc(strchr_svc, &mut cpu, &mut arena).unwrap();
    assert_eq!(cpu.reg(Reg::R0), s1.add(2).as_u32()); // first 'l' at index 2

    cpu.set_reg(Reg::R0, s1.as_u32());
    cpu.set_reg(Reg::R1, b'l' as u32);
    bridge.handle_svc(strrchr_svc, &mut cpu, &mut arena).unwrap();
    assert_eq!(cpu.reg(Reg::R0), s1.add(9).as_u32()); // last 'l' in "world" at index 9

    // 5. strstr
    let strstr_svc = BIONIC_SVC_MAGIC | (BionicFuncId::Strstr as u32);
    let needle = GuestAddr::new(0x40300);
    arena.write_bytes(needle, b"world\0").unwrap();
    cpu.set_reg(Reg::R0, s1.as_u32());
    cpu.set_reg(Reg::R1, needle.as_u32());
    bridge.handle_svc(strstr_svc, &mut cpu, &mut arena).unwrap();
    assert_eq!(cpu.reg(Reg::R0), s1.add(6).as_u32());
}

#[test]
fn test_strtol_strtoul_atoi() {
    let (mut bridge, mut arena, mut cpu) = setup_bridge();
    let s_dec = GuestAddr::new(0x40400);
    let s_hex = GuestAddr::new(0x40420);
    let s_neg = GuestAddr::new(0x40440);
    let endptr = GuestAddr::new(0x40500);

    arena.write_bytes(s_dec, b"  12345extra\0").unwrap();
    arena.write_bytes(s_hex, b"0x2A\0").unwrap();
    arena.write_bytes(s_neg, b"-999\0").unwrap();

    let strtol_svc = BIONIC_SVC_MAGIC | (BionicFuncId::Strtol as u32);
    let atoi_svc = BIONIC_SVC_MAGIC | (BionicFuncId::Atoi as u32);

    // strtol("  12345extra", &endptr, 10)
    cpu.set_reg(Reg::R0, s_dec.as_u32());
    cpu.set_reg(Reg::R1, endptr.as_u32());
    cpu.set_reg(Reg::R2, 10);
    bridge.handle_svc(strtol_svc, &mut cpu, &mut arena).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 12345);
    assert_eq!(arena.read_u32(endptr).unwrap(), s_dec.add(7).as_u32()); // points to 'e'

    // strtol("0x2A", NULL, 0) -> auto base 16
    cpu.set_reg(Reg::R0, s_hex.as_u32());
    cpu.set_reg(Reg::R1, 0);
    cpu.set_reg(Reg::R2, 0);
    bridge.handle_svc(strtol_svc, &mut cpu, &mut arena).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 42);

    // atoi("-999")
    cpu.set_reg(Reg::R0, s_neg.as_u32());
    bridge.handle_svc(atoi_svc, &mut cpu, &mut arena).unwrap();
    assert_eq!(cpu.reg(Reg::R0) as i32, -999);
}

#[test]
fn test_snprintf_and_sprintf() {
    let (mut bridge, mut arena, mut cpu) = setup_bridge();
    let buf = GuestAddr::new(0x40600);
    let fmt = GuestAddr::new(0x40700);
    let str_arg = GuestAddr::new(0x40800);

    arena.write_bytes(fmt, b"Player %s score=%d hex=0x%x\0").unwrap();
    arena.write_bytes(str_arg, b"Hero\0").unwrap();

    // R0 = buf, R1 = size (64), R2 = fmt, R3 = str_arg
    // SP has stack args: score (100) at SP, hex (0xFF) at SP + 4
    let sp = GuestAddr::new(cpu.reg(Reg::SP));
    arena.write_u32(sp, 100).unwrap();
    arena.write_u32(sp.add(4), 0xFF).unwrap();

    cpu.set_reg(Reg::R0, buf.as_u32());
    cpu.set_reg(Reg::R1, 64);
    cpu.set_reg(Reg::R2, fmt.as_u32());
    cpu.set_reg(Reg::R3, str_arg.as_u32());

    let snprintf_svc = BIONIC_SVC_MAGIC | (BionicFuncId::Snprintf as u32);
    bridge.handle_svc(snprintf_svc, &mut cpu, &mut arena).unwrap();

    let mut out_str = Vec::new();
    let mut cur = buf;
    while arena.read_u8(cur).unwrap() != 0 {
        out_str.push(arena.read_u8(cur).unwrap());
        cur = cur.add(1);
    }
    let res = String::from_utf8(out_str).unwrap();
    assert_eq!(res, "Player Hero score=100 hex=0xff");
    assert_eq!(cpu.reg(Reg::R0), res.len() as u32);
}

#[test]
fn test_clock_gettime_and_gettimeofday() {
    let (mut bridge, mut arena, mut cpu) = setup_bridge();
    let tp = GuestAddr::new(0x40900);
    let tv = GuestAddr::new(0x40920);

    // clock_gettime(CLOCK_MONOTONIC=1, &tp)
    cpu.set_reg(Reg::R0, 1);
    cpu.set_reg(Reg::R1, tp.as_u32());
    let clock_svc = BIONIC_SVC_MAGIC | (BionicFuncId::ClockGettime as u32);
    bridge.handle_svc(clock_svc, &mut cpu, &mut arena).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);

    let sec = arena.read_u32(tp).unwrap();
    let nsec = arena.read_u32(tp.add(4)).unwrap();
    assert!(sec > 0);
    assert!(nsec < 1_000_000_000);

    // gettimeofday(&tv, NULL)
    cpu.set_reg(Reg::R0, tv.as_u32());
    cpu.set_reg(Reg::R1, 0);
    let gettime_svc = BIONIC_SVC_MAGIC | (BionicFuncId::Gettimeofday as u32);
    bridge.handle_svc(gettime_svc, &mut cpu, &mut arena).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);

    let tv_sec = arena.read_u32(tv).unwrap();
    let tv_usec = arena.read_u32(tv.add(4)).unwrap();
    assert!(tv_sec > 0);
    assert!(tv_usec < 1_000_000);
}
