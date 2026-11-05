use walzer32_bridge::{BionicBridge, BionicFuncId, BIONIC_SVC_MAGIC};
use walzer32_core::{CpuState, FlatMemory, GuestAddr, Memory, Reg};

fn setup_test_env() -> (FlatMemory, BionicBridge, CpuState) {
    let stub_base = GuestAddr::new(0x1000_0000);
    let heap_start = GuestAddr::new(0x1001_0000);
    let mut mem = FlatMemory::new(stub_base, 0x10_0000); // 1 MB
    let bridge = BionicBridge::new(stub_base, heap_start, 0x8_0000);
    bridge.install_stubs(&mut mem).expect("Failed to install stubs");
    let cpu = CpuState::new();
    (mem, bridge, cpu)
}

fn call_bionic(
    mem: &mut FlatMemory,
    bridge: &mut BionicBridge,
    cpu: &mut CpuState,
    func_id: BionicFuncId,
    args: &[u32],
) -> u32 {
    if !args.is_empty() {
        cpu.set_reg(Reg::R0, args[0]);
    }
    if args.len() > 1 {
        cpu.set_reg(Reg::R1, args[1]);
    }
    if args.len() > 2 {
        cpu.set_reg(Reg::R2, args[2]);
    }
    if args.len() > 3 {
        cpu.set_reg(Reg::R3, args[3]);
    }

    let imm = BIONIC_SVC_MAGIC | (func_id as u32);
    let handled = bridge
        .handle_svc(imm, cpu, mem)
        .expect("handle_svc failed");
    assert!(handled, "SVC was not handled by bionic bridge");

    cpu.reg(Reg::R0)
}

#[test]
fn test_pthread_key_tls() {
    let (mut mem, mut bridge, mut cpu) = setup_test_env();

    let key1_ptr = GuestAddr::new(0x1008_0000);
    let key2_ptr = GuestAddr::new(0x1008_0004);

    // 1. Create two TLS keys
    let res1 = call_bionic(&mut mem, &mut bridge, &mut cpu, BionicFuncId::PthreadKeyCreate, &[key1_ptr.as_u32(), 0]);
    assert_eq!(res1, 0);
    let key1 = mem.read_u32(key1_ptr).unwrap();
    assert_eq!(key1, 1);

    let res2 = call_bionic(&mut mem, &mut bridge, &mut cpu, BionicFuncId::PthreadKeyCreate, &[key2_ptr.as_u32(), 0]);
    assert_eq!(res2, 0);
    let key2 = mem.read_u32(key2_ptr).unwrap();
    assert_eq!(key2, 2);

    // 2. Set specific values for each key
    let s1 = call_bionic(&mut mem, &mut bridge, &mut cpu, BionicFuncId::PthreadSetspecific, &[key1, 0x1234_5678]);
    assert_eq!(s1, 0);
    let s2 = call_bionic(&mut mem, &mut bridge, &mut cpu, BionicFuncId::PthreadSetspecific, &[key2, 0xABCD_EF01]);
    assert_eq!(s2, 0);

    // 3. Get specific values
    let g1 = call_bionic(&mut mem, &mut bridge, &mut cpu, BionicFuncId::PthreadGetspecific, &[key1]);
    assert_eq!(g1, 0x1234_5678);

    let g2 = call_bionic(&mut mem, &mut bridge, &mut cpu, BionicFuncId::PthreadGetspecific, &[key2]);
    assert_eq!(g2, 0xABCD_EF01);

    // 4. Delete key1
    let d1 = call_bionic(&mut mem, &mut bridge, &mut cpu, BionicFuncId::PthreadKeyDelete, &[key1]);
    assert_eq!(d1, 0);

    // 5. Query deleted key1 -> returns 0
    let g1_after = call_bionic(&mut mem, &mut bridge, &mut cpu, BionicFuncId::PthreadGetspecific, &[key1]);
    assert_eq!(g1_after, 0);

    // 6. Set on deleted key1 -> returns 22 (EINVAL)
    let s1_after = call_bionic(&mut mem, &mut bridge, &mut cpu, BionicFuncId::PthreadSetspecific, &[key1, 0x9999]);
    assert_eq!(s1_after, 22);

    // 7. key2 is untouched
    let g2_after = call_bionic(&mut mem, &mut bridge, &mut cpu, BionicFuncId::PthreadGetspecific, &[key2]);
    assert_eq!(g2_after, 0xABCD_EF01);
}

#[test]
fn test_pthread_cond_and_rwlock() {
    let (mut mem, mut bridge, mut cpu) = setup_test_env();

    let cond_ptr = GuestAddr::new(0x1008_0010);
    let mutex_ptr = GuestAddr::new(0x1008_0014);
    let rwlock_ptr = GuestAddr::new(0x1008_0018);
    let timespec_ptr = GuestAddr::new(0x1008_0020);

    mem.write_u32(timespec_ptr, 1).unwrap();
    mem.write_u32(timespec_ptr.add(4), 500_000).unwrap();

    // Condition variable lifecycle
    assert_eq!(call_bionic(&mut mem, &mut bridge, &mut cpu, BionicFuncId::PthreadCondInit, &[cond_ptr.as_u32(), 0]), 0);
    assert_eq!(mem.read_u32(cond_ptr).unwrap(), 0);

    assert_eq!(call_bionic(&mut mem, &mut bridge, &mut cpu, BionicFuncId::PthreadCondSignal, &[cond_ptr.as_u32()]), 0);
    assert_eq!(call_bionic(&mut mem, &mut bridge, &mut cpu, BionicFuncId::PthreadCondBroadcast, &[cond_ptr.as_u32()]), 0);
    assert_eq!(call_bionic(&mut mem, &mut bridge, &mut cpu, BionicFuncId::PthreadCondWait, &[cond_ptr.as_u32(), mutex_ptr.as_u32()]), 0);
    assert_eq!(call_bionic(&mut mem, &mut bridge, &mut cpu, BionicFuncId::PthreadCondTimedwait, &[cond_ptr.as_u32(), mutex_ptr.as_u32(), timespec_ptr.as_u32()]), 0);
    assert_eq!(call_bionic(&mut mem, &mut bridge, &mut cpu, BionicFuncId::PthreadCondDestroy, &[cond_ptr.as_u32()]), 0);

    // Read-Write Lock lifecycle
    assert_eq!(call_bionic(&mut mem, &mut bridge, &mut cpu, BionicFuncId::PthreadRwlockInit, &[rwlock_ptr.as_u32(), 0]), 0);
    assert_eq!(mem.read_u32(rwlock_ptr).unwrap(), 0);

    assert_eq!(call_bionic(&mut mem, &mut bridge, &mut cpu, BionicFuncId::PthreadRwlockRdlock, &[rwlock_ptr.as_u32()]), 0);
    assert_eq!(call_bionic(&mut mem, &mut bridge, &mut cpu, BionicFuncId::PthreadRwlockUnlock, &[rwlock_ptr.as_u32()]), 0);
    assert_eq!(call_bionic(&mut mem, &mut bridge, &mut cpu, BionicFuncId::PthreadRwlockWrlock, &[rwlock_ptr.as_u32()]), 0);
    assert_eq!(call_bionic(&mut mem, &mut bridge, &mut cpu, BionicFuncId::PthreadRwlockUnlock, &[rwlock_ptr.as_u32()]), 0);
    assert_eq!(call_bionic(&mut mem, &mut bridge, &mut cpu, BionicFuncId::PthreadRwlockDestroy, &[rwlock_ptr.as_u32()]), 0);
}

#[test]
fn test_process_identity_and_sched() {
    let (mut mem, mut bridge, mut cpu) = setup_test_env();

    assert_eq!(call_bionic(&mut mem, &mut bridge, &mut cpu, BionicFuncId::Getpid, &[]), 1000);
    assert_eq!(call_bionic(&mut mem, &mut bridge, &mut cpu, BionicFuncId::Gettid, &[]), 1);
    assert_eq!(call_bionic(&mut mem, &mut bridge, &mut cpu, BionicFuncId::Getuid, &[]), 10000);
    assert_eq!(call_bionic(&mut mem, &mut bridge, &mut cpu, BionicFuncId::Geteuid, &[]), 10000);
    assert_eq!(call_bionic(&mut mem, &mut bridge, &mut cpu, BionicFuncId::Getgid, &[]), 10000);
    assert_eq!(call_bionic(&mut mem, &mut bridge, &mut cpu, BionicFuncId::Getegid, &[]), 10000);

    assert_eq!(call_bionic(&mut mem, &mut bridge, &mut cpu, BionicFuncId::SchedYield, &[]), 0);
    assert_eq!(call_bionic(&mut mem, &mut bridge, &mut cpu, BionicFuncId::Usleep, &[100]), 0);

    let req_ptr = GuestAddr::new(0x1008_0030);
    let rem_ptr = GuestAddr::new(0x1008_0038);
    mem.write_u32(req_ptr, 0).unwrap();
    mem.write_u32(req_ptr.add(4), 1000).unwrap();
    assert_eq!(call_bionic(&mut mem, &mut bridge, &mut cpu, BionicFuncId::Nanosleep, &[req_ptr.as_u32(), rem_ptr.as_u32()]), 0);
}

#[test]
fn test_getenv_and_setenv() {
    let (mut mem, mut bridge, mut cpu) = setup_test_env();

    let write_cstr = |mem: &mut FlatMemory, addr: GuestAddr, s: &str| {
        let b = s.as_bytes();
        mem.write_bytes(addr, b).unwrap();
        mem.write_u8(addr.add(b.len() as u32), 0).unwrap();
    };

    let read_cstr = |mem: &FlatMemory, addr: GuestAddr| -> String {
        let mut bytes = Vec::new();
        let mut cur = addr;
        loop {
            let b = mem.read_u8(cur).unwrap();
            if b == 0 {
                break;
            }
            bytes.push(b);
            cur = cur.add(1);
        }
        String::from_utf8(bytes).unwrap()
    };

    let name1_ptr = GuestAddr::new(0x1008_0040);
    write_cstr(&mut mem, name1_ptr, "ANDROID_DATA");

    let p1 = call_bionic(&mut mem, &mut bridge, &mut cpu, BionicFuncId::Getenv, &[name1_ptr.as_u32()]);
    assert_ne!(p1, 0);
    assert_eq!(read_cstr(&mem, GuestAddr::new(p1)), "/data");

    let name2_ptr = GuestAddr::new(0x1008_0060);
    write_cstr(&mut mem, name2_ptr, "PATH");
    let p2 = call_bionic(&mut mem, &mut bridge, &mut cpu, BionicFuncId::Getenv, &[name2_ptr.as_u32()]);
    assert_ne!(p2, 0);
    assert_eq!(read_cstr(&mem, GuestAddr::new(p2)), "/sbin:/system/sbin:/system/bin:/system/xbin");

    // Non-existent variable
    let name_none_ptr = GuestAddr::new(0x1008_00A0);
    write_cstr(&mut mem, name_none_ptr, "FOO_BAR_BAZ");
    let p_none = call_bionic(&mut mem, &mut bridge, &mut cpu, BionicFuncId::Getenv, &[name_none_ptr.as_u32()]);
    assert_eq!(p_none, 0);

    // Set custom variable
    let custom_name_ptr = GuestAddr::new(0x1008_00C0);
    let custom_val_ptr = GuestAddr::new(0x1008_00E0);
    write_cstr(&mut mem, custom_name_ptr, "CUSTOM_APP_CACHE");
    write_cstr(&mut mem, custom_val_ptr, "/data/data/app/cache");

    let set_res = call_bionic(
        &mut mem,
        &mut bridge,
        &mut cpu,
        BionicFuncId::Setenv,
        &[custom_name_ptr.as_u32(), custom_val_ptr.as_u32(), 0],
    );
    assert_eq!(set_res, 0);

    let p_custom = call_bionic(&mut mem, &mut bridge, &mut cpu, BionicFuncId::Getenv, &[custom_name_ptr.as_u32()]);
    assert_ne!(p_custom, 0);
    assert_eq!(read_cstr(&mem, GuestAddr::new(p_custom)), "/data/data/app/cache");

    // Overwrite=0: should not modify
    let custom_val2_ptr = GuestAddr::new(0x1008_0120);
    write_cstr(&mut mem, custom_val2_ptr, "/should_not_overwrite");
    call_bionic(
        &mut mem,
        &mut bridge,
        &mut cpu,
        BionicFuncId::Setenv,
        &[custom_name_ptr.as_u32(), custom_val2_ptr.as_u32(), 0],
    );
    let p_custom_no_ow = call_bionic(&mut mem, &mut bridge, &mut cpu, BionicFuncId::Getenv, &[custom_name_ptr.as_u32()]);
    assert_eq!(read_cstr(&mem, GuestAddr::new(p_custom_no_ow)), "/data/data/app/cache");

    // Overwrite=1: should modify
    call_bionic(
        &mut mem,
        &mut bridge,
        &mut cpu,
        BionicFuncId::Setenv,
        &[custom_name_ptr.as_u32(), custom_val2_ptr.as_u32(), 1],
    );
    let p_custom_ow = call_bionic(&mut mem, &mut bridge, &mut cpu, BionicFuncId::Getenv, &[custom_name_ptr.as_u32()]);
    assert_eq!(read_cstr(&mem, GuestAddr::new(p_custom_ow)), "/should_not_overwrite");
}
