use walzer32_core::{FlatMemory, GuestAddr, Memory, Reg};
use walzer32_rt::{syscall::nr, DbtEngine, SyscallArgs};

#[test]
fn test_rt_clock_gettime_and_gettime64() {
    let mem = FlatMemory::new(GuestAddr::new(0x1000), 0x4000);
    let mut engine = DbtEngine::new(mem);

    // 1. nr::CLOCK_GETTIME (263) -> writes struct timespec { sec: u32, nsec: u32 }
    let tp_addr = 0x2000;
    let args = SyscallArgs {
        nr: nr::CLOCK_GETTIME,
        arg0: 0, // CLOCK_REALTIME
        arg1: tp_addr,
        arg2: 0,
        arg3: 0,
        arg4: 0,
        arg5: 0,
    };
    engine.syscall_handler.handle_syscall(args, &mut engine.cpu, &mut engine.mem).unwrap();
    assert_eq!(engine.cpu.reg(Reg::R0), 0);
    let sec32 = engine.mem.read_u32(GuestAddr::new(tp_addr)).unwrap();
    assert!(sec32 > 1_700_000_000);

    // 2. nr::CLOCK_GETTIME64 (403) -> writes struct timespec64 { sec: u64, nsec: u64 }
    let tp64_addr = 0x2010;
    let args64 = SyscallArgs {
        nr: nr::CLOCK_GETTIME64,
        arg0: 0,
        arg1: tp64_addr,
        arg2: 0,
        arg3: 0,
        arg4: 0,
        arg5: 0,
    };
    engine.syscall_handler.handle_syscall(args64, &mut engine.cpu, &mut engine.mem).unwrap();
    assert_eq!(engine.cpu.reg(Reg::R0), 0);
    let sec_low = engine.mem.read_u32(GuestAddr::new(tp64_addr)).unwrap() as u64;
    let sec_high = engine.mem.read_u32(GuestAddr::new(tp64_addr + 4)).unwrap() as u64;
    let sec64 = (sec_high << 32) | sec_low;
    assert!(sec64 > 1_700_000_000);
}

#[test]
fn test_rt_getrandom_and_prctl() {
    let mem = FlatMemory::new(GuestAddr::new(0x1000), 0x4000);
    let mut engine = DbtEngine::new(mem);

    // 1. nr::GETRANDOM (384)
    let buf_addr = 0x2100;
    let args = SyscallArgs {
        nr: nr::GETRANDOM,
        arg0: buf_addr,
        arg1: 16,
        arg2: 0,
        arg3: 0,
        arg4: 0,
        arg5: 0,
    };
    engine.syscall_handler.handle_syscall(args, &mut engine.cpu, &mut engine.mem).unwrap();
    assert_eq!(engine.cpu.reg(Reg::R0), 16);
    let mut b = [0u8; 16];
    engine.mem.read_bytes(GuestAddr::new(buf_addr), &mut b).unwrap();
    assert!(b.iter().any(|&x| x != 0));

    // 2. nr::PRCTL (172)
    let prctl_args = SyscallArgs {
        nr: nr::PRCTL,
        arg0: 15, // PR_SET_NAME
        arg1: 0x2200,
        arg2: 0,
        arg3: 0,
        arg4: 0,
        arg5: 0,
    };
    engine.syscall_handler.handle_syscall(prctl_args, &mut engine.cpu, &mut engine.mem).unwrap();
    assert_eq!(engine.cpu.reg(Reg::R0), 0);
}

#[test]
fn test_rt_statx_and_pipe2() {
    let mem = FlatMemory::new(GuestAddr::new(0x1000), 0x4000);
    let mut engine = DbtEngine::new(mem);

    // nr::STATX (397)
    let statx_addr = 0x2500;
    let args = SyscallArgs {
        nr: nr::STATX,
        arg0: 0,
        arg1: 0,
        arg2: 0,
        arg3: 0,
        arg4: statx_addr,
        arg5: 0,
    };
    engine.syscall_handler.handle_syscall(args, &mut engine.cpu, &mut engine.mem).unwrap();
    assert_eq!(engine.cpu.reg(Reg::R0), 0);

    // nr::PIPE2 (359)
    let pipe_fds_addr = 0x2600;
    let pipe_args = SyscallArgs {
        nr: nr::PIPE2,
        arg0: pipe_fds_addr,
        arg1: 0,
        arg2: 0,
        arg3: 0,
        arg4: 0,
        arg5: 0,
    };
    engine.syscall_handler.handle_syscall(pipe_args, &mut engine.cpu, &mut engine.mem).unwrap();
    assert_eq!(engine.cpu.reg(Reg::R0), 0);
    let rfd = engine.mem.read_u32(GuestAddr::new(pipe_fds_addr)).unwrap();
    let wfd = engine.mem.read_u32(GuestAddr::new(pipe_fds_addr + 4)).unwrap();
    assert_ne!(rfd, 0);
    assert_ne!(wfd, 0);
}
