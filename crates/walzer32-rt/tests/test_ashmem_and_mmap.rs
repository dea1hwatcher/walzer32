use walzer32_core::{CpuState, FlatMemory, GuestAddr, Memory, Reg};
use walzer32_rt::syscall::{ashmem_cmd, nr, SyscallArgs};
use walzer32_rt::DbtEngine;

#[test]
fn test_ashmem_ioctl_and_mmap_lifecycle() {
    let mem = FlatMemory::new(GuestAddr::new(0x7000_0000), 0x200_000);
    let mut engine = DbtEngine::new(mem);
    engine.set_mmap_base(GuestAddr::new(0x7010_0000));

    // 1. Open /dev/ashmem via VFS
    let ashmem_path_addr = GuestAddr::new(0x7000_1000);
    engine.mem.write_bytes(ashmem_path_addr, b"/dev/ashmem\0").unwrap();

    let mut cpu = CpuState::default();
    cpu.set_reg(Reg::R7, nr::OPEN);
    cpu.set_reg(Reg::R0, ashmem_path_addr.as_u32());
    cpu.set_reg(Reg::R1, 2); // O_RDWR
    let args = SyscallArgs::from_cpu(&cpu);
    engine.syscall_handler.handle_syscall(args, &mut cpu, &mut engine.mem).unwrap();
    let fd = cpu.reg(Reg::R0);
    assert!(fd >= 3, "ashmem fd must be >= 3");

    // 2. Set ashmem name via ioctl(fd, ASHMEM_SET_NAME, "test_texture_buf")
    let name_buf_addr = GuestAddr::new(0x7000_2000);
    engine.mem.write_bytes(name_buf_addr, b"test_texture_buf\0").unwrap();

    cpu.set_reg(Reg::R7, nr::IOCTL);
    cpu.set_reg(Reg::R0, fd);
    cpu.set_reg(Reg::R1, ashmem_cmd::ASHMEM_SET_NAME);
    cpu.set_reg(Reg::R2, name_buf_addr.as_u32());
    let args = SyscallArgs::from_cpu(&cpu);
    engine.syscall_handler.handle_syscall(args, &mut cpu, &mut engine.mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0, "ASHMEM_SET_NAME must succeed");

    // 3. Set ashmem size via ioctl(fd, ASHMEM_SET_SIZE, 8192)
    cpu.set_reg(Reg::R7, nr::IOCTL);
    cpu.set_reg(Reg::R0, fd);
    cpu.set_reg(Reg::R1, ashmem_cmd::ASHMEM_SET_SIZE);
    cpu.set_reg(Reg::R2, 8192);
    let args = SyscallArgs::from_cpu(&cpu);
    engine.syscall_handler.handle_syscall(args, &mut cpu, &mut engine.mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0, "ASHMEM_SET_SIZE must succeed");

    // 4. Query ashmem size via ioctl(fd, ASHMEM_GET_SIZE, 0)
    cpu.set_reg(Reg::R7, nr::IOCTL);
    cpu.set_reg(Reg::R0, fd);
    cpu.set_reg(Reg::R1, ashmem_cmd::ASHMEM_GET_SIZE);
    cpu.set_reg(Reg::R2, 0);
    let args = SyscallArgs::from_cpu(&cpu);
    engine.syscall_handler.handle_syscall(args, &mut cpu, &mut engine.mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 8192, "ASHMEM_GET_SIZE must return 8192");

    // 5. Query ashmem initialized state via ioctl(fd, ASHMEM_IS_INITIALIZED, 0)
    cpu.set_reg(Reg::R7, nr::IOCTL);
    cpu.set_reg(Reg::R0, fd);
    cpu.set_reg(Reg::R1, ashmem_cmd::ASHMEM_IS_INITIALIZED);
    cpu.set_reg(Reg::R2, 0);
    let args = SyscallArgs::from_cpu(&cpu);
    engine.syscall_handler.handle_syscall(args, &mut cpu, &mut engine.mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 1, "ASHMEM_IS_INITIALIZED must return 1");

    // 6. Map ashmem region via mmap2(0, 8192, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0)
    cpu.set_reg(Reg::R7, nr::MMAP2);
    cpu.set_reg(Reg::R0, 0); // addr = 0 (dynamic allocation)
    cpu.set_reg(Reg::R1, 8192); // len
    cpu.set_reg(Reg::R2, 3); // PROT_READ | PROT_WRITE
    cpu.set_reg(Reg::R3, 1); // MAP_SHARED
    cpu.set_reg(Reg::R4, fd);
    cpu.set_reg(Reg::R5, 0); // pgoff
    let args = SyscallArgs::from_cpu(&cpu);
    engine.syscall_handler.handle_syscall(args, &mut cpu, &mut engine.mem).unwrap();
    let mapped_addr = cpu.reg(Reg::R0);
    assert_eq!(mapped_addr, 0x7010_0000, "mmap2 must allocate at mmap_current");

    // 7. Write data to mapped guest address
    let test_bytes = b"Hello Android Ashmem Shared Buffer!";
    engine.mem.write_bytes(GuestAddr::new(mapped_addr), test_bytes).unwrap();

    let mut readback = vec![0u8; test_bytes.len()];
    engine.mem.read_bytes(GuestAddr::new(mapped_addr), &mut readback).unwrap();
    assert_eq!(&readback, test_bytes);

    // 8. Test munmap
    cpu.set_reg(Reg::R7, nr::MUNMAP);
    cpu.set_reg(Reg::R0, mapped_addr);
    cpu.set_reg(Reg::R1, 8192);
    let args = SyscallArgs::from_cpu(&cpu);
    engine.syscall_handler.handle_syscall(args, &mut cpu, &mut engine.mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0, "munmap must succeed");

    // 9. Close fd
    cpu.set_reg(Reg::R7, nr::CLOSE);
    cpu.set_reg(Reg::R0, fd);
    let args = SyscallArgs::from_cpu(&cpu);
    engine.syscall_handler.handle_syscall(args, &mut cpu, &mut engine.mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0, "close must succeed");
}

#[test]
fn test_memfd_create_and_mmap() {
    let mem = FlatMemory::new(GuestAddr::new(0x7000_0000), 0x200_000);
    let mut engine = DbtEngine::new(mem);
    engine.set_mmap_base(GuestAddr::new(0x7015_0000));

    let name_addr = GuestAddr::new(0x7000_1000);
    engine.mem.write_bytes(name_addr, b"my_memfd\0").unwrap();

    // 1. memfd_create("my_memfd", 0) -> fd
    let mut cpu = CpuState::default();
    cpu.set_reg(Reg::R7, nr::MEMFD_CREATE);
    cpu.set_reg(Reg::R0, name_addr.as_u32());
    cpu.set_reg(Reg::R1, 0);
    let args = SyscallArgs::from_cpu(&cpu);
    engine.syscall_handler.handle_syscall(args, &mut cpu, &mut engine.mem).unwrap();
    let fd = cpu.reg(Reg::R0);
    assert!(fd >= 3);

    // 2. Set size via ftruncate / ashmem ioctl
    cpu.set_reg(Reg::R7, nr::IOCTL);
    cpu.set_reg(Reg::R0, fd);
    cpu.set_reg(Reg::R1, ashmem_cmd::ASHMEM_SET_SIZE);
    cpu.set_reg(Reg::R2, 4096);
    let args = SyscallArgs::from_cpu(&cpu);
    engine.syscall_handler.handle_syscall(args, &mut cpu, &mut engine.mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);

    // 3. mmap2
    cpu.set_reg(Reg::R7, nr::MMAP2);
    cpu.set_reg(Reg::R0, 0);
    cpu.set_reg(Reg::R1, 4096);
    cpu.set_reg(Reg::R2, 3);
    cpu.set_reg(Reg::R3, 1);
    cpu.set_reg(Reg::R4, fd);
    cpu.set_reg(Reg::R5, 0);
    let args = SyscallArgs::from_cpu(&cpu);
    engine.syscall_handler.handle_syscall(args, &mut cpu, &mut engine.mem).unwrap();
    let map_addr = cpu.reg(Reg::R0);
    assert_eq!(map_addr, 0x7015_0000);
}
