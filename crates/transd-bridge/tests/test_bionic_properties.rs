use transd_core::{FlatMemory, GuestAddr, Memory};
use transd_elf::SymbolResolver;
use transd_rt::DbtEngine;
use transd_bridge::{
    invoke_guest, BionicBridge, JniBridge,
};

#[test]
fn test_bionic_system_property_resolution() {
    let _mem = FlatMemory::new(GuestAddr::new(0x7000_0000), 0x100_000);
    let bionic = BionicBridge::new(GuestAddr::new(0x7000_0000), GuestAddr::new(0x7005_0000), 0x50_000);

    assert!(bionic.resolve("__system_property_get").is_some());
    assert!(bionic.resolve("__system_property_find").is_some());
    assert!(bionic.resolve("__system_property_read").is_some());
}

#[test]
fn test_bionic_system_property_get_invoke() {
    let mut mem = FlatMemory::new(GuestAddr::new(0x7000_0000), 0x200_000);
    let mut bionic = BionicBridge::new(GuestAddr::new(0x7000_0000), GuestAddr::new(0x7010_0000), 0x100_000);
    bionic.install_stubs(&mut mem).unwrap();
    let mut jni = JniBridge::new(GuestAddr::new(0x7005_0000));
    jni.install(&mut mem).unwrap();
    let mut engine = DbtEngine::new(mem);

    let prop_get_addr = bionic.resolve("__system_property_get").unwrap();

    let name_addr = GuestAddr::new(0x7003_0000);
    let val_out_addr = GuestAddr::new(0x7003_0050);

    // Write query string: "ro.build.version.sdk\0"
    engine.mem.write_bytes(name_addr, b"ro.build.version.sdk\0").unwrap();

    // Guest code calling __system_property_get(name, val_out):
    // PUSH {lr}
    // LDR r0, =name_addr
    // LDR r1, =val_out_addr
    // LDR r2, =prop_get_addr
    // BLX r2
    // POP {lr}
    // BX lr
    let code_addr = GuestAddr::new(0x7002_0000);
    let insts = [
        0xE52DE004, // STR lr, [sp, #-4]!
        0xE59F0010, // LDR r0, [pc, #16] -> name_addr (0x04 + 8 + 16 = 0x1C)
        0xE59F1010, // LDR r1, [pc, #16] -> val_out_addr (0x08 + 8 + 16 = 0x24)
        0xE59F2010, // LDR r2, [pc, #16] -> prop_get_addr (0x0C + 8 + 16 = 0x2C)
        0xE12FFF32, // BLX r2
        0xE49DE004, // LDR lr, [sp], #4
        0xE12FFF1E, // BX lr
        // Literal pool:
        name_addr.as_u32(),
        val_out_addr.as_u32(),
        prop_get_addr.as_u32(),
    ];

    for (i, &word) in insts.iter().enumerate() {
        engine.mem.write_u32(code_addr.add((i * 4) as u32), word).unwrap();
    }
    engine.cpu.set_sp(0x701F_F000);

    let len = invoke_guest(&mut engine, &mut bionic, &mut jni, code_addr, &[]).unwrap();
    assert_eq!(len, 2); // "28" length

    let mut buf = [0u8; 3];
    engine.mem.read_bytes(val_out_addr, &mut buf).unwrap();
    assert_eq!(&buf, b"28\0");
}

#[test]
fn test_bionic_system_property_find_and_read_invoke() {
    let mut mem = FlatMemory::new(GuestAddr::new(0x7000_0000), 0x200_000);
    let mut bionic = BionicBridge::new(GuestAddr::new(0x7000_0000), GuestAddr::new(0x7010_0000), 0x100_000);
    bionic.install_stubs(&mut mem).unwrap();
    let mut jni = JniBridge::new(GuestAddr::new(0x7005_0000));
    jni.install(&mut mem).unwrap();
    let mut engine = DbtEngine::new(mem);

    let prop_find_addr = bionic.resolve("__system_property_find").unwrap();
    let prop_read_addr = bionic.resolve("__system_property_read").unwrap();

    let name_addr = GuestAddr::new(0x7003_0000);
    let name_out_addr = GuestAddr::new(0x7003_0040);
    let val_out_addr = GuestAddr::new(0x7003_0080);

    // Query: "ro.product.cpu.abi\0"
    engine.mem.write_bytes(name_addr, b"ro.product.cpu.abi\0").unwrap();

    // Guest code:
    // PUSH {lr}
    // 1. pi = __system_property_find(name)
    // LDR r0, =name_addr
    // LDR r4, =prop_find_addr
    // BLX r4
    // CMP r0, #0
    // BEQ .error
    //
    // 2. __system_property_read(pi, name_out, val_out)
    // MOV r4, r0             ; r4 = pi
    // LDR r1, =name_out_addr
    // LDR r2, =val_out_addr
    // LDR r3, =prop_read_addr
    // MOV r0, r4             ; r0 = pi
    // BLX r3
    // POP {lr}
    // BX lr
    let code_addr = GuestAddr::new(0x7002_0000);
    let insts = [
        0xE52DE004, // STR lr, [sp, #-4]!
        0xE59F0024, // LDR r0, [pc, #36] -> name_addr (0x04 + 8 + 36 = 0x30)
        0xE59F4024, // LDR r4, [pc, #36] -> prop_find_addr (0x08 + 8 + 36 = 0x34)
        0xE12FFF34, // BLX r4
        0xE1A05000, // MOV r5, r0 (save pi)
        0xE59F101C, // LDR r1, [pc, #28] -> name_out_addr (0x14 + 8 + 28 = 0x38)
        0xE59F201C, // LDR r2, [pc, #28] -> val_out_addr (0x18 + 8 + 28 = 0x3C)
        0xE59F401C, // LDR r4, [pc, #28] -> prop_read_addr (0x1C + 8 + 28 = 0x40)
        0xE1A00005, // MOV r0, r5
        0xE12FFF34, // BLX r4
        0xE49DE004, // LDR lr, [sp], #4
        0xE12FFF1E, // BX lr
        // Literal pool:
        name_addr.as_u32(),
        prop_find_addr.as_u32(),
        name_out_addr.as_u32(),
        val_out_addr.as_u32(),
        prop_read_addr.as_u32(),
    ];

    for (i, &word) in insts.iter().enumerate() {
        engine.mem.write_u32(code_addr.add((i * 4) as u32), word).unwrap();
    }
    engine.cpu.set_sp(0x701F_F000);

    let read_len = invoke_guest(&mut engine, &mut bionic, &mut jni, code_addr, &[]).unwrap();
    assert_eq!(read_len, 11); // "armeabi-v7a" length

    let mut name_buf = [0u8; 19];
    engine.mem.read_bytes(name_out_addr, &mut name_buf).unwrap();
    assert_eq!(&name_buf, b"ro.product.cpu.abi\0");

    let mut val_buf = [0u8; 12];
    engine.mem.read_bytes(val_out_addr, &mut val_buf).unwrap();
    assert_eq!(&val_buf, b"armeabi-v7a\0");
}
