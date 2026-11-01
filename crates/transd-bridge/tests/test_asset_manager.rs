use transd_core::{FlatMemory, GuestAddr, Memory};
use transd_elf::SymbolResolver;
use transd_rt::DbtEngine;
use transd_bridge::{
    invoke_guest_extended, AssetBridge, AssetFuncId, BionicBridge, JniBridge,
};

#[test]
fn test_asset_symbols_resolution() {
    let bridge = AssetBridge::with_stub_base(GuestAddr::new(0x7000_0000));

    let symbols = [
        "AAssetManager_fromJava",
        "AAssetManager_open",
        "AAssetManager_openDir",
        "AAsset_read",
        "AAsset_seek",
        "AAsset_seek64",
        "AAsset_getLength",
        "AAsset_getLength64",
        "AAsset_getRemainingLength",
        "AAsset_getRemainingLength64",
        "AAsset_getBuffer",
        "AAsset_close",
        "AAssetDir_getNextFileName",
        "AAssetDir_rewind",
        "AAssetDir_close",
    ];

    for sym in symbols {
        let addr = bridge.resolve(sym);
        assert!(addr.is_some(), "Symbol {sym} must be resolvable");
        assert!(addr.unwrap().as_u32() >= 0x7000_0000);
    }
}

#[test]
fn test_asset_open_read_seek_getbuffer() {
    let mut mem = FlatMemory::new(GuestAddr::new(0x7000_0000), 0x300_000);

    let mut bionic = BionicBridge::new(
        GuestAddr::new(0x7000_0000),
        GuestAddr::new(0x7002_0000),
        0x20_000,
    );
    bionic.install_stubs(&mut mem).unwrap();

    let mut jni = JniBridge::new(GuestAddr::new(0x7005_0000));
    jni.install(&mut mem).unwrap();

    let mut asset = AssetBridge::new(
        GuestAddr::new(0x7008_0000),
        GuestAddr::new(0x7009_0000),
        0x50_000,
    );
    asset.install_stubs(&mut mem).unwrap();

    let sample_payload = b"Transd NDK Asset Streaming 2026 Engine Payload Content";
    asset.register_asset("config/payload.txt", sample_payload.to_vec());

    // Write filename string "config/payload.txt\0" at 0x7006_0000
    let filename_addr = GuestAddr::new(0x7006_0000);
    mem.write_bytes(filename_addr, b"config/payload.txt\0").unwrap();

    // Destination read buffer at 0x7006_1000
    let read_buf_addr = GuestAddr::new(0x7006_1000);

    let mut engine = DbtEngine::new(mem);

    // Call AAssetManager_open(mgr=0, "config/payload.txt", mode=0)
    let open_addr = asset.stub_base.add((AssetFuncId::AAssetManagerOpen as u32) * 8);
    let get_len_addr = asset.stub_base.add((AssetFuncId::AAssetGetLength as u32) * 8);
    let read_addr = asset.stub_base.add((AssetFuncId::AAssetRead as u32) * 8);
    let rem_len_addr = asset.stub_base.add((AssetFuncId::AAssetGetRemainingLength as u32) * 8);
    let seek_addr = asset.stub_base.add((AssetFuncId::AAssetSeek as u32) * 8);
    let get_buf_addr = asset.stub_base.add((AssetFuncId::AAssetGetBuffer as u32) * 8);
    let close_addr = asset.stub_base.add((AssetFuncId::AAssetClose as u32) * 8);

    // Write ARM32 test program at 0x7007_0000:
    // PUSH {r4, r5, lr}
    // LDR r0, =0          (mgr)
    // LDR r1, =filename_addr
    // LDR r2, =0          (mode)
    // LDR r3, =open_addr
    // BLX r3
    // MOVS r4, r0         (asset handle -> r4)
    // BEQ .fail
    //
    // LDR r0, r4
    // LDR r3, =get_len_addr
    // BLX r3
    // MOV r5, r0          (total len -> r5)
    //
    // LDR r0, r4
    // LDR r1, =read_buf_addr
    // MOV r2, #10         (read 10 bytes)
    // LDR r3, =read_addr
    // BLX r3
    //
    // LDR r0, r4
    // LDR r3, =rem_len_addr
    // BLX r3              (r0 = remaining len)
    //
    // LDR r0, r4
    // MOV r1, #0          (offset 0)
    // MOV r2, #0          (SEEK_SET)
    // LDR r3, =seek_addr
    // BLX r3
    //
    // LDR r0, r4
    // LDR r3, =get_buf_addr
    // BLX r3              (r0 = direct buffer ptr)
    //
    // MOV r5, r0          (save buffer ptr)
    // LDR r0, r4
    // LDR r3, =close_addr
    // BLX r3
    //
    // MOV r0, r5          (return direct buffer ptr)
    // POP {r4, r5, lr}
    // BX lr
    let code_addr = GuestAddr::new(0x7007_0000);

    let insts = [
        0xE92D4030, // 0: PUSH {r4, r5, lr}
        0xE3A00000, // 1: MOV r0, #0
        0xE59F107C, // 2: LDR r1, [pc, #124] -> filename_addr (idx 35)
        0xE3A02000, // 3: MOV r2, #0
        0xE59F3078, // 4: LDR r3, [pc, #120] -> open_addr (idx 36)
        0xE12FFF33, // 5: BLX r3
        0xE1B04000, // 6: MOVS r4, r0
        0x0A000018, // 7: BEQ +24 -> index 33 (exit)
        // get length
        0xE1A00004, // 8: MOV r0, r4
        0xE59F3068, // 9: LDR r3, [pc, #104] -> get_len_addr (idx 37)
        0xE12FFF33, // 10: BLX r3
        0xE1A05000, // 11: MOV r5, r0
        // read 10 bytes
        0xE1A00004, // 12: MOV r0, r4
        0xE59F105C, // 13: LDR r1, [pc, #92] -> read_buf_addr (idx 38)
        0xE3A0200A, // 14: MOV r2, #10
        0xE59F3058, // 15: LDR r3, [pc, #88] -> read_addr (idx 39)
        0xE12FFF33, // 16: BLX r3
        // get remaining length
        0xE1A00004, // 17: MOV r0, r4
        0xE59F3050, // 18: LDR r3, [pc, #80] -> rem_len_addr (idx 40)
        0xE12FFF33, // 19: BLX r3
        // seek back to 0
        0xE1A00004, // 20: MOV r0, r4
        0xE3A01000, // 21: MOV r1, #0
        0xE3A02000, // 22: MOV r2, #0
        0xE59F3040, // 23: LDR r3, [pc, #64] -> seek_addr (idx 41)
        0xE12FFF33, // 24: BLX r3
        // getBuffer
        0xE1A00004, // 25: MOV r0, r4
        0xE59F3038, // 26: LDR r3, [pc, #56] -> get_buf_addr (idx 42)
        0xE12FFF33, // 27: BLX r3
        0xE1A05000, // 28: MOV r5, r0
        // close
        0xE1A00004, // 29: MOV r0, r4
        0xE59F302C, // 30: LDR r3, [pc, #44] -> close_addr (idx 43)
        0xE12FFF33, // 31: BLX r3
        // return r5
        0xE1A00005, // 32: MOV r0, r5
        0xE8BD4030, // 33: POP {r4, r5, lr}
        0xE12FFF1E, // 34: BX lr
        // Literals:
        filename_addr.as_u32(),
        open_addr.as_u32(),
        get_len_addr.as_u32(),
        read_buf_addr.as_u32(),
        read_addr.as_u32(),
        rem_len_addr.as_u32(),
        seek_addr.as_u32(),
        get_buf_addr.as_u32(),
        close_addr.as_u32(),
    ];

    for (i, &word) in insts.iter().enumerate() {
        engine.mem.write_u32(code_addr.add((i * 4) as u32), word).unwrap();
    }

    engine.cpu.set_sp(0x702F_0000);

    let buf_ptr = invoke_guest_extended(
        &mut engine,
        &mut bionic,
        &mut jni,
        None,
        None,
        Some(&mut asset),
        code_addr,
        &[],
    ).unwrap();

    assert_ne!(buf_ptr, 0, "Direct buffer pointer must not be NULL");

    // Verify 10 bytes read into read_buf_addr
    let mut read_bytes = vec![0u8; 10];
    engine.mem.read_bytes(read_buf_addr, &mut read_bytes).unwrap();
    assert_eq!(&read_bytes, b"Transd NDK");

    // Verify full data buffer returned by AAsset_getBuffer
    let mut direct_bytes = vec![0u8; sample_payload.len()];
    engine.mem.read_bytes(GuestAddr::new(buf_ptr), &mut direct_bytes).unwrap();
    assert_eq!(&direct_bytes, sample_payload);

    assert_eq!(asset.stats_assets_opened, 1);
    assert_eq!(asset.stats_bytes_read, 10);
    assert!(asset.open_assets.is_empty(), "Asset should have been closed");
}

#[test]
fn test_asset_dir_traversal() {
    let mut mem = FlatMemory::new(GuestAddr::new(0x7000_0000), 0x200_000);

    let bionic = BionicBridge::new(
        GuestAddr::new(0x7000_0000),
        GuestAddr::new(0x7002_0000),
        0x20_000,
    );
    bionic.install_stubs(&mut mem).unwrap();

    let jni = JniBridge::new(GuestAddr::new(0x7005_0000));
    jni.install(&mut mem).unwrap();

    let mut asset = AssetBridge::new(
        GuestAddr::new(0x7008_0000),
        GuestAddr::new(0x7009_0000),
        0x50_000,
    );
    asset.install_stubs(&mut mem).unwrap();

    asset.register_asset("models/tree.obj", b"v 1 2 3".to_vec());
    asset.register_asset("models/rock.obj", b"v 4 5 6".to_vec());
    asset.register_asset("models/bush.obj", b"v 7 8 9".to_vec());

    let dir_name_addr = GuestAddr::new(0x7006_0000);
    mem.write_bytes(dir_name_addr, b"models\0").unwrap();

    let mut engine = DbtEngine::new(mem);

    // Call AAssetManager_openDir(mgr=0, "models")
    let mut cpu = transd_core::CpuState::default();
    cpu.set_reg(transd_core::Reg::R0, 0);
    cpu.set_reg(transd_core::Reg::R1, dir_name_addr.as_u32());
    let handled = asset.handle_svc(
        transd_bridge::ASSET_SVC_MAGIC | (AssetFuncId::AAssetManagerOpenDir as u32),
        &mut cpu,
        &mut engine.mem,
    ).unwrap();
    assert!(handled);
    let dir_handle = cpu.reg(transd_core::Reg::R0);
    assert_ne!(dir_handle, 0);

    // Read 3 file names in alphabetical order: bush.obj, rock.obj, tree.obj
    let mut names = Vec::new();
    loop {
        cpu.set_reg(transd_core::Reg::R0, dir_handle);
        asset.handle_svc(
            transd_bridge::ASSET_SVC_MAGIC | (AssetFuncId::AAssetDirGetNextFileName as u32),
            &mut cpu,
            &mut engine.mem,
        ).unwrap();
        let name_ptr = cpu.reg(transd_core::Reg::R0);
        if name_ptr == 0 {
            break;
        }
        let mut name_bytes = Vec::new();
        let mut ptr = GuestAddr::new(name_ptr);
        loop {
            let b = engine.mem.read_u8(ptr).unwrap();
            if b == 0 {
                break;
            }
            name_bytes.push(b);
            ptr = ptr.add(1);
        }
        names.push(String::from_utf8(name_bytes).unwrap());
    }

    assert_eq!(names, vec!["bush.obj", "rock.obj", "tree.obj"]);

    // Test rewind
    cpu.set_reg(transd_core::Reg::R0, dir_handle);
    asset.handle_svc(
        transd_bridge::ASSET_SVC_MAGIC | (AssetFuncId::AAssetDirRewind as u32),
        &mut cpu,
        &mut engine.mem,
    ).unwrap();

    // After rewind, next file is bush.obj again
    cpu.set_reg(transd_core::Reg::R0, dir_handle);
    asset.handle_svc(
        transd_bridge::ASSET_SVC_MAGIC | (AssetFuncId::AAssetDirGetNextFileName as u32),
        &mut cpu,
        &mut engine.mem,
    ).unwrap();
    let name_ptr = cpu.reg(transd_core::Reg::R0);
    assert_ne!(name_ptr, 0);

    // Close dir
    cpu.set_reg(transd_core::Reg::R0, dir_handle);
    asset.handle_svc(
        transd_bridge::ASSET_SVC_MAGIC | (AssetFuncId::AAssetDirClose as u32),
        &mut cpu,
        &mut engine.mem,
    ).unwrap();
    assert!(asset.open_dirs.is_empty());
}

#[test]
fn test_asset_load_from_apk() {
    let mut builder = transd_apk::ZipBuilder::new();
    builder.add_file("assets/game/config.lua", b"-- Lua Game Config\nreturn { volume = 1.0 }");
    builder.add_file("assets/game/sprites.png", &[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A]);
    builder.add_file("res/layout/main.xml", b"<xml>ignored</xml>");
    let zip_bytes = builder.build();

    let mut bridge = AssetBridge::with_stub_base(GuestAddr::new(0x7000_0000));
    let count = bridge.load_apk(&zip_bytes).unwrap();
    assert_eq!(count, 2);

    assert!(bridge.assets_map.contains_key("game/config.lua"));
    assert!(bridge.assets_map.contains_key("game/sprites.png"));
    assert!(!bridge.assets_map.contains_key("res/layout/main.xml"));
}
