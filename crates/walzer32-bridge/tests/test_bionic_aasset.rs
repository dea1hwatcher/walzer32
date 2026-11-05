//! Stage 86 integration tests: Android Asset Manager & Configuration NDK APIs
//! Tests: AAssetManager_fromJava, AAssetManager_open, AAssetManager_openDir,
//!        AAsset_read, AAsset_seek, AAsset_seek64, AAsset_close, AAsset_getLength,
//!        AAsset_getLength64, AAsset_getRemainingLength, AAsset_getRemainingLength64,
//!        AAsset_getBuffer, AAsset_isAllocated, AAssetDir_getNextFileName,
//!        AAssetDir_rewind, AAssetDir_close, AConfiguration_*

use walzer32_bridge::bionic::{BionicBridge, BionicFuncId, BIONIC_SVC_MAGIC};
use walzer32_core::{ArenaMemory, CpuState, GuestAddr, Memory, MemoryError, Reg};
use walzer32_elf::loader::SymbolResolver;

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
fn test_aasset_read_seek_buffer() {
    let (mut bridge, mut mem, mut cpu) = setup();

    // Register a test asset directly in the bridge asset store
    let asset_content = b"Hello Android Asset Manager NDK!";
    bridge.register_asset("textures/font.png", asset_content.to_vec());

    // Also register an asset via VFS
    bridge.vfs.register_file("/assets/data/config.json", b"{\"version\": 1}".to_vec());

    // 1. AAssetManager_fromJava
    cpu.set_reg(Reg::R0, 0x1000); // env
    cpu.set_reg(Reg::R1, 0x2000); // jobject
    call_bionic(&mut bridge, BionicFuncId::AAssetManagerFromJava, &mut cpu, &mut mem).unwrap();
    let mgr = cpu.reg(Reg::R0);
    assert_ne!(mgr, 0, "AAssetManager pointer must be non-null");

    // 2. Open asset "textures/font.png"
    let path_addr = GuestAddr::new(HEAP_START + 0x0100);
    mem.write_bytes(path_addr, b"textures/font.png\0").unwrap();

    cpu.set_reg(Reg::R0, mgr);
    cpu.set_reg(Reg::R1, path_addr.as_u32());
    cpu.set_reg(Reg::R2, 3); // AASSET_MODE_BUFFER
    call_bionic(&mut bridge, BionicFuncId::AAssetManagerOpen, &mut cpu, &mut mem).unwrap();
    let asset = cpu.reg(Reg::R0);
    assert_ne!(asset, 0, "AAsset handle must be non-zero");

    // Check lengths
    cpu.set_reg(Reg::R0, asset);
    call_bionic(&mut bridge, BionicFuncId::AAssetGetLength, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), asset_content.len() as u32);

    cpu.set_reg(Reg::R0, asset);
    call_bionic(&mut bridge, BionicFuncId::AAssetGetLength64, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), asset_content.len() as u32);
    assert_eq!(cpu.reg(Reg::R1), 0);

    cpu.set_reg(Reg::R0, asset);
    call_bionic(&mut bridge, BionicFuncId::AAssetGetRemainingLength, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), asset_content.len() as u32);

    // 3. AAsset_getBuffer & isAllocated
    cpu.set_reg(Reg::R0, asset);
    call_bionic(&mut bridge, BionicFuncId::AAssetGetBuffer, &mut cpu, &mut mem).unwrap();
    let buf_ptr = GuestAddr::new(cpu.reg(Reg::R0));
    assert_ne!(buf_ptr.as_u32(), 0);

    let mut direct_buf = vec![0u8; asset_content.len()];
    mem.read_bytes(buf_ptr, &mut direct_buf).unwrap();
    assert_eq!(direct_buf, asset_content);

    cpu.set_reg(Reg::R0, asset);
    call_bionic(&mut bridge, BionicFuncId::AAssetIsAllocated, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 1);

    // 4. Read first 5 bytes
    let read_buf_addr = GuestAddr::new(HEAP_START + 0x0200);
    cpu.set_reg(Reg::R0, asset);
    cpu.set_reg(Reg::R1, read_buf_addr.as_u32());
    cpu.set_reg(Reg::R2, 5);
    call_bionic(&mut bridge, BionicFuncId::AAssetRead, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 5);

    let mut chunk = [0u8; 5];
    mem.read_bytes(read_buf_addr, &mut chunk).unwrap();
    assert_eq!(&chunk, b"Hello");

    // Remaining length should now be len - 5
    cpu.set_reg(Reg::R0, asset);
    call_bionic(&mut bridge, BionicFuncId::AAssetGetRemainingLength, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), (asset_content.len() - 5) as u32);

    // 5. Seek: SEEK_CUR + 1 (skip space)
    cpu.set_reg(Reg::R0, asset);
    cpu.set_reg(Reg::R1, 1);
    cpu.set_reg(Reg::R2, 1); // SEEK_CUR
    call_bionic(&mut bridge, BionicFuncId::AAssetSeek, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 6);

    // Read next 7 bytes ("Android")
    cpu.set_reg(Reg::R0, asset);
    cpu.set_reg(Reg::R1, read_buf_addr.as_u32());
    cpu.set_reg(Reg::R2, 7);
    call_bionic(&mut bridge, BionicFuncId::AAssetRead, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 7);

    let mut chunk2 = [0u8; 7];
    mem.read_bytes(read_buf_addr, &mut chunk2).unwrap();
    assert_eq!(&chunk2, b"Android");

    // 6. Close asset
    cpu.set_reg(Reg::R0, asset);
    call_bionic(&mut bridge, BionicFuncId::AAssetClose, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);

    // 7. Verify opening VFS asset "data/config.json"
    let vfs_path_addr = GuestAddr::new(HEAP_START + 0x0300);
    mem.write_bytes(vfs_path_addr, b"data/config.json\0").unwrap();

    cpu.set_reg(Reg::R0, mgr);
    cpu.set_reg(Reg::R1, vfs_path_addr.as_u32());
    cpu.set_reg(Reg::R2, 0);
    call_bionic(&mut bridge, BionicFuncId::AAssetManagerOpen, &mut cpu, &mut mem).unwrap();
    let vfs_asset = cpu.reg(Reg::R0);
    assert_ne!(vfs_asset, 0, "VFS asset handle must be non-zero");

    cpu.set_reg(Reg::R0, vfs_asset);
    call_bionic(&mut bridge, BionicFuncId::AAssetGetLength, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 14); // b"{\"version\": 1}".len()
}

#[test]
fn test_aassetdir_iteration() {
    let (mut bridge, mut mem, mut cpu) = setup();

    bridge.register_asset("levels/level1.dat", vec![1, 2, 3]);
    bridge.register_asset("levels/level2.dat", vec![4, 5, 6]);
    bridge.register_asset("levels/level3.dat", vec![7, 8, 9]);

    let dir_name_addr = GuestAddr::new(HEAP_START + 0x0400);
    mem.write_bytes(dir_name_addr, b"levels\0").unwrap();

    // Open dir
    cpu.set_reg(Reg::R0, 0xA55E_7000);
    cpu.set_reg(Reg::R1, dir_name_addr.as_u32());
    call_bionic(&mut bridge, BionicFuncId::AAssetManagerOpenDir, &mut cpu, &mut mem).unwrap();
    let dir = cpu.reg(Reg::R0);
    assert_ne!(dir, 0);

    // Iterate filenames
    let mut names = Vec::new();
    loop {
        cpu.set_reg(Reg::R0, dir);
        call_bionic(&mut bridge, BionicFuncId::AAssetDirGetNextFileName, &mut cpu, &mut mem).unwrap();
        let name_ptr = cpu.reg(Reg::R0);
        if name_ptr == 0 {
            break;
        }
        let mut cur = GuestAddr::new(name_ptr);
        let mut bytes = Vec::new();
        loop {
            let b = mem.read_u8(cur).unwrap();
            if b == 0 {
                break;
            }
            bytes.push(b);
            cur = cur.add(1);
        }
        names.push(String::from_utf8(bytes).unwrap());
    }

    assert_eq!(names, vec!["level1.dat", "level2.dat", "level3.dat"]);

    // Rewind and re-read first
    cpu.set_reg(Reg::R0, dir);
    call_bionic(&mut bridge, BionicFuncId::AAssetDirRewind, &mut cpu, &mut mem).unwrap();

    cpu.set_reg(Reg::R0, dir);
    call_bionic(&mut bridge, BionicFuncId::AAssetDirGetNextFileName, &mut cpu, &mut mem).unwrap();
    assert_ne!(cpu.reg(Reg::R0), 0);

    // Close dir
    cpu.set_reg(Reg::R0, dir);
    call_bionic(&mut bridge, BionicFuncId::AAssetDirClose, &mut cpu, &mut mem).unwrap();
}

#[test]
fn test_aconfiguration_lifecycle_and_properties() {
    let (mut bridge, mut mem, mut cpu) = setup();

    // 1. AConfiguration_new
    call_bionic(&mut bridge, BionicFuncId::AConfigurationNew, &mut cpu, &mut mem).unwrap();
    let cfg = cpu.reg(Reg::R0);
    assert_ne!(cfg, 0);

    // Verify defaults
    cpu.set_reg(Reg::R0, cfg);
    call_bionic(&mut bridge, BionicFuncId::AConfigurationGetOrientation, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 1); // PORTRAIT

    cpu.set_reg(Reg::R0, cfg);
    call_bionic(&mut bridge, BionicFuncId::AConfigurationGetDensity, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 320); // XHDPI

    cpu.set_reg(Reg::R0, cfg);
    call_bionic(&mut bridge, BionicFuncId::AConfigurationGetSdkVersion, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 28);

    // 2. Setters
    cpu.set_reg(Reg::R0, cfg);
    cpu.set_reg(Reg::R1, 2); // LANDSCAPE
    call_bionic(&mut bridge, BionicFuncId::AConfigurationSetOrientation, &mut cpu, &mut mem).unwrap();

    cpu.set_reg(Reg::R0, cfg);
    cpu.set_reg(Reg::R1, 480); // XXHDPI
    call_bionic(&mut bridge, BionicFuncId::AConfigurationSetDensity, &mut cpu, &mut mem).unwrap();

    cpu.set_reg(Reg::R0, cfg);
    cpu.set_reg(Reg::R1, 33); // Android 13
    call_bionic(&mut bridge, BionicFuncId::AConfigurationSetSdkVersion, &mut cpu, &mut mem).unwrap();

    // Verify updated values
    cpu.set_reg(Reg::R0, cfg);
    call_bionic(&mut bridge, BionicFuncId::AConfigurationGetOrientation, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 2);

    cpu.set_reg(Reg::R0, cfg);
    call_bionic(&mut bridge, BionicFuncId::AConfigurationGetDensity, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 480);

    cpu.set_reg(Reg::R0, cfg);
    call_bionic(&mut bridge, BionicFuncId::AConfigurationGetSdkVersion, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 33);

    // 3. Language & Country
    let lang_buf = GuestAddr::new(HEAP_START + 0x0500);
    mem.write_bytes(lang_buf, b"fr\0").unwrap();
    cpu.set_reg(Reg::R0, cfg);
    cpu.set_reg(Reg::R1, lang_buf.as_u32());
    call_bionic(&mut bridge, BionicFuncId::AConfigurationSetLanguage, &mut cpu, &mut mem).unwrap();

    let country_buf = GuestAddr::new(HEAP_START + 0x0510);
    mem.write_bytes(country_buf, b"CA\0").unwrap();
    cpu.set_reg(Reg::R0, cfg);
    cpu.set_reg(Reg::R1, country_buf.as_u32());
    call_bionic(&mut bridge, BionicFuncId::AConfigurationSetCountry, &mut cpu, &mut mem).unwrap();

    let out_lang = GuestAddr::new(HEAP_START + 0x0520);
    cpu.set_reg(Reg::R0, cfg);
    cpu.set_reg(Reg::R1, out_lang.as_u32());
    call_bionic(&mut bridge, BionicFuncId::AConfigurationGetLanguage, &mut cpu, &mut mem).unwrap();
    let mut read_lang = [0u8; 2];
    mem.read_bytes(out_lang, &mut read_lang).unwrap();
    assert_eq!(&read_lang, b"fr");

    let out_country = GuestAddr::new(HEAP_START + 0x0530);
    cpu.set_reg(Reg::R0, cfg);
    cpu.set_reg(Reg::R1, out_country.as_u32());
    call_bionic(&mut bridge, BionicFuncId::AConfigurationGetCountry, &mut cpu, &mut mem).unwrap();
    let mut read_country = [0u8; 2];
    mem.read_bytes(out_country, &mut read_country).unwrap();
    assert_eq!(&read_country, b"CA");

    // 4. AConfiguration_copy & AConfiguration_delete
    call_bionic(&mut bridge, BionicFuncId::AConfigurationNew, &mut cpu, &mut mem).unwrap();
    let cfg2 = cpu.reg(Reg::R0);

    cpu.set_reg(Reg::R0, cfg2);
    cpu.set_reg(Reg::R1, cfg);
    call_bionic(&mut bridge, BionicFuncId::AConfigurationCopy, &mut cpu, &mut mem).unwrap();

    // Verify cfg2 has cloned properties
    cpu.set_reg(Reg::R0, cfg2);
    call_bionic(&mut bridge, BionicFuncId::AConfigurationGetDensity, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 480);

    cpu.set_reg(Reg::R0, cfg);
    call_bionic(&mut bridge, BionicFuncId::AConfigurationDelete, &mut cpu, &mut mem).unwrap();
    cpu.set_reg(Reg::R0, cfg2);
    call_bionic(&mut bridge, BionicFuncId::AConfigurationDelete, &mut cpu, &mut mem).unwrap();
}

#[test]
fn test_symbol_resolution() {
    let (bridge, _mem, _cpu) = setup();

    let symbols = [
        "AAssetManager_fromJava",
        "AAssetManager_open",
        "AAssetManager_openDir",
        "AAsset_read",
        "AAsset_seek",
        "AAsset_seek64",
        "AAsset_close",
        "AAsset_getLength",
        "AAsset_getLength64",
        "AAsset_getRemainingLength",
        "AAsset_getRemainingLength64",
        "AAsset_getBuffer",
        "AAsset_isAllocated",
        "AAssetDir_getNextFileName",
        "AAssetDir_rewind",
        "AAssetDir_close",
        "AConfiguration_new",
        "AConfiguration_delete",
        "AConfiguration_fromAssetManager",
        "AConfiguration_copy",
        "AConfiguration_getOrientation",
        "AConfiguration_setOrientation",
        "AConfiguration_getDensity",
        "AConfiguration_setDensity",
        "AConfiguration_getSdkVersion",
        "AConfiguration_setSdkVersion",
        "AConfiguration_getScreenSize",
        "AConfiguration_setScreenSize",
        "AConfiguration_getScreenLong",
        "AConfiguration_setScreenLong",
        "AConfiguration_getUiModeType",
        "AConfiguration_setUiModeType",
        "AConfiguration_getLanguage",
        "AConfiguration_getCountry",
        "AConfiguration_setLanguage",
        "AConfiguration_setCountry",
    ];

    for sym in symbols {
        let addr = bridge.resolve(sym);
        assert!(addr.is_some(), "Symbol {} must be resolved", sym);
        assert_ne!(addr.unwrap().as_u32(), 0);
    }
}
