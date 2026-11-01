use byteorder::{ByteOrder, LittleEndian};
use transd_apk::{ApkPackage, DexParser, ZipArchive, ZipBuilder};

/// Helper to build a minimal DEX file in memory with native methods
fn build_mock_dex() -> Vec<u8> {
    let mut dex = vec![0u8; 512];

    // Magic: dex\n035\0
    dex[0..8].copy_from_slice(b"dex\n035\0");
    LittleEndian::write_u32(&mut dex[32..36], 512); // file_size
    LittleEndian::write_u32(&mut dex[36..40], 0x70); // header_size
    LittleEndian::write_u32(&mut dex[40..44], 0x12345678); // endian_tag

    // Strings table: 3 strings
    // 0: "Lcom/example/game/MainActivity;"
    // 1: "nativeInit"
    // 2: "V"
    let str0 = b"\x1fLcom/example/game/MainActivity;\0";
    let str1 = b"\x0anativeInit\0";
    let str2 = b"\x01V\0";

    let str_ids_off = 0x70;
    let str0_data_off = 0x100;
    let str1_data_off = str0_data_off + str0.len();
    let str2_data_off = str1_data_off + str1.len();

    dex[str0_data_off..str0_data_off + str0.len()].copy_from_slice(str0);
    dex[str1_data_off..str1_data_off + str1.len()].copy_from_slice(str1);
    dex[str2_data_off..str2_data_off + str2.len()].copy_from_slice(str2);

    LittleEndian::write_u32(&mut dex[56..60], 3); // string_ids_size
    LittleEndian::write_u32(&mut dex[60..64], str_ids_off as u32);
    LittleEndian::write_u32(&mut dex[str_ids_off..str_ids_off + 4], str0_data_off as u32);
    LittleEndian::write_u32(&mut dex[str_ids_off + 4..str_ids_off + 8], str1_data_off as u32);
    LittleEndian::write_u32(&mut dex[str_ids_off + 8..str_ids_off + 12], str2_data_off as u32);

    // Types table: 2 types
    let type_ids_off = str_ids_off + 12;
    LittleEndian::write_u32(&mut dex[64..68], 2); // type_ids_size
    LittleEndian::write_u32(&mut dex[68..72], type_ids_off as u32);
    LittleEndian::write_u32(&mut dex[type_ids_off..type_ids_off + 4], 0); // type 0 -> str0
    LittleEndian::write_u32(&mut dex[type_ids_off + 4..type_ids_off + 8], 2); // type 1 -> str2 (V)

    // Method table: 1 method
    let method_ids_off = type_ids_off + 8;
    LittleEndian::write_u32(&mut dex[88..92], 1); // method_ids_size
    LittleEndian::write_u32(&mut dex[92..96], method_ids_off as u32);
    LittleEndian::write_u16(&mut dex[method_ids_off..method_ids_off + 2], 0); // class_idx = 0
    LittleEndian::write_u16(&mut dex[method_ids_off + 2..method_ids_off + 4], 0); // proto_idx = 0
    LittleEndian::write_u32(&mut dex[method_ids_off + 4..method_ids_off + 8], 1); // name_idx = 1 ("nativeInit")

    // Class defs: 1 class
    let class_defs_off = method_ids_off + 8;
    let class_data_off = 0x180;
    LittleEndian::write_u32(&mut dex[96..100], 1); // class_defs_size
    LittleEndian::write_u32(&mut dex[100..104], class_defs_off as u32);
    LittleEndian::write_u32(&mut dex[class_defs_off..class_defs_off + 4], 0); // class_idx = 0
    LittleEndian::write_u32(&mut dex[class_defs_off + 24..class_defs_off + 28], class_data_off as u32);

    // Class data item at 0x180:
    // static_fields = 0, instance_fields = 0, direct_methods = 1, virtual_methods = 0
    dex[class_data_off] = 0; // static_fields_size = 0
    dex[class_data_off + 1] = 0; // instance_fields_size = 0
    dex[class_data_off + 2] = 1; // direct_methods_size = 1
    dex[class_data_off + 3] = 0; // virtual_methods_size = 0

    // encoded_method:
    // method_idx_diff = 0
    // access_flags = ACC_PUBLIC | ACC_STATIC | ACC_NATIVE (0x01 | 0x08 | 0x100 = 0x0109 -> ULEB128: 0x89, 0x02)
    // code_off = 0
    dex[class_data_off + 4] = 0; // method_idx_diff = 0
    dex[class_data_off + 5] = 0x89; // ULEB128 access_flags byte 1
    dex[class_data_off + 6] = 0x02; // ULEB128 access_flags byte 2
    dex[class_data_off + 7] = 0; // code_off = 0

    dex
}

#[test]
fn test_zip_archive_read() {
    let mut builder = ZipBuilder::new();
    builder.add_file("hello.txt", b"Hello Transd DBT!");
    builder.add_file("lib/armeabi-v7a/libtest.so", b"\x7FELF\x01\x01\x01");

    let zip_bytes = builder.build();
    let archive = ZipArchive::new(&zip_bytes).unwrap();

    assert_eq!(archive.entries.len(), 2);
    assert!(archive.entries.contains_key("hello.txt"));
    assert!(archive.entries.contains_key("lib/armeabi-v7a/libtest.so"));

    let file_content = archive.read_file("hello.txt").unwrap();
    assert_eq!(file_content, b"Hello Transd DBT!");
}

#[test]
fn test_dex_native_method_parsing() {
    let dex_bytes = build_mock_dex();
    let dex = DexParser::parse(&dex_bytes).unwrap();

    assert_eq!(dex.classes.len(), 1);
    assert_eq!(dex.classes[0], "com.example.game.MainActivity");

    assert_eq!(dex.native_methods.len(), 1);
    let method = &dex.native_methods[0];
    assert_eq!(method.class_name, "com.example.game.MainActivity");
    assert_eq!(method.method_name, "nativeInit");
    assert!(method.is_static);
    assert_eq!(method.jni_symbol, "Java_com_example_game_MainActivity_nativeInit");
}

#[test]
fn test_apk_package_integration() {
    let mut builder = ZipBuilder::new();
    let dex_bytes = build_mock_dex();
    builder.add_file("classes.dex", &dex_bytes);
    builder.add_file("lib/armeabi-v7a/libgame.so", b"\x7FELF\x01\x01\x01ARM32_SO_BYTES");

    let apk_data = builder.build();
    let apk = ApkPackage::open(&apk_data).unwrap();

    // Verify ABI detection
    assert_eq!(apk.available_abis(), vec!["armeabi-v7a"]);
    assert!(apk.is_arm32_only());

    // Verify native library listing
    let arm32_libs = apk.arm32_libraries();
    assert_eq!(arm32_libs.len(), 1);
    assert_eq!(arm32_libs[0].filename, "libgame.so");

    // Verify library extraction
    let extracted = apk.extract_library("libgame.so").unwrap();
    assert_eq!(extracted, b"\x7FELF\x01\x01\x01ARM32_SO_BYTES");

    // Verify DEX native methods
    assert!(apk.dex.is_some());
    let dex = apk.dex.as_ref().unwrap();
    assert_eq!(dex.native_methods[0].jni_symbol, "Java_com_example_game_MainActivity_nativeInit");
}
