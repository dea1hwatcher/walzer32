use byteorder::{ByteOrder, LittleEndian};
use transd_apk::{
    calculate_crc32, generate_synthetic_arm64_libtransd, repackage_for_arm64, ApkPackage,
    RepackageOptions, ZipArchive, ZipBuilder,
};

#[test]
fn test_zip_builder_and_crc32() {
    let mut builder = ZipBuilder::new();
    let data_a = b"Hello, Transd APK Pipeline!";
    let data_b = b"Binary data payload for test \x00\x01\x02\x03\xFF";

    builder.add_file("assets/hello.txt", data_a);
    builder.add_file("res/data.bin", data_b);

    let crc_a = calculate_crc32(data_a);
    let crc_b = calculate_crc32(data_b);
    assert_ne!(crc_a, 0);
    assert_ne!(crc_b, 0);

    let zip_bytes = builder.build();
    let archive = ZipArchive::new(&zip_bytes).expect("Failed to parse built ZIP");

    assert_eq!(archive.file_names(), vec!["assets/hello.txt", "res/data.bin"]);
    assert_eq!(archive.read_file("assets/hello.txt").unwrap(), data_a);
    assert_eq!(archive.read_file("res/data.bin").unwrap(), data_b);

    let entry_a = archive.entries().get("assets/hello.txt").unwrap();
    assert_eq!(entry_a.crc32, crc_a);
    assert_eq!(entry_a.uncompressed_size, data_a.len());
}

#[test]
fn test_zip_builder_alignment() {
    let mut builder = ZipBuilder::new();
    builder.set_default_so_alignment(4096);

    let dummy_so = vec![0x7Fu8, b'E', b'L', b'F', 0xAA, 0xBB, 0xCC, 0xDD];
    builder.add_file("lib/armeabi-v7a/libnative.so", &dummy_so);
    builder.add_file("lib/arm64-v8a/libtransd.so", &dummy_so);

    let zip_bytes = builder.build();
    let archive = ZipArchive::new(&zip_bytes).expect("Failed to parse aligned ZIP");

    for name in ["lib/armeabi-v7a/libnative.so", "lib/arm64-v8a/libtransd.so"] {
        let entry = archive.entries().get(name).unwrap();
        let off = entry.local_header_offset;
        let name_len = LittleEndian::read_u16(&zip_bytes[off + 26..off + 28]) as usize;
        let extra_len = LittleEndian::read_u16(&zip_bytes[off + 28..off + 30]) as usize;
        let data_offset = off + 30 + name_len + extra_len;

        // Verify data offset in the file is aligned to 4096 bytes (4KB page)
        assert_eq!(
            data_offset % 4096,
            0,
            "File payload for {} is not 4KB aligned (offset: {})",
            name,
            data_offset
        );
        assert_eq!(archive.read_file(name).unwrap(), dummy_so);
    }
}

#[test]
fn test_generate_synthetic_arm64_libtransd() {
    let elf = generate_synthetic_arm64_libtransd();
    assert!(elf.len() >= 512);

    // Verify ELF Header
    assert_eq!(&elf[0..4], &[0x7F, b'E', b'L', b'F']);
    assert_eq!(elf[4], 2); // ELFCLASS64
    assert_eq!(elf[5], 1); // ELFDATA2LSB
    assert_eq!(elf[6], 1); // EV_CURRENT
    assert_eq!(LittleEndian::read_u16(&elf[16..18]), 3); // ET_DYN
    assert_eq!(LittleEndian::read_u16(&elf[18..20]), 183); // EM_AARCH64

    // Verify presence of required export symbols in string table
    let elf_str = String::from_utf8_lossy(&elf);
    assert!(elf_str.contains("libtransd.so"));
    assert!(elf_str.contains("JNI_OnLoad"));
    assert!(elf_str.contains("Java_com_transd_loader_TransdEngine_nativeInit"));
}

#[test]
fn test_repackage_apk_for_arm64() {
    // 1. Build an input 32-bit ARM-only APK
    let mut input_builder = ZipBuilder::new();
    input_builder.add_file("AndroidManifest.xml", b"<manifest package=\"com.test.game\"/>");
    input_builder.add_file("classes.dex", b"dex\n035\0dummy_dex");
    input_builder.add_file(
        "lib/armeabi-v7a/libgame.so",
        &[0x7F, b'E', b'L', b'F', 1, 1, 1, 0, 40, 0, 0, 0],
    );
    input_builder.add_file("META-INF/MANIFEST.MF", b"Manifest-Version: 1.0\n");
    input_builder.add_file("META-INF/CERT.SF", b"Signature file data");
    input_builder.add_file("META-INF/CERT.RSA", b"RSA signature block");

    let input_bytes = input_builder.build();

    // Verify original APK is 32-bit only
    let orig_apk = ApkPackage::open(&input_bytes).unwrap();
    assert!(orig_apk.is_arm32_only());
    assert_eq!(orig_apk.available_abis(), vec!["armeabi-v7a"]);
    assert_eq!(orig_apk.arm32_libraries().len(), 1);

    // 2. Repackage for ARM64
    let mut options = RepackageOptions::default();
    options.config_properties.push(("test.custom.key".into(), "true".into()));

    let (repackaged_bytes, report) = repackage_for_arm64(&input_bytes, &options).unwrap();

    // Verify report
    assert_eq!(report.stripped_signature_files, 2); // CERT.SF and CERT.RSA stripped
    assert!(report.preserved_files >= 3); // AndroidManifest, classes.dex, libgame.so, MANIFEST.MF
    assert_eq!(report.primary_lib, "libgame.so");
    assert_eq!(report.arm32_libraries, vec!["libgame.so"]);
    assert_eq!(report.output_size, repackaged_bytes.len());

    // 3. Inspect repackaged APK
    let repackaged_apk = ApkPackage::open(&repackaged_bytes).unwrap();

    // Now contains both armeabi-v7a and arm64-v8a!
    assert!(!repackaged_apk.is_arm32_only());
    assert_eq!(
        repackaged_apk.available_abis(),
        vec!["arm64-v8a", "armeabi-v7a"]
    );
    assert_eq!(repackaged_apk.arm32_libraries().len(), 1);

    // Verify injected libtransd.so
    let bridge_data = repackaged_apk
        .archive()
        .read_file("lib/arm64-v8a/libtransd.so")
        .expect("Injected libtransd.so missing");
    assert_eq!(&bridge_data[0..4], &[0x7F, b'E', b'L', b'F']);
    assert_eq!(bridge_data[4], 2); // 64-bit ELF

    // Verify injected transd_config.prop
    let config_bytes = repackaged_apk
        .archive()
        .read_file("assets/transd_config.prop")
        .expect("Injected transd_config.prop missing");
    let config_str = String::from_utf8_lossy(&config_bytes);
    assert!(config_str.contains("transd.guest.primary_lib=libgame.so"));
    assert!(config_str.contains("transd.guest.abi=armeabi-v7a"));
    assert!(config_str.contains("test.custom.key=true"));

    // Verify signatures were stripped
    assert!(!repackaged_apk.archive().contains_file("META-INF/CERT.SF"));
    assert!(!repackaged_apk.archive().contains_file("META-INF/CERT.RSA"));
    assert!(repackaged_apk.archive().contains_file("META-INF/MANIFEST.MF"));

    // Verify 4KB alignment on both .so libraries
    for name in ["lib/armeabi-v7a/libgame.so", "lib/arm64-v8a/libtransd.so"] {
        let entry = repackaged_apk.archive().entries().get(name).unwrap();
        let off = entry.local_header_offset;
        let name_len = LittleEndian::read_u16(&repackaged_bytes[off + 26..off + 28]) as usize;
        let extra_len = LittleEndian::read_u16(&repackaged_bytes[off + 28..off + 30]) as usize;
        let data_offset = off + 30 + name_len + extra_len;
        assert_eq!(data_offset % 4096, 0);
    }
}
