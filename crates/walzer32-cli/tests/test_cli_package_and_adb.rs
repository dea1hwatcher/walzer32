use std::fs;
use std::process::Command;
use byteorder::{ByteOrder, LittleEndian};
use walzer32_apk::{ApkPackage, ZipBuilder};
use walzer32_cli::adb::{
    evaluate_compatibility, parse_adb_devices_output, parse_device_info,
};

#[test]
fn test_adb_devices_parsing() {
    let sample_adb_output = r#"List of devices attached
emulator-5554	device
RFCX3000XYZ	device
192.168.1.50:5555	unauthorized
deadbeef	offline

"#;

    let devices = parse_adb_devices_output(sample_adb_output);
    assert_eq!(devices, vec!["emulator-5554", "RFCX3000XYZ"]);

    let empty_output = "List of devices attached\n\n";
    assert!(parse_adb_devices_output(empty_output).is_empty());
}

#[test]
fn test_device_architecture_assessment() {
    // 1. ARM64-only target device (e.g. Pixel 7 / Pixel 8 / Snapdragon 8 Gen 3)
    let arm64_only_dev = parse_device_info(
        "pixel8-001",
        "Pixel 8",
        "arm64-v8a",
        Some(34),
        Some("14"),
    );
    assert!(arm64_only_dev.is_arm64_only);
    assert!(arm64_only_dev.requires_walzer32);
    assert_eq!(arm64_only_dev.sdk_version, Some(34));

    // 2. Hybrid 32/64-bit target device (e.g. Galaxy S20 / Snapdragon 865)
    let hybrid_dev = parse_device_info(
        "s20-002",
        "Galaxy S20",
        "arm64-v8a,armeabi-v7a,armeabi",
        Some(30),
        Some("11"),
    );
    assert!(!hybrid_dev.is_arm64_only);
    assert!(!hybrid_dev.requires_walzer32);

    // 3. Legacy 32-bit only target device
    let arm32_dev = parse_device_info(
        "nexus4-003",
        "Nexus 4",
        "armeabi-v7a,armeabi",
        Some(22),
        Some("5.1"),
    );
    assert!(!arm32_dev.is_arm64_only);
    assert!(!arm32_dev.requires_walzer32);
}

#[test]
fn test_apk_compatibility_evaluation() {
    let arm64_only_dev = parse_device_info("arm64-dev", "Pixel 8", "arm64-v8a", Some(34), Some("14"));
    let hybrid_dev = parse_device_info("hybrid-dev", "Galaxy S10", "arm64-v8a,armeabi-v7a", Some(29), Some("10"));

    // Case 1: 32-bit only APK
    let mut b1 = ZipBuilder::new();
    b1.add_file("lib/armeabi-v7a/libretro.so", b"\x7fELFdummy32bit");
    let apk_bytes1 = b1.build();
    let apk1 = ApkPackage::open(&apk_bytes1).unwrap();

    let eval_arm64 = evaluate_compatibility(&arm64_only_dev, &apk1);
    assert!(!eval_arm64.compatible);
    assert!(eval_arm64.requires_walzer32_repackage);
    assert!(eval_arm64.reason.contains("ARM64-ONLY"));

    let eval_hybrid = evaluate_compatibility(&hybrid_dev, &apk1);
    assert!(eval_hybrid.compatible);
    assert!(!eval_hybrid.requires_walzer32_repackage);

    // Case 2: Repackaged APK with Walzer32 host bridge
    let mut b2 = ZipBuilder::new();
    b2.add_file("lib/armeabi-v7a/libretro.so", b"\x7fELFdummy32bit");
    b2.add_file("lib/arm64-v8a/libwalzer32.so", b"\x7fELFdummy64bit");
    let apk_bytes2 = b2.build();
    let apk2 = ApkPackage::open(&apk_bytes2).unwrap();

    let eval_repackaged = evaluate_compatibility(&arm64_only_dev, &apk2);
    assert!(eval_repackaged.compatible);
    assert!(!eval_repackaged.requires_walzer32_repackage);
    assert!(eval_repackaged.reason.contains("Walzer32 DBT host bridge"));
}

#[test]
fn test_cli_package_and_inspect_e2e() {
    let cli_exe = env!("CARGO_BIN_EXE_walzer32-cli");
    let temp_dir = std::env::temp_dir();
    let input_apk_path = temp_dir.join("test_input_game.apk");
    let output_apk_path = temp_dir.join("test_output_game_arm64.apk");

    // Clean up any stale test files
    let _ = fs::remove_file(&input_apk_path);
    let _ = fs::remove_file(&output_apk_path);

    // 1. Build sample 32-bit APK
    let mut builder = ZipBuilder::new();
    builder.add_file(
        "AndroidManifest.xml",
        b"<manifest package=\"com.walzer32.testgame\"/>",
    );
    builder.add_file("classes.dex", b"dex\n035\0testdex");
    builder.add_file("lib/armeabi-v7a/libgamecore.so", b"\x7fELF\x01\x01\x01\x00arm32test");
    builder.add_file("META-INF/MANIFEST.MF", b"Manifest-Version: 1.0\n");
    builder.add_file("META-INF/SIGNATURE.SF", b"SHA-256 Digest...\n");

    let input_bytes = builder.build();
    fs::write(&input_apk_path, input_bytes).expect("Failed to write test input APK");

    // 2. Execute `walzer32-cli package <input> -o <output> --align 4096 --config walzer32.custom_opt=enabled`
    let package_output = Command::new(cli_exe)
        .arg("package")
        .arg(&input_apk_path)
        .arg("-o")
        .arg(&output_apk_path)
        .arg("--align")
        .arg("4096")
        .arg("--config")
        .arg("walzer32.custom_opt=enabled")
        .output()
        .expect("Failed to execute walzer32-cli package");

    assert!(
        package_output.status.success(),
        "Package command failed: {}",
        String::from_utf8_lossy(&package_output.stderr)
    );

    let pkg_stdout = String::from_utf8_lossy(&package_output.stdout);
    assert!(pkg_stdout.contains("=== Walzer32 APK Repackaging Pipeline ==="));
    assert!(pkg_stdout.contains("Repackaging Successful!"));
    assert!(pkg_stdout.contains("lib/arm64-v8a/libwalzer32.so"));
    assert!(pkg_stdout.contains("assets/walzer32_config.prop"));

    assert!(output_apk_path.exists(), "Output APK file was not created");

    // 3. Execute `walzer32-cli apk <output_apk_path>` to inspect repackaged package
    let apk_inspect_output = Command::new(cli_exe)
        .arg("apk")
        .arg(&output_apk_path)
        .output()
        .expect("Failed to execute walzer32-cli apk");

    assert!(apk_inspect_output.status.success());
    let inspect_stdout = String::from_utf8_lossy(&apk_inspect_output.stdout);
    assert!(inspect_stdout.contains("Available ABIs: [\"arm64-v8a\", \"armeabi-v7a\"]"));
    assert!(inspect_stdout.contains("32-bit ARM Only: NO"));

    // 4. Verify internal structure and alignment of the output APK
    let repackaged_bytes = fs::read(&output_apk_path).expect("Failed to read output APK");
    let repackaged_apk = ApkPackage::open(&repackaged_bytes).expect("Failed to parse repackaged APK");

    assert!(!repackaged_apk.archive().contains_file("META-INF/SIGNATURE.SF"));
    assert!(repackaged_apk.archive().contains_file("META-INF/MANIFEST.MF"));

    let config_bytes = repackaged_apk
        .archive()
        .read_file("assets/walzer32_config.prop")
        .expect("Missing assets/walzer32_config.prop");
    let config_str = String::from_utf8_lossy(&config_bytes);
    assert!(config_str.contains("walzer32.custom_opt=enabled"));
    assert!(config_str.contains("walzer32.guest.primary_lib=libgamecore.so"));

    let bridge_bytes = repackaged_apk
        .archive()
        .read_file("lib/arm64-v8a/libwalzer32.so")
        .expect("Missing lib/arm64-v8a/libwalzer32.so");
    assert_eq!(&bridge_bytes[0..4], &[0x7F, b'E', b'L', b'F']);
    assert_eq!(bridge_bytes[4], 2); // 64-bit ELF

    // Verify 4KB alignment on uncompressed native libraries
    for name in ["lib/armeabi-v7a/libgamecore.so", "lib/arm64-v8a/libwalzer32.so"] {
        let entry = repackaged_apk.archive().entries().get(name).unwrap();
        let off = entry.local_header_offset;
        let name_len = LittleEndian::read_u16(&repackaged_bytes[off + 26..off + 28]) as usize;
        let extra_len = LittleEndian::read_u16(&repackaged_bytes[off + 28..off + 30]) as usize;
        let data_offset = off + 30 + name_len + extra_len;
        assert_eq!(
            data_offset % 4096,
            0,
            "{} is not 4KB aligned in output APK",
            name
        );
    }

    // Clean up
    let _ = fs::remove_file(&input_apk_path);
    let _ = fs::remove_file(&output_apk_path);
}

#[test]
fn test_cli_help_and_unknown_commands() {
    let cli_exe = env!("CARGO_BIN_EXE_walzer32-cli");

    let help_output = Command::new(cli_exe)
        .arg("help")
        .output()
        .expect("Failed to execute help");
    assert!(help_output.status.success());
    let help_str = String::from_utf8_lossy(&help_output.stdout);
    assert!(help_str.contains("package <file.apk>"));
    assert!(help_str.contains("test-device [OPTIONS]"));
    assert!(help_str.contains("install <file.apk>"));
    assert!(help_str.contains("launch <pkg_or_apk>"));

    // Missing required argument for package
    let bad_pkg = Command::new(cli_exe)
        .arg("package")
        .output()
        .expect("Failed to execute package");
    assert_eq!(bad_pkg.status.code(), Some(1));
}
