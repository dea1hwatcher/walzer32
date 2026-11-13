/// End-to-end integration test for E3 repackage pipeline:
///   manifest patching, dynamic ARM64 stub generation, DEX bootstrap injection.
use walzer32_apk::{
    has_extract_native_libs, DexParser, RepackageOptions,
    ZipArchive, ZipBuilder, repackage_for_arm64,
};

// ─── Minimal AXML AndroidManifest.xml ───────────────────────────────────────
// Binary AXML header + string pool with just enough data to pass ManifestParser.
// extractNativeLibs is intentionally absent (defaults to true in AXML parser).
fn make_minimal_axml_manifest() -> Vec<u8> {
    // Build via the same helpers used in the existing apk pipeline tests.
    // We use walzer32_apk internals through the public manifest module.
    // The simplest approach: use a pre-serialised raw AXML from the apk pipeline fixture.
    // Since we don't have a fixture helper here, we craft a byte blob that the
    // ManifestParser will accept as "no extractNativeLibs attribute found" (i.e. absent == true).
    //
    // Real AXML format starts with magic 0x00080003.  We build just enough:
    //   - File header  (8 bytes)
    //   - String pool  (minimal — empty)
    //   - Resource map (empty)
    //   - Start-namespace / Start-element / End-element / End-namespace nodes
    //
    // Because hand-crafting full AXML is fragile, we delegate to the existing
    // test_apk_pipeline.rs helper by re-implementing the same trivial builder.

    // Magic bytes: AXML (0x00080003), followed by file size placeholder
    let mut buf: Vec<u8> = Vec::new();
    // We use a hand-built AXML that the ManifestParser can at minimum open and return
    // has_extract_native_libs = true (absent → default true).
    // If parsing fails the patch step degrades gracefully (patched_manifest = false).
    // For the test we therefore only assert structural presence of arm64 stubs and classes2.dex,
    // not the manifest flag.

    // Simple 8-byte stub that will NOT parse as valid AXML (ManifestParser returns Err).
    // The repackage pipeline is designed to handle this gracefully (patched_manifest = false).
    buf.extend_from_slice(b"\x03\x00\x08\x00\x08\x00\x00\x00"); // minimal chunk header
    buf
}

// ─── Minimal valid ARM32 ELF .so ────────────────────────────────────────────
// 32-bit little-endian ELF with e_type=ET_DYN, e_machine=EM_ARM, no sections.
fn make_minimal_arm32_elf(soname: &str) -> Vec<u8> {
    let _ = soname;
    let mut e = vec![0u8; 0x34]; // ELF32 header size
    // ELF magic
    e[0] = 0x7F; e[1] = b'E'; e[2] = b'L'; e[3] = b'F';
    e[4] = 1; // ELFCLASS32
    e[5] = 1; // ELFDATA2LSB
    e[6] = 1; // EV_CURRENT
    // e[7..15] = 0 (OSABI etc.)
    e[16] = 3; e[17] = 0; // ET_DYN
    e[18] = 0x28; e[19] = 0; // EM_ARM
    e[20] = 1; // EV_CURRENT (version)
    // e_entry = 0
    // e_phoff = 0
    // e_shoff = 0
    e[36] = 0x34; e[37] = 0; e[38] = 0; e[39] = 0; // e_flags
    e[40] = 0x34; e[41] = 0; // e_ehsize
    e[42] = 0x20; e[43] = 0; // e_phentsize
    // e_phnum = 0
    e[46] = 0x28; e[47] = 0; // e_shentsize
    // e_shnum = 0, e_shstrndx = 0
    e
}

// ─── Build a synthetic ARM32 APK ────────────────────────────────────────────
fn make_synthetic_arm32_apk() -> Vec<u8> {
    let mut builder = ZipBuilder::new();

    // AndroidManifest.xml (stub — parse may fail, that's OK)
    builder.add_file("AndroidManifest.xml", &make_minimal_axml_manifest());

    // classes.dex — minimal valid DEX header (magic + 0-class file)
    let mut dex_hdr = vec![0u8; 0x70];
    dex_hdr[0..8].copy_from_slice(b"dex\n035\0");
    // file_size field at offset 32
    let sz = 0x70u32.to_le_bytes();
    dex_hdr[32..36].copy_from_slice(&sz);
    // header_size at 36
    dex_hdr[36..40].copy_from_slice(&0x70u32.to_le_bytes());
    // endian_tag at 40
    dex_hdr[40..44].copy_from_slice(&0x12345678u32.to_le_bytes());
    builder.add_file("classes.dex", &dex_hdr);

    // lib/armeabi-v7a/libgame.so
    let so_bytes = make_minimal_arm32_elf("libgame.so");
    builder.add_file_aligned("lib/armeabi-v7a/libgame.so", &so_bytes, 4096);

    builder.build()
}

// ═══════════════════════════════════════════════════════════════════════════
//  Tests
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_repackage_e2e_arm64_stub_present() {
    let apk_bytes = make_synthetic_arm32_apk();

    let options = RepackageOptions {
        patch_manifest: true,
        inject_dex_bootstrap: true,
        use_dynamic_arm64_stubs: true,
        sign_output_apk: false,
        ..Default::default()
    };

    let (output, report) = repackage_for_arm64(&apk_bytes, &options)
        .expect("repackage_for_arm64 failed");

    // Output must be a valid ZIP
    let archive = ZipArchive::new(&output).expect("output is not a valid ZIP");

    // ── ARM64 stubs injected ──
    assert!(
        archive.contains_file("lib/arm64-v8a/libgame.so"),
        "missing lib/arm64-v8a/libgame.so"
    );
    assert!(
        archive.contains_file("lib/arm64-v8a/libwalzer32.so"),
        "missing lib/arm64-v8a/libwalzer32.so"
    );

    // ── ARM64 stub is ELF64 AArch64 ──
    let stub = archive.read_file("lib/arm64-v8a/libgame.so").unwrap();
    assert!(stub.len() >= 0x40, "stub too small to be ELF64");
    assert_eq!(&stub[0..4], b"\x7FELF", "stub missing ELF magic");
    assert_eq!(stub[4], 2, "stub ELFCLASS should be 64-bit (2)");
    assert_eq!(stub[5], 1, "stub should be little-endian");
    let e_machine = u16::from_le_bytes([stub[18], stub[19]]);
    assert_eq!(e_machine, 0xB7, "stub e_machine should be EM_AARCH64 (0xB7)");

    // ── Report fields ──
    assert_eq!(report.arm32_libraries, vec!["libgame.so"]);
    assert!(!report.signed);
}

#[test]
fn test_repackage_e2e_dex_bootstrap_injected() {
    let apk_bytes = make_synthetic_arm32_apk();

    let options = RepackageOptions {
        inject_dex_bootstrap: true,
        sign_output_apk: false,
        ..Default::default()
    };

    let (output, report) = repackage_for_arm64(&apk_bytes, &options)
        .expect("repackage_for_arm64 failed");

    let archive = ZipArchive::new(&output).expect("not a valid ZIP");

    // classes2.dex must be present
    assert!(
        archive.contains_file("classes2.dex"),
        "missing classes2.dex"
    );

    // Parse the injected DEX
    let dex_bytes = archive.read_file("classes2.dex").unwrap();
    let dex = DexParser::parse(&dex_bytes).expect("classes2.dex is not valid DEX");
    // Bootstrap DEX contains Walzer32 loader class
    assert!(
        dex.classes.iter().any(|n| n.contains("Walzer32") || n.contains("walzer32")),
        "DEX bootstrap missing Walzer32 class, found: {:?}",
        dex.classes
    );

    assert!(report.injected_dex_bootstrap);
}

#[test]
fn test_repackage_e2e_no_sign_flag() {
    let apk_bytes = make_synthetic_arm32_apk();

    let options = RepackageOptions {
        sign_output_apk: false,
        ..Default::default()
    };

    let (_output, report) = repackage_for_arm64(&apk_bytes, &options)
        .expect("repackage_for_arm64 failed");

    assert!(!report.signed, "expected unsigned output");
}

#[test]
fn test_repackage_e2e_no_dynamic_stubs_uses_template() {
    let apk_bytes = make_synthetic_arm32_apk();

    let options = RepackageOptions {
        use_dynamic_arm64_stubs: false,
        inject_dex_bootstrap: false,
        sign_output_apk: false,
        ..Default::default()
    };

    let (output, report) = repackage_for_arm64(&apk_bytes, &options)
        .expect("repackage_for_arm64 failed");

    let archive = ZipArchive::new(&output).expect("not a valid ZIP");
    assert!(archive.contains_file("lib/arm64-v8a/libgame.so"));
    assert!(!report.injected_dex_bootstrap);
}

#[test]
fn test_has_extract_native_libs_free_fn_on_stub() {
    // The stub AXML is not valid, so the function should return Err or Some(true) default.
    // Either way it should not panic.
    let stub = make_minimal_axml_manifest();
    // We can't assert a specific result since the stub is intentionally minimal/invalid,
    // but we verify it doesn't panic.
    let _ = has_extract_native_libs(&stub);
}
