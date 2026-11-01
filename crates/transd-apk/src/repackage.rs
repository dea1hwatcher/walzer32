use byteorder::{ByteOrder, LittleEndian};
use crate::apk::{ApkError, ApkPackage};
use crate::zip::ZipBuilder;

/// Configuration options for APK repackaging
#[derive(Debug, Clone)]
pub struct RepackageOptions {
    /// Custom bytes for host arm64-v8a libtransd.so (if None, synthetic ARM64 ELF is generated)
    pub custom_libtransd: Option<Vec<u8>>,
    /// Additional key-value properties to inject into assets/transd_config.prop
    pub config_properties: Vec<(String, String)>,
    /// Primary 32-bit library filename to execute (auto-detected if None)
    pub primary_lib: Option<String>,
    /// Alignment for .so libraries (default: 4096 bytes for page-mmap)
    pub so_alignment: usize,
    /// Keep legacy signatures in META-INF (default: false, stripped for re-signing)
    pub keep_legacy_signatures: bool,
}

impl Default for RepackageOptions {
    fn default() -> Self {
        Self {
            custom_libtransd: None,
            config_properties: Vec::new(),
            primary_lib: None,
            so_alignment: 4096,
            keep_legacy_signatures: false,
        }
    }
}

/// Detailed report of APK repackaging operations
#[derive(Debug, Clone)]
pub struct RepackageReport {
    pub preserved_files: usize,
    pub stripped_signature_files: usize,
    pub arm32_libraries: Vec<String>,
    pub injected_arm64_lib: String,
    pub injected_config_path: String,
    pub primary_lib: String,
    pub output_size: usize,
}

/// Generates a minimal, syntactically valid AArch64 (64-bit ELF) shared library (`libtransd.so`)
///
/// Contains:
/// - Standard ELF64 header for AArch64 (EM_AARCH64)
/// - PT_LOAD and PT_DYNAMIC program headers
/// - Dynamic string and symbol table exporting `JNI_OnLoad` and `nativeInit`
/// - AArch64 machine code returning JNI_VERSION_1_6 (0x00010006)
pub fn generate_synthetic_arm64_libtransd() -> Vec<u8> {
    let mut elf = Vec::with_capacity(1024);

    // 1. ELF Header (64 bytes)
    elf.extend_from_slice(&[
        0x7F, b'E', b'L', b'F', // Magic
        2,                      // 64-bit (ELFCLASS64)
        1,                      // Little-Endian (ELFDATA2LSB)
        1,                      // Version 1
        0,                      // System V / Linux ABI
        0, 0, 0, 0, 0, 0, 0, 0, // Padding
    ]);
    elf.extend_from_slice(&3u16.to_le_bytes());   // e_type: ET_DYN (Shared object)
    elf.extend_from_slice(&183u16.to_le_bytes()); // e_machine: EM_AARCH64 (0xB7)
    elf.extend_from_slice(&1u32.to_le_bytes());   // e_version: 1
    elf.extend_from_slice(&0x1000u64.to_le_bytes()); // e_entry
    elf.extend_from_slice(&64u64.to_le_bytes());  // e_phoff: 64 (immediately after Ehdr)
    elf.extend_from_slice(&0u64.to_le_bytes());   // e_shoff: 0
    elf.extend_from_slice(&0u32.to_le_bytes());   // e_flags: 0
    elf.extend_from_slice(&64u16.to_le_bytes());  // e_ehsize: 64
    elf.extend_from_slice(&56u16.to_le_bytes());  // e_phentsize: 56
    elf.extend_from_slice(&2u16.to_le_bytes());   // e_phnum: 2 (PT_LOAD, PT_DYNAMIC)
    elf.extend_from_slice(&64u16.to_le_bytes());  // e_shentsize: 64
    elf.extend_from_slice(&0u16.to_le_bytes());   // e_shnum: 0
    elf.extend_from_slice(&0u16.to_le_bytes());   // e_shstrndx: 0

    // 2. Program Headers (2 * 56 = 112 bytes) -> ends at offset 64 + 112 = 176 (0xB0)
    // Phdr 0: PT_LOAD
    let mut phdr_load = vec![0u8; 56];
    LittleEndian::write_u32(&mut phdr_load[0..4], 1);          // PT_LOAD
    LittleEndian::write_u32(&mut phdr_load[4..8], 5);          // PF_R | PF_X
    LittleEndian::write_u64(&mut phdr_load[8..16], 0);         // p_offset
    LittleEndian::write_u64(&mut phdr_load[16..24], 0);        // p_vaddr
    LittleEndian::write_u64(&mut phdr_load[24..32], 0);        // p_paddr
    LittleEndian::write_u64(&mut phdr_load[32..40], 0x1000);   // p_filesz
    LittleEndian::write_u64(&mut phdr_load[40..48], 0x1000);   // p_memsz
    LittleEndian::write_u64(&mut phdr_load[48..56], 0x1000);   // p_align
    elf.extend_from_slice(&phdr_load);

    // Phdr 1: PT_DYNAMIC
    let dyn_offset: u64 = 0x200;
    let dyn_size: u64 = 7 * 16; // 7 dynamic entries of 16 bytes = 112 bytes
    let mut phdr_dyn = vec![0u8; 56];
    LittleEndian::write_u32(&mut phdr_dyn[0..4], 2);           // PT_DYNAMIC
    LittleEndian::write_u32(&mut phdr_dyn[4..8], 6);           // PF_R | PF_W
    LittleEndian::write_u64(&mut phdr_dyn[8..16], dyn_offset); // p_offset
    LittleEndian::write_u64(&mut phdr_dyn[16..24], dyn_offset);// p_vaddr
    LittleEndian::write_u64(&mut phdr_dyn[24..32], dyn_offset);// p_paddr
    LittleEndian::write_u64(&mut phdr_dyn[32..40], dyn_size);  // p_filesz
    LittleEndian::write_u64(&mut phdr_dyn[40..48], dyn_size);  // p_memsz
    LittleEndian::write_u64(&mut phdr_dyn[48..56], 8);         // p_align
    elf.extend_from_slice(&phdr_dyn);

    // 3. String Table (.dynstr) at offset 0xB0 (176)
    let strtab_offset: u64 = 0xB0;
    let mut strtab = Vec::new();
    strtab.push(0u8); // Index 0: empty string

    let soname_idx = strtab.len() as u32;
    strtab.extend_from_slice(b"libtransd.so\0");

    let jni_onload_idx = strtab.len() as u32;
    strtab.extend_from_slice(b"JNI_OnLoad\0");

    let native_init_idx = strtab.len() as u32;
    strtab.extend_from_slice(b"Java_com_transd_loader_TransdEngine_nativeInit\0");

    let strtab_size = strtab.len() as u64;
    elf.extend_from_slice(&strtab);

    // Align to 8 bytes for symbol table
    while elf.len() % 8 != 0 {
        elf.push(0);
    }

    // 4. Symbol Table (.dynsym) - 24 bytes per Elf64_Sym
    let symtab_offset = elf.len() as u64;

    // Entry 0: STN_UNDEF (all zero)
    elf.extend_from_slice(&[0u8; 24]);

    // Code offset (where JNI_OnLoad code will sit)
    let code_offset: u64 = 0x180;

    // Entry 1: JNI_OnLoad (FUNC, GLOBAL)
    let mut sym1 = vec![0u8; 24];
    LittleEndian::write_u32(&mut sym1[0..4], jni_onload_idx);
    sym1[4] = (1 << 4) | 2; // STB_GLOBAL << 4 | STT_FUNC
    sym1[5] = 0;
    LittleEndian::write_u16(&mut sym1[6..8], 1); // shndx = 1
    LittleEndian::write_u64(&mut sym1[8..16], code_offset);
    LittleEndian::write_u64(&mut sym1[16..24], 12); // size = 12 bytes
    elf.extend_from_slice(&sym1);

    // Entry 2: Java_com_transd_loader_TransdEngine_nativeInit
    let mut sym2 = vec![0u8; 24];
    LittleEndian::write_u32(&mut sym2[0..4], native_init_idx);
    sym2[4] = (1 << 4) | 2; // STB_GLOBAL << 4 | STT_FUNC
    sym2[5] = 0;
    LittleEndian::write_u16(&mut sym2[6..8], 1); // shndx = 1
    LittleEndian::write_u64(&mut sym2[8..16], code_offset + 12);
    LittleEndian::write_u64(&mut sym2[16..24], 8); // size = 8 bytes
    elf.extend_from_slice(&sym2);

    // Pad up to code_offset (0x180)
    while elf.len() < code_offset as usize {
        elf.push(0);
    }

    // 5. Machine Code Section
    // JNI_OnLoad:
    // movz w0, #0x0006          (0x528000c0)
    // movk w0, #0x0001, lsl #16 (0x72a00020) -> returns JNI_VERSION_1_6 = 0x00010006
    // ret                       (0xd65f03c0)
    elf.extend_from_slice(&[0xc0, 0x00, 0x80, 0x52]);
    elf.extend_from_slice(&[0x20, 0x00, 0xa0, 0x72]);
    elf.extend_from_slice(&[0xc0, 0x03, 0x5f, 0xd6]);

    // Java_com_transd_loader_TransdEngine_nativeInit:
    // movz w0, #0               (0x52800000) -> returns JNI_OK = 0
    // ret                       (0xd65f03c0)
    elf.extend_from_slice(&[0x00, 0x00, 0x80, 0x52]);
    elf.extend_from_slice(&[0xc0, 0x03, 0x5f, 0xd6]);

    // Pad up to dyn_offset (0x200)
    while elf.len() < dyn_offset as usize {
        elf.push(0);
    }

    // 6. Dynamic Section (.dynamic) - 16 bytes each
    let dyn_tags: [(i64, u64); 7] = [
        (14, soname_idx as u64),   // DT_SONAME
        (5, strtab_offset),        // DT_STRTAB
        (6, symtab_offset),        // DT_SYMTAB
        (10, strtab_size),         // DT_STRSZ
        (11, 24),                  // DT_SYMENT
        (12, code_offset),         // DT_INIT (points to JNI_OnLoad code)
        (0, 0),                    // DT_NULL
    ];

    for (tag, val) in dyn_tags {
        elf.extend_from_slice(&tag.to_le_bytes());
        elf.extend_from_slice(&val.to_le_bytes());
    }

    // Pad to 512 bytes
    while elf.len() < 512 {
        elf.push(0);
    }

    elf
}

/// Repackages an existing 32-bit ARM Android APK for ARM64-only execution
///
/// Steps:
/// 1. Reads all files, manifests, and assets from input APK.
/// 2. Verifies presence of 32-bit ARM (armeabi-v7a) native libraries.
/// 3. Injects `lib/arm64-v8a/libtransd.so` (host AArch64 bridge library).
/// 4. Injects `assets/transd_config.prop` with runtime engine configuration.
/// 5. Strips legacy signatures (`META-INF/*.SF`, `*.RSA`, `*.DSA`, `*.EC`) for clean re-signing.
/// 6. Aligns uncompressed `.so` libraries to 4KB (page alignment) for Android linker direct mmap.
/// 7. Emits standard, fully compliant APK package bytes ready for installation via ADB.
pub fn repackage_for_arm64(
    input_apk_bytes: &[u8],
    options: &RepackageOptions,
) -> Result<(Vec<u8>, RepackageReport), ApkError> {
    let apk = ApkPackage::open(input_apk_bytes)?;

    let arm32_libs = apk.arm32_libraries();
    if arm32_libs.is_empty() {
        return Err(ApkError::NoArm32Libraries);
    }

    let arm32_names: Vec<String> = arm32_libs.iter().map(|lib| lib.filename.clone()).collect();
    let primary_lib = match options.primary_lib {
        Some(ref name) => name.clone(),
        None => arm32_libs[0].filename.clone(),
    };

    let all_files = apk.read_all_files()?;
    let mut builder = ZipBuilder::new();
    builder.set_default_so_alignment(options.so_alignment);

    let mut preserved_files = 0;
    let mut stripped_signatures = 0;

    for (name, data) in all_files {
        // Strip legacy signatures unless explicitly told to keep them
        if !options.keep_legacy_signatures
            && name.starts_with("META-INF/")
            && (name.ends_with(".SF")
                || name.ends_with(".RSA")
                || name.ends_with(".DSA")
                || name.ends_with(".EC"))
        {
            stripped_signatures += 1;
            continue;
        }

        // Avoid duplicate bridge injection
        if name == "lib/arm64-v8a/libtransd.so" || name == "assets/transd_config.prop" {
            continue;
        }

        if name.ends_with(".so") {
            builder.add_file_aligned(&name, &data, options.so_alignment);
        } else {
            builder.add_file(&name, &data);
        }
        preserved_files += 1;
    }

    // Inject host ARM64 DBT bridge library
    let arm64_bridge_bytes = match options.custom_libtransd {
        Some(ref bytes) => bytes.clone(),
        None => generate_synthetic_arm64_libtransd(),
    };
    builder.add_file_aligned(
        "lib/arm64-v8a/libtransd.so",
        &arm64_bridge_bytes,
        options.so_alignment,
    );

    // Build assets/transd_config.prop
    let mut config_text = String::new();
    config_text.push_str("# Transd Dynamic Binary Translation Configuration\n");
    config_text.push_str("transd.version=0.1.0\n");
    config_text.push_str("transd.guest.abi=armeabi-v7a\n");
    config_text.push_str(&format!("transd.guest.primary_lib={}\n", primary_lib));
    config_text.push_str("transd.jit.pinned_regs=true\n");
    config_text.push_str("transd.jit.chaining=true\n");
    config_text.push_str("transd.vfs.enabled=true\n");
    config_text.push_str("transd.vfs.redirect_bionic=true\n");
    config_text.push_str("transd.vfs.arm32_proc_cpuinfo=true\n");
    config_text.push_str("transd.bridge.gles=true\n");
    config_text.push_str("transd.bridge.vulkan=true\n");

    for (k, v) in &options.config_properties {
        config_text.push_str(&format!("{}={}\n", k, v));
    }

    builder.add_file("assets/transd_config.prop", config_text.as_bytes());

    let repackaged_bytes = builder.build();
    let report = RepackageReport {
        preserved_files,
        stripped_signature_files: stripped_signatures,
        arm32_libraries: arm32_names,
        injected_arm64_lib: "lib/arm64-v8a/libtransd.so".to_string(),
        injected_config_path: "assets/transd_config.prop".to_string(),
        primary_lib,
        output_size: repackaged_bytes.len(),
    };

    Ok((repackaged_bytes, report))
}
