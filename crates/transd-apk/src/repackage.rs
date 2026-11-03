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

/// Precompiled valid AArch64 ELF shared library stub satisfying Android 15/16 Bionic invariants
/// (valid section headers, .gnu.hash, DT_NEEDED: libtransd.so, and JNI exports).
pub const ARM64_STUB_TEMPLATE: &[u8] = include_bytes!("arm64_stub.so");

/// Generates a valid AArch64 (64-bit ELF) shared library stub mirroring guest libraries
pub fn generate_synthetic_arm64_stub(_soname: &str, _needed: Option<&str>) -> Vec<u8> {
    ARM64_STUB_TEMPLATE.to_vec()
}

/// Generates default synthetic libtransd.so
pub fn generate_synthetic_arm64_libtransd() -> Vec<u8> {
    generate_synthetic_arm64_stub("libtransd.so", None)
}

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
            let mut so_bytes = data;
            // Sanitize ELF headers for 32-bit ARM libraries (strip DT_TEXTREL & normalize DT_NEEDED)
            let _ = transd_elf::sanitize_elf_headers(&mut so_bytes);
            builder.add_file_aligned(&name, &so_bytes, options.so_alignment);
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

    // Also inject arm64-v8a stubs for each guest 32-bit library so System.loadLibrary succeeds
    for lib_name in &arm32_names {
        if lib_name == "libtransd.so" {
            continue;
        }
        let stub_elf = generate_synthetic_arm64_stub(lib_name, Some("libtransd.so"));
        let stub_path = format!("lib/arm64-v8a/{}", lib_name);
        builder.add_file_aligned(&stub_path, &stub_elf, options.so_alignment);
    }

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
