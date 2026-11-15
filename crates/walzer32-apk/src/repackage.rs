use crate::apk::{ApkError, ApkPackage};
use crate::zip::ZipBuilder;
use crate::{arm64_elf, dex, manifest};

/// Configuration options for APK repackaging
#[derive(Debug, Clone)]
pub struct RepackageOptions {
    /// Custom bytes for host arm64-v8a libwalzer32.so (if None, synthetic ARM64 ELF is generated)
    pub custom_libwalzer32: Option<Vec<u8>>,
    /// Additional key-value properties to inject into assets/walzer32_config.prop
    pub config_properties: Vec<(String, String)>,
    /// Primary 32-bit library filename to execute (auto-detected if None)
    pub primary_lib: Option<String>,
    /// Alignment for .so libraries (default: 4096 bytes for page-mmap)
    pub so_alignment: usize,
    /// Keep legacy signatures in META-INF (default: false, stripped for re-signing)
    pub keep_legacy_signatures: bool,
    /// Patch AndroidManifest.xml to set extractNativeLibs=true (default: true)
    pub patch_manifest: bool,
    /// Inject walzer32 DEX bootstrap as classes2.dex (default: true)
    pub inject_dex_bootstrap: bool,
    /// Sign the output APK via apksigner (requires JAVA_HOME + ANDROID_HOME, default: false)
    pub sign_output_apk: bool,
    /// Generate dynamic ARM64 stubs per-library using arm64_elf module (default: true)
    pub use_dynamic_arm64_stubs: bool,
}

impl Default for RepackageOptions {
    fn default() -> Self {
        Self {
            custom_libwalzer32: None,
            config_properties: Vec::new(),
            primary_lib: None,
            so_alignment: 4096,
            keep_legacy_signatures: false,
            patch_manifest: true,
            inject_dex_bootstrap: true,
            sign_output_apk: false,
            use_dynamic_arm64_stubs: true,
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
    pub patched_manifest: bool,
    pub injected_dex_bootstrap: bool,
    pub signed: bool,
}

/// Precompiled valid AArch64 ELF shared library stub satisfying Android 15/16 Bionic invariants
/// (valid section headers, .gnu.hash, DT_NEEDED: libwalzer32.so, and JNI exports).
pub const ARM64_STUB_TEMPLATE: &[u8] = include_bytes!("arm64_stub.so");

/// Generates a valid AArch64 (64-bit ELF) shared library stub mirroring guest libraries
pub fn generate_synthetic_arm64_stub(_soname: &str, _needed: Option<&str>) -> Vec<u8> {
    ARM64_STUB_TEMPLATE.to_vec()
}

/// Generates default synthetic libwalzer32.so
pub fn generate_synthetic_arm64_libwalzer32() -> Vec<u8> {
    generate_synthetic_arm64_stub("libwalzer32.so", None)
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

    // Collect metadata before reading all files (avoid borrow conflict with apk)
    let arm32_meta: Vec<(String, String)> = arm32_libs
        .iter()
        .map(|lib| (lib.path.clone(), lib.filename.clone()))
        .collect();
    let primary_lib = match options.primary_lib {
        Some(ref name) => name.clone(),
        None => arm32_meta[0].1.clone(),
    };
    let arm32_names: Vec<String> = arm32_meta.iter().map(|(_, n)| n.clone()).collect();

    let all_files = apk.read_all_files()?;

    // Build a lookup: zip-path -> bytes (used for dynamic stub generation)
    let file_map: std::collections::HashMap<String, Vec<u8>> =
        all_files.iter().cloned().collect();

    let mut builder = ZipBuilder::new();
    builder.set_default_so_alignment(options.so_alignment);

    let mut preserved_files = 0usize;
    let mut stripped_signatures = 0usize;

    for (name, data) in &all_files {
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

        // Skip entries we will re-inject
        if name == "lib/arm64-v8a/libwalzer32.so" || name == "assets/walzer32_config.prop" {
            continue;
        }

        if name.ends_with(".so") {
            let mut so_bytes = data.clone();
            // Sanitize ELF headers for 32-bit ARM libraries (strip DT_TEXTREL & normalize DT_NEEDED)
            let _ = walzer32_elf::sanitize_elf_headers(&mut so_bytes);
            builder.add_file_aligned(name, &so_bytes, options.so_alignment);
        } else {
            builder.add_file(name, data);
        }
        preserved_files += 1;
    }

    // Optionally patch AndroidManifest.xml
    let patched_manifest = if options.patch_manifest {
        if let Some(raw) = file_map.get("AndroidManifest.xml") {
            match manifest::patch_manifest_extract_native_libs(raw, true) {
                Ok(patched) => {
                    builder.replace_file("AndroidManifest.xml", &patched);
                    true
                }
                Err(_) => false,
            }
        } else {
            false
        }
    } else {
        false
    };

    // Inject host ARM64 DBT bridge library
    let arm64_bridge_bytes = match options.custom_libwalzer32 {
        Some(ref bytes) => bytes.clone(),
        None => generate_synthetic_arm64_libwalzer32(),
    };
    builder.add_file_aligned(
        "lib/arm64-v8a/libwalzer32.so",
        &arm64_bridge_bytes,
        options.so_alignment,
    );

    // Inject arm64-v8a stubs for each guest 32-bit library so System.loadLibrary succeeds
    for (zip_path, lib_filename) in &arm32_meta {
        if lib_filename == "libwalzer32.so" {
            continue;
        }
        let stub_elf = if options.use_dynamic_arm64_stubs {
            let empty = Vec::new();
            let lib_bytes = file_map.get(zip_path).unwrap_or(&empty);
            let exports = arm64_elf::extract_arm32_jni_exports(lib_bytes);
            arm64_elf::generate_dynamic_arm64_stub(lib_filename, &["libwalzer32.so"], &exports)
        } else {
            generate_synthetic_arm64_stub(lib_filename, Some("libwalzer32.so"))
        };
        let stub_path = format!("lib/arm64-v8a/{}", lib_filename);
        builder.add_file_aligned(&stub_path, &stub_elf, options.so_alignment);
    }

    // Optionally inject DEX bootstrap
    let injected_dex_bootstrap = if options.inject_dex_bootstrap {
        // Determine the next available classesN.dex name so Multidex APKs never get duplicate entries
        let mut max_dex_idx = 1usize;
        for (name, _) in &all_files {
            if name == "classes.dex" {
                max_dex_idx = max_dex_idx.max(1);
            } else if let Some(stripped) = name.strip_prefix("classes") {
                if let Some(idx_str) = stripped.strip_suffix(".dex") {
                    if let Ok(idx) = idx_str.parse::<usize>() {
                        max_dex_idx = max_dex_idx.max(idx);
                    }
                }
            }
        }
        let target_dex_name = format!("classes{}.dex", max_dex_idx + 1);
        let dex_bytes = dex::generate_walzer32_bootstrap_dex();
        builder.add_file(&target_dex_name, &dex_bytes);
        true
    } else {
        false
    };

    // Build assets/walzer32_config.prop
    let mut config_text = String::new();
    config_text.push_str("# Walzer32 Dynamic Binary Translation Configuration\n");
    config_text.push_str("walzer32.version=0.1.0\n");
    config_text.push_str("walzer32.guest.abi=armeabi-v7a\n");
    config_text.push_str(&format!("walzer32.guest.primary_lib={}\n", primary_lib));
    config_text.push_str("walzer32.jit.pinned_regs=true\n");
    config_text.push_str("walzer32.jit.chaining=true\n");
    config_text.push_str("walzer32.vfs.enabled=true\n");
    config_text.push_str("walzer32.vfs.redirect_bionic=true\n");
    config_text.push_str("walzer32.vfs.arm32_proc_cpuinfo=true\n");
    config_text.push_str("walzer32.bridge.gles=true\n");
    config_text.push_str("walzer32.bridge.vulkan=true\n");

    for (k, v) in &options.config_properties {
        config_text.push_str(&format!("{}={}\n", k, v));
    }

    builder.add_file("assets/walzer32_config.prop", config_text.as_bytes());

    let mut repackaged_bytes = builder.build();

    // Optionally sign the APK
    let signed = if options.sign_output_apk {
        repackaged_bytes = crate::signer::sign_apk(repackaged_bytes)
            .map_err(ApkError::Signer)?;
        true
    } else {
        false
    };

    let output_size = repackaged_bytes.len();
    let report = RepackageReport {
        preserved_files,
        stripped_signature_files: stripped_signatures,
        arm32_libraries: arm32_names,
        injected_arm64_lib: "lib/arm64-v8a/libwalzer32.so".to_string(),
        injected_config_path: "assets/walzer32_config.prop".to_string(),
        primary_lib,
        output_size,
        patched_manifest,
        injected_dex_bootstrap,
        signed,
    };

    Ok((repackaged_bytes, report))
}
