use transd_apk::ApkPackage;
use crate::runner;

pub fn handle_apk_command(
    path: &str,
    data: &[u8],
    run_app: bool,
    target_lib: Option<&str>,
    target_func: Option<&str>,
    args: &[u32],
    show_hud: bool,
) -> Result<u32, Box<dyn std::error::Error>> {
    println!("=== Transd APK Inspector: {} ===", path);

    let apk = ApkPackage::open(data)?;

    // 1. Package & Manifest Details
    if let Some(ref m) = apk.manifest {
        println!("Package Name:   {}", if m.package_name.is_empty() { "unknown" } else { &m.package_name });
        println!(
            "Version:        {} (code: {})",
            m.version_name.as_deref().unwrap_or("unspecified"),
            m.version_code.map(|c| c.to_string()).unwrap_or_else(|| "none".into())
        );
        println!(
            "SDK Levels:     Min SDK {}, Target SDK {}",
            m.min_sdk_version.map(|v| v.to_string()).unwrap_or_else(|| "any".into()),
            m.target_sdk_version.map(|v| v.to_string()).unwrap_or_else(|| "any".into())
        );
        if let Some(ref app) = m.application_name {
            println!("Application:    {}", app);
        }
        if let Some(ref act) = m.main_activity {
            println!("Main Activity:  {}", act);
        }
    } else {
        println!("Manifest:       No AndroidManifest.xml parsed");
    }

    // 2. ABI Compatibility Check
    let abis = apk.available_abis();
    println!("Available ABIs: {:?}", abis);
    println!("32-bit ARM Only: {}", if apk.is_arm32_only() { "YES (Requires Transd DBT on ARMv9+)" } else { "NO" });

    // 3. Native Libraries
    let arm32_libs = apk.arm32_libraries();
    println!("\n[32-bit Native Libraries ({} found)]", arm32_libs.len());
    for lib in &arm32_libs {
        println!(
            "  - {} ({:.2} KB uncompressed)",
            lib.path,
            lib.uncompressed_size as f64 / 1024.0
        );
    }

    if arm32_libs.is_empty() {
        println!("  (No armeabi-v7a / armeabi libraries detected)");
        return Ok(0);
    }

    // 4. DEX Classes & Native Methods
    if let Some(ref dex) = apk.dex {
        println!("\n[DEX Classes & Native Methods]");
        println!("  Total classes: {}", dex.classes.len());
        println!("  Native JNI methods: {}", dex.native_methods.len());

        for (idx, method) in dex.native_methods.iter().enumerate().take(15) {
            println!(
                "  [{}] {}.{}() -> JNI: {}",
                idx + 1,
                method.class_name,
                method.method_name,
                method.jni_symbol
            );
        }
        if dex.native_methods.len() > 15 {
            println!("  ... and {} more native methods", dex.native_methods.len() - 15);
        }
    }

    // 5. Execution (if requested)
    if run_app || target_func.is_some() {
        // Choose library to run
        let lib_filename = match target_lib {
            Some(name) => name,
            None => {
                // Default to the first .so in arm32_libs
                &arm32_libs[0].filename
            }
        };

        println!("\n[Extracting & Running 32-bit Native Library: {}]", lib_filename);
        let so_bytes = apk.extract_library(lib_filename)?;

        // Verify JNI bindings if DEX is present
        if let Ok(bindings) = apk.resolve_jni_bindings(&so_bytes) {
            let matched_count = bindings.iter().filter(|(_, bound)| *bound).count();
            println!("  Bound {} / {} DEX native methods into {}", matched_count, bindings.len(), lib_filename);
        }

        // Execute in DBT
        return runner::execute_so(lib_filename, &so_bytes, target_func, args, show_hud);
    }

    println!("\nTip: Use 'transd-cli apk {} --run' to execute primary native library in DBT.", path);
    Ok(0)
}
