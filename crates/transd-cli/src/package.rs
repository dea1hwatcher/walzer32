use std::fs;
use transd_apk::{repackage_for_arm64, ApkPackage, RepackageOptions};

/// Handles the `transd-cli package` command to convert a 32-bit ARM APK for ARM64-only execution
pub fn handle_package_command(
    input_path: &str,
    output_path: Option<&str>,
    custom_bridge: Option<&str>,
    primary_lib: Option<&str>,
    align: Option<usize>,
    config_props: &[(String, String)],
) -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Transd APK Repackaging Pipeline ===");
    println!("Input APK:       {}", input_path);

    let input_bytes = fs::read(input_path)?;
    let original_apk = ApkPackage::open(&input_bytes)?;

    println!(
        "Package:         {}",
        original_apk
            .manifest
            .as_ref()
            .map(|m| m.package_name.as_str())
            .unwrap_or("unknown")
    );
    let orig_abis = original_apk.available_abis();
    println!("Original ABIs:   {:?}", orig_abis);

    let arm32_libs = original_apk.arm32_libraries();
    println!("32-bit Libraries: {} found", arm32_libs.len());
    for lib in &arm32_libs {
        println!("  - {}", lib.path);
    }

    if arm32_libs.is_empty() {
        return Err("Cannot repackage: No 32-bit ARM (armeabi-v7a) native libraries found in APK".into());
    }

    // Prepare repackaging options
    let mut options = RepackageOptions::default();
    if let Some(align_val) = align {
        options.so_alignment = align_val;
    }
    if let Some(plib) = primary_lib {
        options.primary_lib = Some(plib.to_string());
    }
    if let Some(bridge_path) = custom_bridge {
        println!("Custom Bridge:   {}", bridge_path);
        let bridge_bytes = fs::read(bridge_path)?;
        options.custom_libtransd = Some(bridge_bytes);
    }
    options.config_properties = config_props.to_vec();

    println!("\nRepackaging for ARM64-only devices...");
    let (repackaged_bytes, report) = repackage_for_arm64(&input_bytes, &options)?;

    // Determine output file path
    let default_output = if let Some(stripped) = input_path.strip_suffix(".apk") {
        format!("{}-arm64.apk", stripped)
    } else {
        format!("{}.arm64.apk", input_path)
    };
    let final_output = output_path.unwrap_or(&default_output);

    fs::write(final_output, &repackaged_bytes)?;

    println!("\nRepackaging Successful!");
    println!("  Preserved Files:       {}", report.preserved_files);
    println!("  Stripped Signatures:   {}", report.stripped_signature_files);
    println!("  Primary 32-bit Lib:    {}", report.primary_lib);
    println!("  Injected Host Bridge:  {} (4KB page-aligned)", report.injected_arm64_lib);
    println!("  Injected Config:       {}", report.injected_config_path);
    println!("  Output File:           {}", final_output);
    println!(
        "  Output Size:           {:.2} KB (was {:.2} KB)",
        report.output_size as f64 / 1024.0,
        input_bytes.len() as f64 / 1024.0
    );

    println!("\nNext steps:");
    println!("  1. (Optional) Sign APK:   apksigner sign --ks debug.keystore {}", final_output);
    println!("  2. Install via ADB:       transd-cli install {}", final_output);
    println!("  3. Launch on device:      transd-cli launch {}", final_output);

    Ok(())
}
