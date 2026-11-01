use std::fs;
use std::process::Command;
use transd_apk::ApkPackage;

/// Structured description of a connected Android device inspected via ADB
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdbDeviceInfo {
    pub serial: String,
    pub model: String,
    pub abilist: String,
    pub sdk_version: Option<u32>,
    pub release_version: Option<String>,
    pub is_arm64_only: bool,
    pub requires_transd: bool,
}

/// Compatibility evaluation of an APK package on a target Android device
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompatibilityEvaluation {
    pub compatible: bool,
    pub requires_transd_repackage: bool,
    pub reason: String,
}

/// Parses the output of `adb devices` into a list of active device serial IDs
pub fn parse_adb_devices_output(output: &str) -> Vec<String> {
    let mut devices = Vec::new();
    for line in output.lines().skip(1) {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 2 && parts[1] == "device" {
            devices.push(parts[0].to_string());
        }
    }
    devices
}

/// Constructs an `AdbDeviceInfo` from queried system properties
pub fn parse_device_info(
    serial: &str,
    model: &str,
    abilist: &str,
    sdk: Option<u32>,
    release: Option<&str>,
) -> AdbDeviceInfo {
    let is_arm64_only = !abilist.contains("armeabi") && abilist.contains("arm64");
    let requires_transd = is_arm64_only;

    AdbDeviceInfo {
        serial: serial.to_string(),
        model: model.to_string(),
        abilist: abilist.to_string(),
        sdk_version: sdk,
        release_version: release.map(|s| s.to_string()),
        is_arm64_only,
        requires_transd,
    }
}

/// Evaluates whether an APK can run natively or requires Transd DBT repackaging on the device
pub fn evaluate_compatibility(
    device: &AdbDeviceInfo,
    apk: &ApkPackage,
) -> CompatibilityEvaluation {
    let apk_arm32_only = apk.is_arm32_only();
    let apk_has_arm64 = apk.available_abis().iter().any(|a| a == "arm64-v8a");
    let has_transd_bridge = apk
        .archive()
        .contains_file("lib/arm64-v8a/libtransd.so");

    if device.is_arm64_only {
        if apk_has_arm64 && has_transd_bridge {
            CompatibilityEvaluation {
                compatible: true,
                requires_transd_repackage: false,
                reason: "APK is repackaged with Transd DBT host bridge. Ready for ARM64-only execution!".into(),
            }
        } else if apk_arm32_only {
            CompatibilityEvaluation {
                compatible: false,
                requires_transd_repackage: true,
                reason: "Device is ARM64-ONLY (No AArch32 EL0 silicon). APK contains only 32-bit ARM libraries. Native installation will fail with INSTALL_FAILED_NO_MATCHING_ABIS. Run 'transd-cli package' first.".into(),
            }
        } else if apk_has_arm64 {
            CompatibilityEvaluation {
                compatible: true,
                requires_transd_repackage: false,
                reason: "APK contains native 64-bit ARM binaries and will execute natively.".into(),
            }
        } else {
            CompatibilityEvaluation {
                compatible: false,
                requires_transd_repackage: true,
                reason: "APK has no compatible ARM64 libraries for this ARM64-only device.".into(),
            }
        }
    } else {
        CompatibilityEvaluation {
            compatible: true,
            requires_transd_repackage: false,
            reason: "Target device supports 32-bit ARM natively (hybrid 32/64-bit hardware present).".into(),
        }
    }
}

/// Queries ADB for all currently connected and authorized Android devices
pub fn list_devices() -> Result<Vec<AdbDeviceInfo>, Box<dyn std::error::Error>> {
    let output = Command::new("adb").arg("devices").output()?;
    let text = String::from_utf8_lossy(&output.stdout);
    let serials = parse_adb_devices_output(&text);

    let mut devices = Vec::new();
    for ser in serials {
        let abi_out = Command::new("adb")
            .args(["-s", &ser, "shell", "getprop", "ro.product.cpu.abilist"])
            .output();
        let abis = match abi_out {
            Ok(o) => String::from_utf8_lossy(&o.stdout).trim().to_string(),
            Err(_) => "unknown".to_string(),
        };

        let model_out = Command::new("adb")
            .args(["-s", &ser, "shell", "getprop", "ro.product.model"])
            .output();
        let model = match model_out {
            Ok(o) => String::from_utf8_lossy(&o.stdout).trim().to_string(),
            Err(_) => "Android Device".to_string(),
        };

        let sdk_out = Command::new("adb")
            .args(["-s", &ser, "shell", "getprop", "ro.build.version.sdk"])
            .output();
        let sdk = sdk_out
            .ok()
            .and_then(|o| String::from_utf8_lossy(&o.stdout).trim().parse::<u32>().ok());

        let rel_out = Command::new("adb")
            .args(["-s", &ser, "shell", "getprop", "ro.build.version.release"])
            .output();
        let release = rel_out
            .ok()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string());

        devices.push(parse_device_info(
            &ser,
            &model,
            &abis,
            sdk,
            release.as_deref(),
        ));
    }

    Ok(devices)
}

/// Inspect connected Android devices via ADB to determine 32-bit vs ARM64-only capabilities
pub fn check_adb_devices() {
    println!("=== Transd Android ADB Device Inspector ===");

    match list_devices() {
        Ok(devices) => {
            if devices.is_empty() {
                println!("No connected Android devices detected via ADB.");
                println!("Connect an Android device with USB debugging enabled or start an emulator.");
                return;
            }

            println!("Detected {} connected Android device(s):", devices.len());
            for dev in devices {
                println!("\nDevice: {} ({})", dev.serial, dev.model);
                println!("  Supported ABIs: {}", dev.abilist);
                if let Some(sdk) = dev.sdk_version {
                    println!(
                        "  Android Version: {} (API level {})",
                        dev.release_version.as_deref().unwrap_or("unknown"),
                        sdk
                    );
                }
                if dev.is_arm64_only {
                    println!("  Architecture: ARM64-ONLY (ARMv9+ Cortex-X3 / A715 - No AArch32 EL0 silicon)");
                    println!("  DBT Status:   Transd REQUIRED to run 32-bit legacy APKs");
                } else {
                    println!("  Architecture: Mixed 32/64-bit hardware support present");
                    println!("  DBT Status:   Transd operational in emulation/compatibility mode");
                }
            }
        }
        Err(_) => {
            println!("Status: 'adb' command not found in PATH or ADB daemon failed to start.");
            println!("Tip: Install Android SDK Platform-Tools to interact with physical devices / emulators.");
        }
    }
}

/// Runs a comprehensive on-device diagnostic and optional APK compatibility check
pub fn test_device(
    device_id: Option<&str>,
    apk_path: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Transd ADB On-Device Test Runner ===");

    let devices = list_devices()?;
    if devices.is_empty() {
        println!("Error: No connected Android devices detected.");
        return Ok(());
    }

    let target_dev = match device_id {
        Some(id) => devices
            .into_iter()
            .find(|d| d.serial == id)
            .ok_or_else(|| format!("Target device '{}' not found", id))?,
        None => devices.into_iter().next().unwrap(),
    };

    println!("Selected Device: {} ({})", target_dev.serial, target_dev.model);
    println!("  CPU ABIs: {}", target_dev.abilist);
    println!(
        "  Android OS: {} (SDK {})",
        target_dev.release_version.as_deref().unwrap_or("unknown"),
        target_dev.sdk_version.map(|v| v.to_string()).unwrap_or_else(|| "unknown".into())
    );
    println!(
        "  ARM64-Only Silicon: {}",
        if target_dev.is_arm64_only { "YES (Requires Transd)" } else { "NO (Supports AArch32)" }
    );

    if let Some(path) = apk_path {
        println!("\n[Testing APK Compatibility: {}]", path);
        let apk_bytes = fs::read(path)?;
        let apk = ApkPackage::open(&apk_bytes)?;

        let eval = evaluate_compatibility(&target_dev, &apk);
        println!("  Target Result: {}", if eval.compatible { "COMPATIBLE" } else { "INCOMPATIBLE" });
        println!("  Evaluation:    {}", eval.reason);
        if eval.requires_transd_repackage {
            println!("  Action: Run 'transd-cli package {}' to inject Transd DBT host bridge.", path);
        }
    }

    Ok(())
}

/// Installs an APK onto a connected Android device via ADB
pub fn install_apk(
    device_id: Option<&str>,
    apk_path: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Transd ADB Package Installer ===");
    println!("Installing APK: {}", apk_path);

    if !std::path::Path::new(apk_path).exists() {
        return Err(format!("APK file '{}' does not exist", apk_path).into());
    }

    let mut cmd = Command::new("adb");
    if let Some(id) = device_id {
        cmd.args(["-s", id]);
    }
    cmd.args(["install", "-r", apk_path]);

    let output = cmd.output()?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    println!("{}", stdout);
    if !stderr.is_empty() {
        eprintln!("{}", stderr);
    }

    if output.status.success() && stdout.contains("Success") {
        println!("APK successfully installed on target device!");
    } else {
        println!("Installation finished with exit status: {}", output.status);
    }

    Ok(())
}

/// Launches an application on a connected device via ADB
pub fn launch_app(
    device_id: Option<&str>,
    target: &str,
    activity: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Transd ADB App Launcher ===");

    let (package_name, activity_name) = if target.ends_with(".apk") {
        println!("Inspecting APK to determine package and main activity: {}", target);
        let apk_bytes = fs::read(target)?;
        let apk = ApkPackage::open(&apk_bytes)?;

        let pkg = apk
            .manifest
            .as_ref()
            .map(|m| m.package_name.clone())
            .unwrap_or_else(|| "com.transd.app".into());

        let act = match activity {
            Some(a) => a.to_string(),
            None => apk
                .manifest
                .as_ref()
                .and_then(|m| m.main_activity.clone())
                .unwrap_or_else(|| ".MainActivity".into()),
        };

        (pkg, act)
    } else {
        let pkg = target.to_string();
        let act = activity.unwrap_or(".MainActivity").to_string();
        (pkg, act)
    };

    let component = if activity_name.starts_with('.') {
        format!("{}/{}", package_name, activity_name)
    } else if activity_name.contains('/') {
        activity_name
    } else {
        format!("{}/{}", package_name, activity_name)
    };

    println!("Launching Component: {}", component);

    let mut cmd = Command::new("adb");
    if let Some(id) = device_id {
        cmd.args(["-s", id]);
    }
    cmd.args(["shell", "am", "start", "-n", &component]);

    let output = cmd.output()?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    println!("{}", stdout);
    if !stderr.is_empty() {
        eprintln!("{}", stderr);
    }

    Ok(())
}
