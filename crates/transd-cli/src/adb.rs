use std::process::Command;

/// Inspect connected Android devices via ADB to determine 32-bit vs ARM64-only capabilities
pub fn check_adb_devices() {
    println!("=== Transd Android ADB Device Inspector ===");

    let output = match Command::new("adb").arg("devices").output() {
        Ok(out) => out,
        Err(_) => {
            println!("Status: 'adb' command not found in PATH.");
            println!("Tip: Install Android SDK Platform-Tools to interact with physical devices / emulators.");
            return;
        }
    };

    let text = String::from_utf8_lossy(&output.stdout);
    let mut devices = Vec::new();
    for line in text.lines().skip(1) {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 2 && parts[1] == "device" {
            devices.push(parts[0].to_string());
        }
    }

    if devices.is_empty() {
        println!("No connected Android devices detected via ADB.");
        println!("Connect an Android device with USB debugging enabled or start an emulator.");
        return;
    }

    println!("Detected {} connected Android device(s):", devices.len());
    for dev in &devices {
        // Query CPU ABI list
        let abi_out = Command::new("adb")
            .args(["-s", dev, "shell", "getprop", "ro.product.cpu.abilist"])
            .output();
        let abis = match abi_out {
            Ok(o) => String::from_utf8_lossy(&o.stdout).trim().to_string(),
            Err(_) => "unknown".to_string(),
        };

        // Query Model name
        let model_out = Command::new("adb")
            .args(["-s", dev, "shell", "getprop", "ro.product.model"])
            .output();
        let model = match model_out {
            Ok(o) => String::from_utf8_lossy(&o.stdout).trim().to_string(),
            Err(_) => "unknown".to_string(),
        };

        let is_arm64_only = !abis.contains("armeabi") && abis.contains("arm64");

        println!("\nDevice: {} ({})", dev, model);
        println!("  Supported ABIs: {}", abis);
        if is_arm64_only {
            println!("  Architecture: ARM64-ONLY (ARMv9+ Cortex-X3 / A715 - No AArch32 EL0 silicon)");
            println!("  DBT Status:   Transd REQUIRED to run 32-bit legacy APKs");
        } else {
            println!("  Architecture: Mixed 32/64-bit hardware support present");
            println!("  DBT Status:   Transd operational in emulation/compatibility mode");
        }
    }
}
