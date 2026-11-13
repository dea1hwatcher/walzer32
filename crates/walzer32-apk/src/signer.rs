use std::path::PathBuf;
use std::process::Command;

/// Signs an APK using the platform's apksigner tool and a generated debug keystore.
///
/// Requires `JAVA_HOME` and `ANDROID_HOME` env vars (or falls back to known default paths).
/// Generates a temporary debug JKS keystore via `keytool` on first use, then
/// invokes `apksigner.bat sign` to produce a v2/v3-signed APK.
pub fn sign_apk(apk_bytes: Vec<u8>) -> Result<Vec<u8>, String> {
    let tmp = std::env::temp_dir();
    let apk_in = tmp.join("walzer32_unsigned.apk");
    let apk_out = tmp.join("walzer32_signed.apk");
    let ks_path = tmp.join("walzer32_debug.jks");

    std::fs::write(&apk_in, &apk_bytes).map_err(|e| format!("write unsigned apk: {e}"))?;

    let java_home = std::env::var("JAVA_HOME")
        .unwrap_or_else(|_| r"C:\Users\luna\.jdks\jdk-21.0.13.0.2+1".to_string());
    let android_home = std::env::var("ANDROID_HOME")
        .unwrap_or_else(|_| r"D:\Android\Sdk".to_string());

    // Generate debug keystore if not present
    if !ks_path.exists() {
        let keytool = PathBuf::from(&java_home).join("bin").join("keytool");
        let status = Command::new(&keytool)
            .args([
                "-genkeypair",
                "-v",
                "-keystore",
                ks_path.to_str().ok_or("bad ks path")?,
                "-storepass",
                "android",
                "-keypass",
                "android",
                "-alias",
                "walzer32debug",
                "-keyalg",
                "RSA",
                "-keysize",
                "2048",
                "-validity",
                "10000",
                "-dname",
                "CN=Walzer32 Debug, O=Android, C=US",
            ])
            .status()
            .map_err(|e| format!("keytool exec: {e}"))?;
        if !status.success() {
            return Err("keytool failed to generate debug keystore".into());
        }
    }

    // Sign with apksigner
    let apksigner = PathBuf::from(&android_home)
        .join("build-tools")
        .join("36.0.0")
        .join("apksigner.bat");

    let status = Command::new(&apksigner)
        .env("JAVA_HOME", &java_home)
        .args([
            "sign",
            "--ks",
            ks_path.to_str().ok_or("bad ks path")?,
            "--ks-pass",
            "pass:android",
            "--key-pass",
            "pass:android",
            "--ks-key-alias",
            "walzer32debug",
            "--out",
            apk_out.to_str().ok_or("bad apk_out path")?,
            apk_in.to_str().ok_or("bad apk_in path")?,
        ])
        .status()
        .map_err(|e| format!("apksigner exec: {e}"))?;

    if !status.success() {
        return Err("apksigner sign failed".into());
    }

    std::fs::read(&apk_out).map_err(|e| format!("read signed apk: {e}"))
}
