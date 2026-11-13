pub mod apk;
pub mod arm64_elf;
pub mod dex;
pub mod manifest;
pub mod repackage;
pub mod signer;
pub mod zip;

pub use apk::{ApkError, ApkNativeLib, ApkPackage};
pub use arm64_elf::{extract_arm32_jni_exports, generate_dynamic_arm64_stub};
pub use dex::{
    generate_walzer32_bootstrap_dex, DexError, DexFile, DexNativeMethod, DexParser, ACC_NATIVE,
    ACC_PUBLIC, ACC_STATIC,
};
pub use manifest::{
    has_extract_native_libs, patch_manifest_extract_native_libs, ManifestError, ManifestInfo,
    ManifestParser,
};
pub use repackage::{
    generate_synthetic_arm64_libwalzer32, generate_synthetic_arm64_stub, repackage_for_arm64,
    RepackageOptions, RepackageReport,
};
pub use signer::sign_apk;
pub use zip::{calculate_crc32, ZipArchive, ZipBuilder, ZipEntry, ZipError, ZipFileEntry};
