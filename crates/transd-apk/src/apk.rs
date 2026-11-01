use std::collections::HashSet;
use thiserror::Error;

use crate::dex::{DexError, DexFile, DexNativeMethod, DexParser};
use crate::manifest::{ManifestError, ManifestInfo, ManifestParser};
use crate::zip::{ZipArchive, ZipError};

#[derive(Error, Debug)]
pub enum ApkError {
    #[error("ZIP archive error: {0}")]
    Zip(#[from] ZipError),
    #[error("Manifest error: {0}")]
    Manifest(#[from] ManifestError),
    #[error("DEX error: {0}")]
    Dex(#[from] DexError),
    #[error("No 32-bit ARM (armeabi-v7a) native libraries found in APK")]
    NoArm32Libraries,
    #[error("Library '{0}' not found in APK")]
    LibraryNotFound(String),
}

/// Information about a native shared library (.so) inside an APK
#[derive(Debug, Clone)]
pub struct ApkNativeLib {
    pub abi: String,
    pub path: String,
    pub filename: String,
    pub compressed_size: usize,
    pub uncompressed_size: usize,
}

/// Complete representation of an Android APK package
pub struct ApkPackage<'a> {
    archive: ZipArchive<'a>,
    pub manifest: Option<ManifestInfo>,
    pub dex: Option<DexFile>,
    pub native_libs: Vec<ApkNativeLib>,
}

impl<'a> ApkPackage<'a> {
    pub fn open(data: &'a [u8]) -> Result<Self, ApkError> {
        let archive = ZipArchive::new(data)?;

        // 1. Parse AndroidManifest.xml (if present)
        let manifest = if archive.entries.contains_key("AndroidManifest.xml") {
            let manifest_data = archive.read_file("AndroidManifest.xml")?;
            ManifestParser::parse(&manifest_data).ok()
        } else {
            None
        };

        // 2. Parse classes.dex (if present)
        let dex = if archive.entries.contains_key("classes.dex") {
            let dex_data = archive.read_file("classes.dex")?;
            DexParser::parse(&dex_data).ok()
        } else {
            None
        };

        // 3. Scan for native libraries across all ABIs in lib/
        let mut native_libs = Vec::new();
        for (path, entry) in &archive.entries {
            if path.starts_with("lib/") && path.ends_with(".so") {
                let parts: Vec<&str> = path.split('/').collect();
                if parts.len() >= 3 {
                    let abi = parts[1].to_string();
                    let filename = parts[2].to_string();
                    native_libs.push(ApkNativeLib {
                        abi,
                        path: path.clone(),
                        filename,
                        compressed_size: entry.compressed_size,
                        uncompressed_size: entry.uncompressed_size,
                    });
                }
            }
        }

        Ok(Self {
            archive,
            manifest,
            dex,
            native_libs,
        })
    }

    /// Returns list of unique ABIs present in this APK (e.g. ["armeabi-v7a", "arm64-v8a"])
    pub fn available_abis(&self) -> Vec<String> {
        let mut abis: HashSet<String> = HashSet::new();
        for lib in &self.native_libs {
            abis.insert(lib.abi.clone());
        }
        let mut list: Vec<String> = abis.into_iter().collect();
        list.sort();
        list
    }

    /// Checks if this APK is 32-bit ARM only (contains armeabi-v7a/armeabi, but NOT arm64-v8a)
    pub fn is_arm32_only(&self) -> bool {
        let abis = self.available_abis();
        let has_arm32 = abis.iter().any(|a| a == "armeabi-v7a" || a == "armeabi");
        let has_arm64 = abis.iter().any(|a| a == "arm64-v8a");
        has_arm32 && !has_arm64
    }

    /// Returns list of 32-bit ARM native libraries (armeabi-v7a or armeabi)
    pub fn arm32_libraries(&self) -> Vec<&ApkNativeLib> {
        self.native_libs
            .iter()
            .filter(|lib| lib.abi == "armeabi-v7a" || lib.abi == "armeabi")
            .collect()
    }

    /// Extracts the raw bytes of a specified native library from the APK
    pub fn extract_library(&self, filename: &str) -> Result<Vec<u8>, ApkError> {
        let target = self
            .arm32_libraries()
            .into_iter()
            .find(|lib| lib.filename == filename || lib.path == filename)
            .ok_or_else(|| ApkError::LibraryNotFound(filename.to_string()))?;

        let bytes = self.archive.read_file(&target.path)?;
        Ok(bytes)
    }

    /// Matches DEX native method declarations against 32-bit .so exported symbols
    pub fn resolve_jni_bindings(
        &self,
        so_data: &[u8],
    ) -> Result<Vec<(DexNativeMethod, bool)>, ApkError> {
        let elf = transd_elf::ElfParser::parse(so_data)
            .map_err(|e| ApkError::LibraryNotFound(format!("Invalid ELF in APK: {:?}", e)))?;

        let mut bindings = Vec::new();
        if let Some(ref dex) = self.dex {
            for method in &dex.native_methods {
                let symbol_exists = elf.find_dynamic_symbol(&method.jni_symbol).is_some();
                bindings.push((method.clone(), symbol_exists));
            }
        }

        Ok(bindings)
    }
}
