use std::collections::HashMap;
use std::sync::Arc;
use walzer32_core::{GuestAddr, Memory, MemoryError, Reg};
use walzer32_elf::SymbolResolver;

pub const ASSET_SVC_MAGIC: u32 = 0xA50000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum AssetFuncId {
    AAssetManagerFromJava = 1,
    AAssetManagerOpen = 2,
    AAssetManagerOpenDir = 3,
    AAssetRead = 4,
    AAssetSeek = 5,
    AAssetSeek64 = 6,
    AAssetGetLength = 7,
    AAssetGetLength64 = 8,
    AAssetGetRemainingLength = 9,
    AAssetGetRemainingLength64 = 10,
    AAssetGetBuffer = 11,
    AAssetClose = 12,
    AAssetDirGetNextFileName = 13,
    AAssetDirRewind = 14,
    AAssetDirClose = 15,
    AAssetIsAllocated = 16,
}

impl AssetFuncId {
    pub fn from_u32(val: u32) -> Option<Self> {
        match val {
            1 => Some(Self::AAssetManagerFromJava),
            2 => Some(Self::AAssetManagerOpen),
            3 => Some(Self::AAssetManagerOpenDir),
            4 => Some(Self::AAssetRead),
            5 => Some(Self::AAssetSeek),
            6 => Some(Self::AAssetSeek64),
            7 => Some(Self::AAssetGetLength),
            8 => Some(Self::AAssetGetLength64),
            9 => Some(Self::AAssetGetRemainingLength),
            10 => Some(Self::AAssetGetRemainingLength64),
            11 => Some(Self::AAssetGetBuffer),
            12 => Some(Self::AAssetClose),
            13 => Some(Self::AAssetDirGetNextFileName),
            14 => Some(Self::AAssetDirRewind),
            15 => Some(Self::AAssetDirClose),
            16 => Some(Self::AAssetIsAllocated),
            _ => None,
        }
    }
}

/// An open Android asset descriptor managed by AssetBridge
#[derive(Debug, Clone)]
pub struct OpenAsset {
    pub path: String,
    pub data: Arc<Vec<u8>>,
    pub cursor: usize,
    pub mode: u32,
    pub guest_buffer: Option<GuestAddr>,
}

/// An open directory iterator over APK assets
#[derive(Debug, Clone)]
pub struct OpenAssetDir {
    pub dir_path: String,
    pub file_names: Vec<String>,
    pub current_index: usize,
    pub name_buf_addr: GuestAddr,
}

/// Bridge for Android NDK AssetManager C API (`libandroid.so`)
pub struct AssetBridge {
    pub stub_base: GuestAddr,
    pub heap_current: GuestAddr,
    pub heap_limit: GuestAddr,
    symbol_table: HashMap<String, GuestAddr>,
    pub assets_map: HashMap<String, Arc<Vec<u8>>>,
    pub open_assets: HashMap<u32, OpenAsset>,
    pub open_dirs: HashMap<u32, OpenAssetDir>,
    next_asset_handle: u32,
    next_dir_handle: u32,
    pub stats_assets_opened: u64,
    pub stats_bytes_read: u64,
}

impl AssetBridge {
    pub fn new(stub_base: GuestAddr, heap_start: GuestAddr, heap_size: u32) -> Self {
        let mut bridge = Self {
            stub_base,
            heap_current: heap_start,
            heap_limit: heap_start.add(heap_size),
            symbol_table: HashMap::new(),
            assets_map: HashMap::new(),
            open_assets: HashMap::new(),
            open_dirs: HashMap::new(),
            next_asset_handle: 0xA000_0001,
            next_dir_handle: 0xD000_0001,
            stats_assets_opened: 0,
            stats_bytes_read: 0,
        };

        bridge.register_known_symbols();
        bridge
    }

    /// Creates an AssetBridge with default 2MB heap starting at stub_base + 0x1000
    pub fn with_stub_base(stub_base: GuestAddr) -> Self {
        Self::new(stub_base, stub_base.add(0x1000), 0x20_0000)
    }

    fn register_known_symbols(&mut self) {
        let funcs = [
            ("AAssetManager_fromJava", AssetFuncId::AAssetManagerFromJava),
            ("AAssetManager_open", AssetFuncId::AAssetManagerOpen),
            ("AAssetManager_openDir", AssetFuncId::AAssetManagerOpenDir),
            ("AAsset_read", AssetFuncId::AAssetRead),
            ("AAsset_seek", AssetFuncId::AAssetSeek),
            ("AAsset_seek64", AssetFuncId::AAssetSeek64),
            ("AAsset_getLength", AssetFuncId::AAssetGetLength),
            ("AAsset_getLength64", AssetFuncId::AAssetGetLength64),
            ("AAsset_getRemainingLength", AssetFuncId::AAssetGetRemainingLength),
            ("AAsset_getRemainingLength64", AssetFuncId::AAssetGetRemainingLength64),
            ("AAsset_getBuffer", AssetFuncId::AAssetGetBuffer),
            ("AAsset_close", AssetFuncId::AAssetClose),
            ("AAssetDir_getNextFileName", AssetFuncId::AAssetDirGetNextFileName),
            ("AAssetDir_rewind", AssetFuncId::AAssetDirRewind),
            ("AAssetDir_close", AssetFuncId::AAssetDirClose),
            ("AAsset_isAllocated", AssetFuncId::AAssetIsAllocated),
        ];

        for (name, id) in funcs {
            let addr = self.stub_base.add((id as u32) * 8);
            self.symbol_table.insert(name.to_string(), addr);
        }
    }

    /// Initializes stub code into guest memory at stub_base
    pub fn install_stubs(&self, mem: &mut impl Memory) -> Result<(), MemoryError> {
        for &id in &[
            AssetFuncId::AAssetManagerFromJava,
            AssetFuncId::AAssetManagerOpen,
            AssetFuncId::AAssetManagerOpenDir,
            AssetFuncId::AAssetRead,
            AssetFuncId::AAssetSeek,
            AssetFuncId::AAssetSeek64,
            AssetFuncId::AAssetGetLength,
            AssetFuncId::AAssetGetLength64,
            AssetFuncId::AAssetGetRemainingLength,
            AssetFuncId::AAssetGetRemainingLength64,
            AssetFuncId::AAssetGetBuffer,
            AssetFuncId::AAssetClose,
            AssetFuncId::AAssetDirGetNextFileName,
            AssetFuncId::AAssetDirRewind,
            AssetFuncId::AAssetDirClose,
            AssetFuncId::AAssetIsAllocated,
        ] {
            let addr = self.stub_base.add((id as u32) * 8);
            let svc_code = 0xEF00_0000 | (ASSET_SVC_MAGIC | (id as u32));
            let bx_lr = 0xE12F_FF1E;

            mem.write_u32(addr, svc_code)?;
            mem.write_u32(addr.add(4), bx_lr)?;
        }
        Ok(())
    }

    /// Loads all assets contained in an APK archive into the bridge
    pub fn load_apk(&mut self, apk_bytes: &[u8]) -> Result<usize, walzer32_apk::ApkError> {
        let archive = walzer32_apk::ZipArchive::new(apk_bytes)?;
        let mut count = 0;
        for name in archive.file_names() {
            if name.starts_with("assets/") && !name.ends_with('/') {
                if let Ok(data) = archive.read_file(&name) {
                    let arc = Arc::new(data);
                    let stripped = name.trim_start_matches("assets/").to_string();
                    self.assets_map.insert(stripped, Arc::clone(&arc));
                    self.assets_map.insert(name, arc);
                    count += 1;
                }
            }
        }
        Ok(count)
    }

    /// Registers a custom in-memory asset
    pub fn register_asset(&mut self, path: &str, content: Vec<u8>) {
        let arc = Arc::new(content);
        let normalized = path.trim_start_matches('/').to_string();
        let stripped = normalized.trim_start_matches("assets/").to_string();
        self.assets_map.insert(stripped, Arc::clone(&arc));
        self.assets_map.insert(format!("assets/{normalized}"), arc);
    }

    /// Handles an AssetManager SVC invocation from 32-bit guest code
    pub fn handle_svc(
        &mut self,
        svc_imm: u32,
        cpu: &mut walzer32_core::CpuState,
        mem: &mut impl Memory,
    ) -> Result<bool, MemoryError> {
        if (svc_imm & 0xFF0000) != ASSET_SVC_MAGIC {
            return Ok(false);
        }

        let func_id_raw = svc_imm & 0xFFFF;
        let func_id = match AssetFuncId::from_u32(func_id_raw) {
            Some(id) => id,
            None => return Ok(false),
        };

        match func_id {
            AssetFuncId::AAssetManagerFromJava => {
                // Returns synthetic pointer to AAssetManager instance
                cpu.set_reg(Reg::R0, 0xA55E_0001);
            }
            AssetFuncId::AAssetManagerOpen => {
                let filename_ptr = GuestAddr::new(cpu.reg(Reg::R1));
                let mode = cpu.reg(Reg::R2);
                if filename_ptr.as_u32() == 0 {
                    cpu.set_reg(Reg::R0, 0);
                    return Ok(true);
                }
                let filename = Self::read_c_string(mem, filename_ptr)?;
                let normalized = filename
                    .trim_start_matches("./")
                    .trim_start_matches('/')
                    .trim_start_matches("assets/")
                    .to_string();

                let entry = self
                    .assets_map
                    .get(&normalized)
                    .or_else(|| self.assets_map.get(&filename))
                    .cloned();

                if let Some(data) = entry {
                    let handle = self.next_asset_handle;
                    self.next_asset_handle = self.next_asset_handle.wrapping_add(1);

                    self.open_assets.insert(
                        handle,
                        OpenAsset {
                            path: normalized,
                            data,
                            cursor: 0,
                            mode,
                            guest_buffer: None,
                        },
                    );
                    self.stats_assets_opened += 1;
                    cpu.set_reg(Reg::R0, handle);
                } else {
                    cpu.set_reg(Reg::R0, 0); // NULL (Asset not found)
                }
            }
            AssetFuncId::AAssetRead => {
                let handle = cpu.reg(Reg::R0);
                let buf_ptr = GuestAddr::new(cpu.reg(Reg::R1));
                let count = cpu.reg(Reg::R2) as usize;

                if let Some(asset) = self.open_assets.get_mut(&handle) {
                    let available = asset.data.len().saturating_sub(asset.cursor);
                    let to_read = count.min(available);
                    if to_read > 0 {
                        mem.write_bytes(buf_ptr, &asset.data[asset.cursor..asset.cursor + to_read])?;
                        asset.cursor += to_read;
                        self.stats_bytes_read += to_read as u64;
                        cpu.set_reg(Reg::R0, to_read as u32);
                    } else {
                        cpu.set_reg(Reg::R0, 0);
                    }
                } else {
                    cpu.set_reg(Reg::R0, (-1i32) as u32); // Error
                }
            }
            AssetFuncId::AAssetSeek | AssetFuncId::AAssetSeek64 => {
                let handle = cpu.reg(Reg::R0);
                let offset = cpu.reg(Reg::R1) as i32;
                let whence = cpu.reg(Reg::R2) as i32;

                if let Some(asset) = self.open_assets.get_mut(&handle) {
                    let new_cursor = match whence {
                        0 => offset as isize,                                // SEEK_SET
                        1 => (asset.cursor as isize) + (offset as isize),    // SEEK_CUR
                        2 => (asset.data.len() as isize) + (offset as isize),// SEEK_END
                        _ => -1,
                    };

                    if new_cursor < 0 {
                        cpu.set_reg(Reg::R0, (-1i32) as u32);
                    } else {
                        asset.cursor = (new_cursor as usize).min(asset.data.len());
                        cpu.set_reg(Reg::R0, asset.cursor as u32);
                        if func_id == AssetFuncId::AAssetSeek64 {
                            cpu.set_reg(Reg::R1, 0); // High 32 bits
                        }
                    }
                } else {
                    cpu.set_reg(Reg::R0, (-1i32) as u32);
                }
            }
            AssetFuncId::AAssetGetLength | AssetFuncId::AAssetGetLength64 => {
                let handle = cpu.reg(Reg::R0);
                if let Some(asset) = self.open_assets.get(&handle) {
                    cpu.set_reg(Reg::R0, asset.data.len() as u32);
                    if func_id == AssetFuncId::AAssetGetLength64 {
                        cpu.set_reg(Reg::R1, 0);
                    }
                } else {
                    cpu.set_reg(Reg::R0, (-1i32) as u32);
                }
            }
            AssetFuncId::AAssetGetRemainingLength | AssetFuncId::AAssetGetRemainingLength64 => {
                let handle = cpu.reg(Reg::R0);
                if let Some(asset) = self.open_assets.get(&handle) {
                    let remaining = asset.data.len().saturating_sub(asset.cursor);
                    cpu.set_reg(Reg::R0, remaining as u32);
                    if func_id == AssetFuncId::AAssetGetRemainingLength64 {
                        cpu.set_reg(Reg::R1, 0);
                    }
                } else {
                    cpu.set_reg(Reg::R0, (-1i32) as u32);
                }
            }
            AssetFuncId::AAssetGetBuffer => {
                let handle = cpu.reg(Reg::R0);
                if let Some(asset) = self.open_assets.get_mut(&handle) {
                    if asset.guest_buffer.is_none() {
                        let size = asset.data.len();
                        let align_size = (size + 7) & !7;
                        if self.heap_current.add(align_size as u32) <= self.heap_limit {
                            let ptr = self.heap_current;
                            self.heap_current = self.heap_current.add(align_size as u32);
                            mem.write_bytes(ptr, &asset.data)?;
                            asset.guest_buffer = Some(ptr);
                        }
                    }
                    let buf_addr = asset.guest_buffer.map(|p| p.as_u32()).unwrap_or(0);
                    cpu.set_reg(Reg::R0, buf_addr);
                } else {
                    cpu.set_reg(Reg::R0, 0);
                }
            }
            AssetFuncId::AAssetClose => {
                let handle = cpu.reg(Reg::R0);
                self.open_assets.remove(&handle);
                cpu.set_reg(Reg::R0, 0);
            }
            AssetFuncId::AAssetManagerOpenDir => {
                let dir_name_ptr = GuestAddr::new(cpu.reg(Reg::R1));
                let dir_name = if dir_name_ptr.as_u32() != 0 {
                    Self::read_c_string(mem, dir_name_ptr)?
                } else {
                    String::new()
                };
                let normalized_dir = dir_name.trim_start_matches('/').trim_start_matches("assets/").to_string();

                // Find all child files under normalized_dir
                let mut matched_files = Vec::new();
                for key in self.assets_map.keys() {
                    let clean = key.trim_start_matches("assets/");
                    if (normalized_dir.is_empty() || clean.starts_with(&normalized_dir)) && clean != normalized_dir {
                        let relative = if normalized_dir.is_empty() {
                            clean
                        } else {
                            clean[normalized_dir.len()..].trim_start_matches('/')
                        };
                        let child_name = relative.split('/').next().unwrap_or(relative).to_string();
                        if !matched_files.contains(&child_name) {
                            matched_files.push(child_name);
                        }
                    }
                }
                matched_files.sort();

                let handle = self.next_dir_handle;
                self.next_dir_handle = self.next_dir_handle.wrapping_add(1);

                // Allocate 256 bytes in heap for returned C filename strings
                if self.heap_current.add(256) > self.heap_limit {
                    cpu.set_reg(Reg::R0, 0);
                    return Ok(true);
                }
                let name_buf = self.heap_current;
                self.heap_current = self.heap_current.add(256);

                self.open_dirs.insert(
                    handle,
                    OpenAssetDir {
                        dir_path: normalized_dir,
                        file_names: matched_files,
                        current_index: 0,
                        name_buf_addr: name_buf,
                    },
                );

                cpu.set_reg(Reg::R0, handle);
            }
            AssetFuncId::AAssetDirGetNextFileName => {
                let handle = cpu.reg(Reg::R0);
                if let Some(dir) = self.open_dirs.get_mut(&handle) {
                    if dir.current_index < dir.file_names.len() {
                        let name = &dir.file_names[dir.current_index];
                        dir.current_index += 1;

                        let mut bytes = name.as_bytes().to_vec();
                        bytes.push(0); // Null terminator
                        let _ = mem.write_bytes(dir.name_buf_addr, &bytes);
                        cpu.set_reg(Reg::R0, dir.name_buf_addr.as_u32());
                    } else {
                        cpu.set_reg(Reg::R0, 0); // End of directory
                    }
                } else {
                    cpu.set_reg(Reg::R0, 0);
                }
            }
            AssetFuncId::AAssetDirRewind => {
                let handle = cpu.reg(Reg::R0);
                if let Some(dir) = self.open_dirs.get_mut(&handle) {
                    dir.current_index = 0;
                }
                cpu.set_reg(Reg::R0, 0);
            }
            AssetFuncId::AAssetDirClose => {
                let handle = cpu.reg(Reg::R0);
                self.open_dirs.remove(&handle);
                cpu.set_reg(Reg::R0, 0);
            }
            AssetFuncId::AAssetIsAllocated => {
                let handle = cpu.reg(Reg::R0);
                let allocated = self
                    .open_assets
                    .get(&handle)
                    .map(|a| u32::from(a.guest_buffer.is_some()))
                    .unwrap_or(0);
                cpu.set_reg(Reg::R0, allocated);
            }
        }

        Ok(true)
    }

    fn read_c_string(mem: &impl Memory, addr: GuestAddr) -> Result<String, MemoryError> {
        let mut bytes = Vec::new();
        let mut cur = addr;
        loop {
            let b = mem.read_u8(cur)?;
            if b == 0 {
                break;
            }
            bytes.push(b);
            cur = cur.add(1);
        }
        Ok(String::from_utf8_lossy(&bytes).to_string())
    }
}

impl SymbolResolver for AssetBridge {
    fn resolve(&self, name: &str) -> Option<GuestAddr> {
        self.symbol_table.get(name).copied()
    }
}
