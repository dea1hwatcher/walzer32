use std::collections::HashMap;
use byteorder::{ByteOrder, LittleEndian};
use thiserror::Error;
use transd_core::{GuestAddr, Memory, MemoryError};

use crate::header::*;
use crate::parser::{ElfError, ElfParser};

#[derive(Error, Debug)]
pub enum LoaderError {
    #[error("ELF parsing error: {0}")]
    Elf(#[from] ElfError),
    #[error("Memory error: {0}")]
    Memory(#[from] MemoryError),
    #[error("Relocation error: {0}")]
    Relocation(String),
}

/// Interface for resolving external symbol references (from other libraries or Bionic)
pub trait SymbolResolver {
    fn resolve(&self, name: &str) -> Option<GuestAddr>;
}

impl<T: SymbolResolver + ?Sized> SymbolResolver for &T {
    fn resolve(&self, name: &str) -> Option<GuestAddr> {
        (**self).resolve(name)
    }
}

impl<A: SymbolResolver, B: SymbolResolver> SymbolResolver for (A, B) {
    fn resolve(&self, name: &str) -> Option<GuestAddr> {
        self.0.resolve(name).or_else(|| self.1.resolve(name))
    }
}

/// Composite resolver chaining multiple symbol providers
pub struct CompositeResolver<'a> {
    resolvers: Vec<&'a dyn SymbolResolver>,
}

impl<'a> CompositeResolver<'a> {
    pub fn new() -> Self {
        Self {
            resolvers: Vec::new(),
        }
    }

    pub fn with(mut self, resolver: &'a dyn SymbolResolver) -> Self {
        self.resolvers.push(resolver);
        self
    }

    pub fn add(&mut self, resolver: &'a dyn SymbolResolver) {
        self.resolvers.push(resolver);
    }
}

impl<'a> Default for CompositeResolver<'a> {
    fn default() -> Self {
        Self::new()
    }
}

impl<'a> SymbolResolver for CompositeResolver<'a> {
    fn resolve(&self, name: &str) -> Option<GuestAddr> {
        for r in &self.resolvers {
            if let Some(addr) = r.resolve(name) {
                return Some(addr);
            }
        }
        None
    }
}

/// A dummy resolver that returns None for all symbols
pub struct NullResolver;
impl SymbolResolver for NullResolver {
    fn resolve(&self, _name: &str) -> Option<GuestAddr> {
        None
    }
}

/// Binding type of an exported or imported symbol
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SymbolBinding {
    Local,
    Global,
    Weak,
}

impl SymbolBinding {
    pub fn from_st_info(st_info: u8) -> Self {
        match st_info >> 4 {
            STB_LOCAL => Self::Local,
            STB_WEAK => Self::Weak,
            _ => Self::Global,
        }
    }
}

/// Detailed information about an ELF symbol
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SymbolInfo {
    pub name: String,
    pub addr: GuestAddr,
    pub size: u32,
    pub binding: SymbolBinding,
    pub version: Option<String>,
    pub is_default_version: bool,
}

/// Information about a successfully loaded shared object (.so)
#[derive(Debug, Clone)]
pub struct LoadedLibrary {
    /// Virtual base address in guest address space
    pub load_base: GuestAddr,
    /// Total virtual size occupied in memory
    pub total_size: usize,
    /// SONAME of this library (if present in DT_SONAME)
    pub soname: Option<String>,
    /// Dependencies required by this library (DT_NEEDED)
    pub needed: Vec<String>,
    /// Entry point address
    pub entry_point: GuestAddr,
    /// Constructor function (DT_INIT)
    pub init_func: Option<GuestAddr>,
    /// Array of constructor functions (DT_INIT_ARRAY)
    pub init_array: Vec<GuestAddr>,
    /// Array of destructor functions (DT_FINI_ARRAY)
    pub fini_array: Vec<GuestAddr>,
    /// Exported symbols map (Symbol Name -> Guest Address)
    pub symbols: HashMap<String, GuestAddr>,
    /// Detailed exported symbols map (Symbol Name -> List of SymbolInfo)
    pub symbol_details: HashMap<String, Vec<SymbolInfo>>,
}

impl LoadedLibrary {
    /// Finds the address of an exported symbol (e.g. "JNI_OnLoad")
    pub fn find_symbol(&self, name: &str) -> Option<GuestAddr> {
        if let Some(&addr) = self.symbols.get(name) {
            return Some(addr);
        }
        self.find_symbol_versioned(name, None)
    }

    /// Finds a symbol with an optional explicit version constraint (e.g. "LIBC" or "LIBC_PRIVATE")
    pub fn find_symbol_versioned(&self, name: &str, version: Option<&str>) -> Option<GuestAddr> {
        let (base_name, requested_ver) = if let Some(idx) = name.find('@') {
            let n = &name[..idx];
            let v = &name[idx + 1..];
            (n, Some(v.trim_start_matches('@')))
        } else {
            (name, version)
        };

        if let Some(list) = self.symbol_details.get(base_name) {
            if let Some(req_v) = requested_ver {
                for sym in list {
                    if let Some(v) = &sym.version {
                        if v == req_v {
                            return Some(sym.addr);
                        }
                    }
                }
            } else {
                // Prefer default version and strong global
                for sym in list {
                    if sym.is_default_version && sym.binding == SymbolBinding::Global {
                        return Some(sym.addr);
                    }
                }
                for sym in list {
                    if sym.is_default_version {
                        return Some(sym.addr);
                    }
                }
                if let Some(first) = list.first() {
                    return Some(first.addr);
                }
            }
        }
        None
    }
}

/// In-process Dynamic Shared Object (DSO) Registry for dynamic linking and dlsym
#[derive(Debug, Default, Clone)]
pub struct DsoRegistry {
    libraries: Vec<LoadedLibrary>,
    handle_map: HashMap<u32, usize>,
    next_handle: u32,
}

impl DsoRegistry {
    pub fn new() -> Self {
        Self {
            libraries: Vec::new(),
            handle_map: HashMap::new(),
            next_handle: 1,
        }
    }

    /// Registers a loaded library into the DSO registry and returns a stable handle
    pub fn register(&mut self, lib: LoadedLibrary) -> u32 {
        let handle = self.next_handle;
        self.next_handle += 1;
        let idx = self.libraries.len();
        self.libraries.push(lib);
        self.handle_map.insert(handle, idx);
        handle
    }

    /// Retrieves a reference to a loaded library by its handle
    pub fn get(&self, handle: u32) -> Option<&LoadedLibrary> {
        self.handle_map.get(&handle).and_then(|&idx| self.libraries.get(idx))
    }

    /// Finds a loaded library by its soname
    pub fn find_by_soname(&self, soname: &str) -> Option<(u32, &LoadedLibrary)> {
        for (&h, &idx) in &self.handle_map {
            if let Some(lib) = self.libraries.get(idx) {
                if let Some(s) = &lib.soname {
                    if s == soname {
                        return Some((h, lib));
                    }
                }
            }
        }
        None
    }

    /// Resolves a symbol via dlopen handle (RTLD_DEFAULT, RTLD_NEXT, or handle)
    pub fn dlsym(&self, handle: u32, symbol: &str, caller_handle: Option<u32>) -> Option<GuestAddr> {
        if handle == RTLD_DEFAULT || handle == 0xFFFF_FFFF {
            let mut weak_candidate = None;
            for lib in &self.libraries {
                if let Some(list) = lib.symbol_details.get(symbol) {
                    for sym in list {
                        if sym.binding == SymbolBinding::Global {
                            return Some(sym.addr);
                        } else if sym.binding == SymbolBinding::Weak && weak_candidate.is_none() {
                            weak_candidate = Some(sym.addr);
                        }
                    }
                } else if let Some(addr) = lib.find_symbol(symbol) {
                    return Some(addr);
                }
            }
            return weak_candidate;
        }

        if handle == RTLD_NEXT {
            let start_idx = if let Some(ch) = caller_handle {
                self.handle_map.get(&ch).map(|&i| i + 1).unwrap_or(0)
            } else {
                0
            };

            let mut weak_candidate = None;
            for lib in &self.libraries[start_idx..] {
                if let Some(list) = lib.symbol_details.get(symbol) {
                    for sym in list {
                        if sym.binding == SymbolBinding::Global {
                            return Some(sym.addr);
                        } else if sym.binding == SymbolBinding::Weak && weak_candidate.is_none() {
                            weak_candidate = Some(sym.addr);
                        }
                    }
                } else if let Some(addr) = lib.find_symbol(symbol) {
                    return Some(addr);
                }
            }
            return weak_candidate;
        }

        if let Some(lib) = self.get(handle) {
            return lib.find_symbol(symbol);
        }

        None
    }
}

impl SymbolResolver for DsoRegistry {
    fn resolve(&self, name: &str) -> Option<GuestAddr> {
        self.dlsym(RTLD_DEFAULT, name, None)
    }
}

pub struct ElfLoader;

impl ElfLoader {
    /// Loads a 32-bit ARM ELF shared object into memory at the specified load_base,
    /// performs memory mapping, processes dynamic tags, and resolves relocations.
    pub fn load(
        data: &[u8],
        load_base: GuestAddr,
        mem: &mut impl Memory,
        resolver: &impl SymbolResolver,
    ) -> Result<LoadedLibrary, LoaderError> {
        let parser = ElfParser::parse(data)?;

        // 1. Calculate virtual memory bounds across all PT_LOAD segments
        let mut min_vaddr = u32::MAX;
        let mut max_vaddr = 0u32;

        for ph in parser.load_segments() {
            if ph.p_vaddr < min_vaddr {
                min_vaddr = ph.p_vaddr;
            }
            let end = ph.p_vaddr + ph.p_memsz;
            if end > max_vaddr {
                max_vaddr = end;
            }
        }

        if min_vaddr == u32::MAX {
            return Err(LoaderError::Relocation("No PT_LOAD segments found".into()));
        }

        let total_size = (max_vaddr - min_vaddr) as usize;

        // 2. Load PT_LOAD segments into guest memory
        for ph in parser.load_segments() {
            let seg_target = load_base.add(ph.p_vaddr);
            let file_bytes = parser.segment_bytes(ph)?;

            // Copy file data
            mem.write_bytes(seg_target, file_bytes)?;

            // Zero out remaining BSS area (p_memsz - p_filesz)
            if ph.p_memsz > ph.p_filesz {
                let bss_size = (ph.p_memsz - ph.p_filesz) as usize;
                let bss_target = seg_target.add(ph.p_filesz);
                let zeroes = vec![0u8; bss_size];
                mem.write_bytes(bss_target, &zeroes)?;
            }
        }

        // 3. Process Dynamic Table
        let dyn_entries = parser.parse_dynamic_table()?;

        let mut strtab_vaddr = None;
        let mut strsz = 0usize;
        let mut symtab_vaddr = None;
        let mut syment = 16usize; // Default Elf32_Sym size is 16 bytes
        let mut rel_vaddr = None;
        let mut relsz = 0usize;
        let mut relent = 8usize; // Default Elf32_Rel size is 8 bytes
        let mut jmprel_vaddr = None;
        let mut pltrelsz = 0usize;
        let mut soname_offset = None;
        let mut needed_offsets = Vec::new();
        let mut init_vaddr = None;
        let mut init_array_vaddr = None;
        let mut init_arraysz = 0usize;
        let mut fini_array_vaddr = None;
        let mut fini_arraysz = 0usize;
        let mut versym_vaddr = None;
        let mut verdef_vaddr = None;
        let mut verdefnum = 0usize;
        let mut verneed_vaddr = None;
        let mut verneednum = 0usize;

        for entry in &dyn_entries {
            match entry.d_tag {
                DT_STRTAB => strtab_vaddr = Some(entry.d_val),
                DT_STRSZ => strsz = entry.d_val as usize,
                DT_SYMTAB => symtab_vaddr = Some(entry.d_val),
                DT_SYMENT => syment = entry.d_val as usize,
                DT_REL => rel_vaddr = Some(entry.d_val),
                DT_RELSZ => relsz = entry.d_val as usize,
                DT_RELENT => relent = entry.d_val as usize,
                DT_JMPREL => jmprel_vaddr = Some(entry.d_val),
                DT_PLTRELSZ => pltrelsz = entry.d_val as usize,
                DT_SONAME => soname_offset = Some(entry.d_val as usize),
                DT_NEEDED => needed_offsets.push(entry.d_val as usize),
                DT_INIT => init_vaddr = Some(entry.d_val),
                DT_INIT_ARRAY => init_array_vaddr = Some(entry.d_val),
                DT_INIT_ARRAYSZ => init_arraysz = entry.d_val as usize,
                DT_FINI_ARRAY => fini_array_vaddr = Some(entry.d_val),
                DT_FINI_ARRAYSZ => fini_arraysz = entry.d_val as usize,
                DT_VERSYM => versym_vaddr = Some(entry.d_val),
                DT_VERDEF => verdef_vaddr = Some(entry.d_val),
                DT_VERDEFNUM => verdefnum = entry.d_val as usize,
                DT_VERNEED => verneed_vaddr = Some(entry.d_val),
                DT_VERNEEDNUM => verneednum = entry.d_val as usize,
                _ => {}
            }
        }

        // Read dynamic string table from file data
        let strtab_offset = strtab_vaddr
            .and_then(|va| parser.vaddr_to_offset(va))
            .unwrap_or(0);

        let get_string = |str_off: usize| -> Option<String> {
            if str_off < strsz {
                parser.read_string_at(strtab_offset + str_off).ok().map(|s| s.to_string())
            } else {
                None
            }
        };

        let soname = soname_offset.and_then(get_string);
        let needed: Vec<String> = needed_offsets
            .into_iter()
            .filter_map(get_string)
            .collect();

        // 4. Build version string map from DT_VERNEED and DT_VERDEF
        let mut version_index_map = HashMap::new();
        if let Some(vn_va) = verneed_vaddr
            && let Some(mut vn_file_off) = parser.vaddr_to_offset(vn_va)
        {
            for _ in 0..verneednum {
                if vn_file_off + 16 > data.len() {
                    break;
                }
                let vn_cnt = LittleEndian::read_u16(&data[vn_file_off + 2..vn_file_off + 4]) as usize;
                let vn_aux = LittleEndian::read_u32(&data[vn_file_off + 8..vn_file_off + 12]) as usize;
                let vn_next = LittleEndian::read_u32(&data[vn_file_off + 12..vn_file_off + 16]) as usize;

                let mut vna_file_off = vn_file_off + vn_aux;
                for _ in 0..vn_cnt {
                    if vna_file_off + 16 > data.len() {
                        break;
                    }
                    let vna_other = LittleEndian::read_u16(&data[vna_file_off + 6..vna_file_off + 8]);
                    let vna_name = LittleEndian::read_u32(&data[vna_file_off + 8..vna_file_off + 12]) as usize;
                    let vna_next = LittleEndian::read_u32(&data[vna_file_off + 12..vna_file_off + 16]) as usize;

                    let ver_idx = vna_other & VERSYM_VERSION;
                    if let Some(ver_str) = get_string(vna_name) {
                        version_index_map.insert(ver_idx, ver_str);
                    }

                    if vna_next == 0 {
                        break;
                    }
                    vna_file_off += vna_next;
                }

                if vn_next == 0 {
                    break;
                }
                vn_file_off += vn_next;
            }
        }

        if let Some(vd_va) = verdef_vaddr
            && let Some(mut vd_file_off) = parser.vaddr_to_offset(vd_va)
        {
            for _ in 0..verdefnum {
                if vd_file_off + 20 > data.len() {
                    break;
                }
                let vd_ndx = LittleEndian::read_u16(&data[vd_file_off + 4..vd_file_off + 6]);
                let vd_cnt = LittleEndian::read_u16(&data[vd_file_off + 6..vd_file_off + 8]) as usize;
                let vd_aux = LittleEndian::read_u32(&data[vd_file_off + 12..vd_file_off + 16]) as usize;
                let vd_next = LittleEndian::read_u32(&data[vd_file_off + 16..vd_file_off + 20]) as usize;

                let mut vda_file_off = vd_file_off + vd_aux;
                for _ in 0..vd_cnt {
                    if vda_file_off + 8 > data.len() {
                        break;
                    }
                    let vda_name = LittleEndian::read_u32(&data[vda_file_off..vda_file_off + 4]) as usize;
                    let vda_next = LittleEndian::read_u32(&data[vda_file_off + 4..vda_file_off + 8]) as usize;

                    let ver_idx = vd_ndx & VERSYM_VERSION;
                    if let Some(ver_str) = get_string(vda_name) {
                        version_index_map.insert(ver_idx, ver_str);
                    }

                    if vda_next == 0 {
                        break;
                    }
                    vda_file_off += vda_next;
                }

                if vd_next == 0 {
                    break;
                }
                vd_file_off += vd_next;
            }
        }

        // 5. Parse Symbols and build exported symbol map
        let mut symbols = HashMap::new();
        let mut symbol_details: HashMap<String, Vec<SymbolInfo>> = HashMap::new();
        let versym_offset = versym_vaddr.and_then(|va| parser.vaddr_to_offset(va));

        if let Some(sym_va) = symtab_vaddr
            && let Some(sym_file_off) = parser.vaddr_to_offset(sym_va)
        {
            // If STRSZ is known, the symbol table typically ends where STRTAB begins or has reasonable count
            let max_symbols = if strtab_offset > sym_file_off {
                (strtab_offset - sym_file_off) / syment
            } else {
                1024 // Fallback reasonable upper bound
            };

            for i in 0..max_symbols {
                let off = sym_file_off + i * syment;
                if off + syment > data.len() {
                    break;
                }

                let st_name = LittleEndian::read_u32(&data[off..off + 4]);
                let st_value = LittleEndian::read_u32(&data[off + 4..off + 8]);
                let st_size = LittleEndian::read_u32(&data[off + 8..off + 12]);
                let st_info = data[off + 12];
                let _st_other = data[off + 13];
                let st_shndx = LittleEndian::read_u16(&data[off + 14..off + 16]);

                if st_name == 0 && st_value == 0 && i > 0 {
                    // End of symbol table reached
                    break;
                }

                if st_shndx != SHN_UNDEF
                    && st_value != 0
                    && let Some(name) = get_string(st_name as usize)
                    && !name.is_empty()
                {
                    let sym_addr = load_base.add(st_value);
                    let binding = SymbolBinding::from_st_info(st_info);

                    let (version, is_default_version) = if let Some(vs_off) = versym_offset {
                        if vs_off + (i + 1) * 2 <= data.len() {
                            let vs = LittleEndian::read_u16(&data[vs_off + i * 2..vs_off + (i + 1) * 2]);
                            let is_hidden = (vs & VERSYM_HIDDEN) != 0;
                            let v_idx = vs & VERSYM_VERSION;
                            let ver_name = version_index_map.get(&v_idx).cloned();
                            (ver_name, !is_hidden)
                        } else {
                            (None, true)
                        }
                    } else {
                        (None, true)
                    };

                    let info = SymbolInfo {
                        name: name.clone(),
                        addr: sym_addr,
                        size: st_size,
                        binding,
                        version,
                        is_default_version,
                    };
                    symbol_details.entry(name.clone()).or_default().push(info);

                    // Strong global symbols preempt weak symbols in the flat symbols map
                    if binding == SymbolBinding::Global {
                        symbols.insert(name, sym_addr);
                    } else {
                        symbols.entry(name).or_insert(sym_addr);
                    }
                }
            }
        }

        // Helper to read symbol name by index
        let get_symbol_name_by_idx = |idx: u32| -> Option<String> {
            if let Some(sym_va) = symtab_vaddr
                && let Some(sym_file_off) = parser.vaddr_to_offset(sym_va)
            {
                let off = sym_file_off + (idx as usize) * syment;
                if off + syment <= data.len() {
                    let st_name = LittleEndian::read_u32(&data[off..off + 4]) as usize;
                    return get_string(st_name);
                }
            }
            None
        };

        // Helper to read symbol binding by index
        let get_symbol_binding_by_idx = |idx: u32| -> SymbolBinding {
            if let Some(sym_va) = symtab_vaddr
                && let Some(sym_file_off) = parser.vaddr_to_offset(sym_va)
            {
                let off = sym_file_off + (idx as usize) * syment;
                if off + syment <= data.len() {
                    let st_info = data[off + 12];
                    return SymbolBinding::from_st_info(st_info);
                }
            }
            SymbolBinding::Global
        };

        // 6. Apply Relocations (both DT_REL and DT_JMPREL)
        let mut rel_tables = Vec::new();
        if let (Some(va), sz) = (rel_vaddr, relsz) {
            rel_tables.push((va, sz));
        }
        if let (Some(va), sz) = (jmprel_vaddr, pltrelsz) {
            rel_tables.push((va, sz));
        }

        for (table_va, table_sz) in rel_tables {
            let count = table_sz / relent;
            for i in 0..count {
                let rel_entry_addr = load_base.add(table_va + (i * relent) as u32);
                let r_offset = mem.read_u32(rel_entry_addr)?;
                let r_info = mem.read_u32(rel_entry_addr.add(4))?;

                let rel = Elf32Rel { r_offset, r_info };
                let target_addr = load_base.add(rel.r_offset);
                let r_type = rel.r_type();
                let sym_idx = rel.r_sym();

                match r_type {
                    R_ARM_NONE => {}
                    R_ARM_RELATIVE => {
                        // B + A (Base + addend in place)
                        let addend = mem.read_u32(target_addr)?;
                        let final_val = load_base.as_u32().wrapping_add(addend);
                        mem.write_u32(target_addr, final_val)?;
                    }
                    R_ARM_GLOB_DAT | R_ARM_JUMP_SLOT => {
                        // S (Symbol value)
                        if let Some(sym_name) = get_symbol_name_by_idx(sym_idx) {
                            let resolved = symbols
                                .get(&sym_name)
                                .copied()
                                .or_else(|| resolver.resolve(&sym_name));

                            if let Some(addr) = resolved {
                                mem.write_u32(target_addr, addr.as_u32())?;
                            } else if get_symbol_binding_by_idx(sym_idx) == SymbolBinding::Weak {
                                // Unresolved weak symbol safely defaults to NULL
                                mem.write_u32(target_addr, 0)?;
                            }
                        }
                    }
                    R_ARM_ABS32 => {
                        // S + A
                        if let Some(sym_name) = get_symbol_name_by_idx(sym_idx) {
                            let resolved = symbols
                                .get(&sym_name)
                                .copied()
                                .or_else(|| resolver.resolve(&sym_name));

                            if let Some(addr) = resolved {
                                let addend = mem.read_u32(target_addr)?;
                                let final_val = addr.as_u32().wrapping_add(addend);
                                mem.write_u32(target_addr, final_val)?;
                            } else if get_symbol_binding_by_idx(sym_idx) == SymbolBinding::Weak {
                                mem.write_u32(target_addr, 0)?;
                            }
                        }
                    }
                    _ => {}
                }
            }
        }

        // 6. Collect Init and Fini functions
        let init_func = init_vaddr.map(|va| load_base.add(va));

        let mut init_array = Vec::new();
        if let Some(va) = init_array_vaddr {
            let count = init_arraysz / 4;
            for i in 0..count {
                let func_ptr_addr = load_base.add(va + (i * 4) as u32);
                let func_addr = mem.read_u32(func_ptr_addr)?;
                if func_addr != 0 && func_addr != u32::MAX {
                    init_array.push(GuestAddr::new(func_addr));
                }
            }
        }

        let mut fini_array = Vec::new();
        if let Some(va) = fini_array_vaddr {
            let count = fini_arraysz / 4;
            for i in 0..count {
                let func_ptr_addr = load_base.add(va + (i * 4) as u32);
                let func_addr = mem.read_u32(func_ptr_addr)?;
                if func_addr != 0 && func_addr != u32::MAX {
                    fini_array.push(GuestAddr::new(func_addr));
                }
            }
        }

        Ok(LoadedLibrary {
            load_base,
            total_size,
            soname,
            needed,
            entry_point: load_base.add(parser.header.e_entry),
            init_func,
            init_array,
            fini_array,
            symbols,
            symbol_details,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use transd_core::FlatMemory;

    /// Helper to construct a minimal valid ARM32 ELF in memory for testing
    fn create_test_arm32_elf() -> Vec<u8> {
        let mut elf = vec![0u8; 512];

        // 1. Ehdr (52 bytes)
        elf[0..4].copy_from_slice(&ELF_MAGIC);
        elf[4] = ELFCLASS32;
        elf[5] = ELFDATA2LSB;
        elf[6] = EV_CURRENT;
        LittleEndian::write_u16(&mut elf[16..18], ET_DYN);
        LittleEndian::write_u16(&mut elf[18..20], EM_ARM);
        LittleEndian::write_u32(&mut elf[20..24], EV_CURRENT as u32);
        LittleEndian::write_u32(&mut elf[24..28], 0x1000); // e_entry
        LittleEndian::write_u32(&mut elf[28..32], 52);     // e_phoff
        LittleEndian::write_u16(&mut elf[40..42], 52);     // e_ehsize
        LittleEndian::write_u16(&mut elf[42..44], 32);     // e_phentsize
        LittleEndian::write_u16(&mut elf[44..46], 2);      // e_phnum (1 PT_LOAD, 1 PT_DYNAMIC)

        // 2. Phdr #0: PT_LOAD (offset 52)
        // Code/Data segment: filesz = 512, memsz = 512
        LittleEndian::write_u32(&mut elf[52..56], PT_LOAD);
        LittleEndian::write_u32(&mut elf[56..60], 0);      // p_offset
        LittleEndian::write_u32(&mut elf[60..64], 0);      // p_vaddr
        LittleEndian::write_u32(&mut elf[64..68], 0);      // p_paddr
        LittleEndian::write_u32(&mut elf[68..72], 512);    // p_filesz
        LittleEndian::write_u32(&mut elf[72..76], 512);    // p_memsz
        LittleEndian::write_u32(&mut elf[76..80], PF_R | PF_W | PF_X);
        LittleEndian::write_u32(&mut elf[80..84], 4096);   // p_align

        // 3. Phdr #1: PT_DYNAMIC (offset 84)
        // Dynamic segment located at offset 200, size 64 bytes (8 entries)
        LittleEndian::write_u32(&mut elf[84..88], PT_DYNAMIC);
        LittleEndian::write_u32(&mut elf[88..92], 200);    // p_offset
        LittleEndian::write_u32(&mut elf[92..96], 200);    // p_vaddr
        LittleEndian::write_u32(&mut elf[96..100], 200);   // p_paddr
        LittleEndian::write_u32(&mut elf[100..104], 64);   // p_filesz
        LittleEndian::write_u32(&mut elf[104..108], 64);   // p_memsz
        LittleEndian::write_u32(&mut elf[108..112], PF_R | PF_W);
        LittleEndian::write_u32(&mut elf[112..116], 4);    // p_align

        // 4. Strtab located at offset 300
        // "\0libtest.so\0JNI_OnLoad\0"
        let strtab = b"\0libtest.so\0JNI_OnLoad\0";
        elf[300..300 + strtab.len()].copy_from_slice(strtab);

        // 5. Symtab located at offset 350
        // Sym #0: undefined dummy (16 bytes)
        // Sym #1: JNI_OnLoad (st_name = 12, st_value = 0x80, st_info = STT_FUNC, st_shndx = 1)
        LittleEndian::write_u32(&mut elf[350 + 16..350 + 20], 12); // st_name -> "JNI_OnLoad"
        LittleEndian::write_u32(&mut elf[350 + 20..350 + 24], 0x80); // st_value = 0x80
        elf[350 + 28] = (STB_GLOBAL << 4) | STT_FUNC;
        LittleEndian::write_u16(&mut elf[350 + 30..350 + 32], 1); // st_shndx = 1

        // 6. Dynamic Table at offset 200
        // Entry 0: DT_STRTAB = 300
        LittleEndian::write_u32(&mut elf[200..204], DT_STRTAB);
        LittleEndian::write_u32(&mut elf[204..208], 300);
        // Entry 1: DT_STRSZ = strtab.len()
        LittleEndian::write_u32(&mut elf[208..212], DT_STRSZ);
        LittleEndian::write_u32(&mut elf[212..216], strtab.len() as u32);
        // Entry 2: DT_SONAME = 1 ("libtest.so")
        LittleEndian::write_u32(&mut elf[216..220], DT_SONAME);
        LittleEndian::write_u32(&mut elf[220..224], 1);
        // Entry 3: DT_SYMTAB = 350
        LittleEndian::write_u32(&mut elf[224..228], DT_SYMTAB);
        LittleEndian::write_u32(&mut elf[228..232], 350);
        // Entry 4: DT_NULL
        LittleEndian::write_u32(&mut elf[232..236], DT_NULL);
        LittleEndian::write_u32(&mut elf[236..240], 0);

        elf
    }

    #[test]
    fn test_elf_loader_basic() {
        let elf_bytes = create_test_arm32_elf();
        let mut mem = FlatMemory::new(GuestAddr::new(0x4000_0000), 0x10_000);

        let lib = ElfLoader::load(
            &elf_bytes,
            GuestAddr::new(0x4000_0000),
            &mut mem,
            &NullResolver,
        )
        .unwrap();

        assert_eq!(lib.load_base, GuestAddr::new(0x4000_0000));
        assert_eq!(lib.soname.as_deref(), Some("libtest.so"));

        // Verify that exported symbol JNI_OnLoad was correctly resolved to load_base + 0x80
        let jni_onload = lib.find_symbol("JNI_OnLoad").unwrap();
        assert_eq!(jni_onload, GuestAddr::new(0x4000_0080));
    }

    struct MockResolver;
    impl SymbolResolver for MockResolver {
        fn resolve(&self, name: &str) -> Option<GuestAddr> {
            if name == "__android_log_print" {
                Some(GuestAddr::new(0x7000_1234))
            } else {
                None
            }
        }
    }

    #[test]
    fn test_elf_loader_relocations() {
        let mut elf_bytes = create_test_arm32_elf();

        // Let's add a relocation table at offset 400 (size 16 bytes: 2 relocations)
        // Relocation 0: R_ARM_RELATIVE at offset 0x100
        // Initial value at offset 0x100 is 0x40. Base = 0x4000_0000. Expected final value = 0x4000_0040.
        LittleEndian::write_u32(&mut elf_bytes[0x100..0x104], 0x40);

        // Rel 0: r_offset = 0x100, r_info = (0 << 8) | R_ARM_RELATIVE (23)
        LittleEndian::write_u32(&mut elf_bytes[400..404], 0x100);
        LittleEndian::write_u32(&mut elf_bytes[404..408], R_ARM_RELATIVE as u32);

        // Relocation 1: R_ARM_GLOB_DAT at offset 0x104 for symbol __android_log_print
        // We add symbol 2: __android_log_print in strtab and symtab
        let log_name_offset = 300 + 23; // after "\0libtest.so\0JNI_OnLoad\0"
        let log_str = b"__android_log_print\0";
        elf_bytes[log_name_offset..log_name_offset + log_str.len()].copy_from_slice(log_str);

        // Update DT_STRSZ in Dynamic table (Entry 1 at offset 208)
        let total_strsz = 23 + log_str.len();
        LittleEndian::write_u32(&mut elf_bytes[212..216], total_strsz as u32);

        // Sym 2 in symtab (offset 350 + 32):
        LittleEndian::write_u32(&mut elf_bytes[350 + 32..350 + 36], 23); // st_name
        LittleEndian::write_u32(&mut elf_bytes[350 + 36..350 + 40], 0);    // st_value = 0 (undefined / imported)
        LittleEndian::write_u16(&mut elf_bytes[350 + 46..350 + 48], SHN_UNDEF);

        // Rel 1: r_offset = 0x104, r_info = (2 << 8) | R_ARM_GLOB_DAT (21)
        LittleEndian::write_u32(&mut elf_bytes[408..412], 0x104);
        LittleEndian::write_u32(&mut elf_bytes[412..416], (2 << 8) | (R_ARM_GLOB_DAT as u32));

        // Update Dynamic table to include DT_REL = 400, DT_RELSZ = 16, DT_RELENT = 8
        // Entry 4: DT_REL = 400
        LittleEndian::write_u32(&mut elf_bytes[232..236], DT_REL);
        LittleEndian::write_u32(&mut elf_bytes[236..240], 400);
        // Entry 5: DT_RELSZ = 16
        LittleEndian::write_u32(&mut elf_bytes[240..244], DT_RELSZ);
        LittleEndian::write_u32(&mut elf_bytes[244..248], 16);
        // Entry 6: DT_NULL
        LittleEndian::write_u32(&mut elf_bytes[248..252], DT_NULL);
        LittleEndian::write_u32(&mut elf_bytes[252..256], 0);

        let mut mem = FlatMemory::new(GuestAddr::new(0x4000_0000), 0x10_000);
        let _lib = ElfLoader::load(
            &elf_bytes,
            GuestAddr::new(0x4000_0000),
            &mut mem,
            &MockResolver,
        )
        .unwrap();

        // Verify R_ARM_RELATIVE was applied: mem at 0x4000_0100 should be 0x4000_0040
        let rel_val = mem.read_u32(GuestAddr::new(0x4000_0100)).unwrap();
        assert_eq!(rel_val, 0x4000_0040);

        // Verify R_ARM_GLOB_DAT was applied: mem at 0x4000_0104 should be 0x7000_1234
        let glob_val = mem.read_u32(GuestAddr::new(0x4000_0104)).unwrap();
        assert_eq!(glob_val, 0x7000_1234);
    }

    #[test]
    fn test_elf_loader_unresolved_weak_relocation() {
        let mut elf_bytes = create_test_arm32_elf();

        // Target address initially contains garbage non-zero value
        LittleEndian::write_u32(&mut elf_bytes[0x104..0x108], 0xDEAD_BEEF);

        // Add symbol 2: "optional_extension" as STB_WEAK, undefined
        let opt_name_offset = 300 + 23;
        let opt_str = b"optional_extension\0";
        elf_bytes[opt_name_offset..opt_name_offset + opt_str.len()].copy_from_slice(opt_str);

        let total_strsz = 23 + opt_str.len();
        LittleEndian::write_u32(&mut elf_bytes[212..216], total_strsz as u32);

        // Sym 2 in symtab (offset 350 + 32):
        LittleEndian::write_u32(&mut elf_bytes[350 + 32..350 + 36], 23); // st_name
        LittleEndian::write_u32(&mut elf_bytes[350 + 36..350 + 40], 0);    // st_value = 0
        elf_bytes[350 + 32 + 12] = (STB_WEAK << 4) | STT_FUNC;
        LittleEndian::write_u16(&mut elf_bytes[350 + 46..350 + 48], SHN_UNDEF);

        // Rel 0: offset 0x104, type R_ARM_GLOB_DAT
        LittleEndian::write_u32(&mut elf_bytes[400..404], 0x104);
        LittleEndian::write_u32(&mut elf_bytes[404..408], (2 << 8) | (R_ARM_GLOB_DAT as u32));

        // Dynamic table
        LittleEndian::write_u32(&mut elf_bytes[232..236], DT_REL);
        LittleEndian::write_u32(&mut elf_bytes[236..240], 400);
        LittleEndian::write_u32(&mut elf_bytes[240..244], DT_RELSZ);
        LittleEndian::write_u32(&mut elf_bytes[244..248], 8);
        LittleEndian::write_u32(&mut elf_bytes[248..252], DT_NULL);
        LittleEndian::write_u32(&mut elf_bytes[252..256], 0);

        let mut mem = FlatMemory::new(GuestAddr::new(0x4000_0000), 0x10_000);
        let _lib = ElfLoader::load(
            &elf_bytes,
            GuestAddr::new(0x4000_0000),
            &mut mem,
            &NullResolver, // NullResolver will NOT find optional_extension
        )
        .unwrap();

        // Unresolved weak symbol MUST be safely zeroed out (NULL pointer)
        let resolved_val = mem.read_u32(GuestAddr::new(0x4000_0104)).unwrap();
        assert_eq!(resolved_val, 0);
    }
}
