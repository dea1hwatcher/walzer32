use byteorder::{ByteOrder, LittleEndian};
use thiserror::Error;

use crate::header::*;

#[derive(Error, Debug)]
pub enum ElfError {
    #[error("File is too small to contain ELF header (length: {0})")]
    TooSmall(usize),
    #[error("Invalid ELF magic: {0:?}")]
    InvalidMagic([u8; 4]),
    #[error("Unsupported ELF class (expected 32-bit, got {0})")]
    UnsupportedClass(u8),
    #[error("Unsupported ELF endianness (expected Little-Endian, got {0})")]
    UnsupportedEndian(u8),
    #[error("Unsupported machine architecture (expected ARM, got {0})")]
    UnsupportedMachine(u16),
    #[error("Out of bounds read at offset {offset} (size {size}) in file of len {len}")]
    OutOfBounds {
        offset: usize,
        size: usize,
        len: usize,
    },
    #[error("Missing or malformed dynamic section: {0}")]
    MalformedDynamic(String),
}

pub struct ElfParser<'a> {
    data: &'a [u8],
    pub header: Elf32Ehdr,
    pub program_headers: Vec<Elf32Phdr>,
}

impl<'a> ElfParser<'a> {
    pub fn parse(data: &'a [u8]) -> Result<Self, ElfError> {
        if data.len() < 52 {
            return Err(ElfError::TooSmall(data.len()));
        }

        // 1. Validate Ident
        let magic = [data[0], data[1], data[2], data[3]];
        if magic != ELF_MAGIC {
            return Err(ElfError::InvalidMagic(magic));
        }

        if data[4] != ELFCLASS32 {
            return Err(ElfError::UnsupportedClass(data[4]));
        }

        if data[5] != ELFDATA2LSB {
            return Err(ElfError::UnsupportedEndian(data[5]));
        }

        let e_type = LittleEndian::read_u16(&data[16..18]);
        let e_machine = LittleEndian::read_u16(&data[18..20]);
        if e_machine != EM_ARM {
            return Err(ElfError::UnsupportedMachine(e_machine));
        }

        let header = Elf32Ehdr {
            e_type,
            e_machine,
            e_version: LittleEndian::read_u32(&data[20..24]),
            e_entry: LittleEndian::read_u32(&data[24..28]),
            e_phoff: LittleEndian::read_u32(&data[28..32]),
            e_shoff: LittleEndian::read_u32(&data[32..36]),
            e_flags: LittleEndian::read_u32(&data[36..40]),
            e_ehsize: LittleEndian::read_u16(&data[40..42]),
            e_phentsize: LittleEndian::read_u16(&data[42..44]),
            e_phnum: LittleEndian::read_u16(&data[44..46]),
            e_shentsize: LittleEndian::read_u16(&data[46..48]),
            e_shnum: LittleEndian::read_u16(&data[48..50]),
            e_shstrndx: LittleEndian::read_u16(&data[50..52]),
        };

        // 2. Parse Program Headers
        let mut program_headers = Vec::with_capacity(header.e_phnum as usize);
        let ph_start = header.e_phoff as usize;
        let ph_entry_size = header.e_phentsize as usize;

        for i in 0..header.e_phnum as usize {
            let off = ph_start + i * ph_entry_size;
            if off + 32 > data.len() {
                return Err(ElfError::OutOfBounds {
                    offset: off,
                    size: 32,
                    len: data.len(),
                });
            }

            let phdr = Elf32Phdr {
                p_type: LittleEndian::read_u32(&data[off..off + 4]),
                p_offset: LittleEndian::read_u32(&data[off + 4..off + 8]),
                p_vaddr: LittleEndian::read_u32(&data[off + 8..off + 12]),
                p_paddr: LittleEndian::read_u32(&data[off + 12..off + 16]),
                p_filesz: LittleEndian::read_u32(&data[off + 16..off + 20]),
                p_memsz: LittleEndian::read_u32(&data[off + 20..off + 24]),
                p_flags: LittleEndian::read_u32(&data[off + 24..off + 28]),
                p_align: LittleEndian::read_u32(&data[off + 28..off + 32]),
            };
            program_headers.push(phdr);
        }

        Ok(Self {
            data,
            header,
            program_headers,
        })
    }

    /// Finds PT_LOAD segments
    pub fn load_segments(&self) -> impl Iterator<Item = &Elf32Phdr> {
        self.program_headers
            .iter()
            .filter(|ph| ph.p_type == PT_LOAD)
    }

    /// Finds PT_DYNAMIC segment
    pub fn dynamic_segment(&self) -> Option<&Elf32Phdr> {
        self.program_headers
            .iter()
            .find(|ph| ph.p_type == PT_DYNAMIC)
    }

    /// Reads raw file slice for a given program header
    pub fn segment_bytes(&self, ph: &Elf32Phdr) -> Result<&'a [u8], ElfError> {
        let off = ph.p_offset as usize;
        let sz = ph.p_filesz as usize;
        if off + sz <= self.data.len() {
            Ok(&self.data[off..off + sz])
        } else {
            Err(ElfError::OutOfBounds {
                offset: off,
                size: sz,
                len: self.data.len(),
            })
        }
    }

    /// Parses the dynamic table entries (Elf32Dyn)
    pub fn parse_dynamic_table(&self) -> Result<Vec<Elf32Dyn>, ElfError> {
        let dyn_ph = match self.dynamic_segment() {
            Some(ph) => ph,
            None => return Ok(Vec::new()),
        };

        let bytes = self.segment_bytes(dyn_ph)?;
        let count = bytes.len() / 8;
        let mut entries = Vec::with_capacity(count);

        for i in 0..count {
            let off = i * 8;
            let d_tag = LittleEndian::read_u32(&bytes[off..off + 4]);
            let d_val = LittleEndian::read_u32(&bytes[off + 4..off + 8]);
            entries.push(Elf32Dyn { d_tag, d_val });
            if d_tag == DT_NULL {
                break;
            }
        }

        Ok(entries)
    }

    /// Translates a virtual address (as declared in the ELF) to a file offset
    pub fn vaddr_to_offset(&self, vaddr: u32) -> Option<usize> {
        for ph in self.load_segments() {
            if vaddr >= ph.p_vaddr && vaddr < ph.p_vaddr + ph.p_filesz {
                return Some((ph.p_offset + (vaddr - ph.p_vaddr)) as usize);
            }
        }
        None
    }

    /// Reads a null-terminated string at a given file offset
    pub fn read_string_at(&self, offset: usize) -> Result<&'a str, ElfError> {
        if offset >= self.data.len() {
            return Err(ElfError::OutOfBounds {
                offset,
                size: 1,
                len: self.data.len(),
            });
        }

        let slice = &self.data[offset..];
        let null_pos = slice
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(slice.len());

        std::str::from_utf8(&slice[..null_pos])
            .map_err(|_| ElfError::MalformedDynamic("Invalid UTF-8 in string table".into()))
    }

    /// Extracts exported dynamic symbol names
    pub fn dynamic_symbol_names(&self) -> Vec<String> {
        let mut names = Vec::new();
        let dyn_entries = match self.parse_dynamic_table() {
            Ok(e) => e,
            Err(_) => return names,
        };

        let mut symtab_vaddr = None;
        let mut strtab_vaddr = None;
        let mut syment = 16usize;

        for d in &dyn_entries {
            match d.d_tag {
                DT_SYMTAB => symtab_vaddr = Some(d.d_val),
                DT_STRTAB => strtab_vaddr = Some(d.d_val),
                DT_SYMENT => syment = d.d_val as usize,
                _ => {}
            }
        }

        if let (Some(sym_va), Some(str_va)) = (symtab_vaddr, strtab_vaddr)
            && let (Some(sym_off), Some(str_off)) = (self.vaddr_to_offset(sym_va), self.vaddr_to_offset(str_va))
        {
            for i in 1..4096 {
                let off = sym_off + i * syment;
                if off + syment > self.data.len() {
                    break;
                }
                let st_name = LittleEndian::read_u32(&self.data[off..off + 4]) as usize;
                let st_value = LittleEndian::read_u32(&self.data[off + 4..off + 8]);
                let st_shndx = LittleEndian::read_u16(&self.data[off + 14..off + 16]);
                if st_name == 0 && st_value == 0 {
                    break;
                }
                if st_shndx != SHN_UNDEF
                    && let Ok(name) = self.read_string_at(str_off + st_name)
                    && !name.is_empty()
                {
                    names.push(name.to_string());
                }
            }
        }
        names
    }

    /// Checks if a given dynamic symbol exists in the ELF
    pub fn find_dynamic_symbol(&self, name: &str) -> Option<String> {
        self.dynamic_symbol_names().into_iter().find(|n| n == name)
    }

    /// Extracts `DT_NEEDED` shared library dependency names from the ELF dynamic section.
    pub fn needed_libraries(&self) -> Vec<String> {
        let mut needed = Vec::new();
        let dyn_entries = match self.parse_dynamic_table() {
            Ok(e) => e,
            Err(_) => return needed,
        };

        let mut strtab_vaddr = None;
        let mut needed_offsets = Vec::new();
        for d in &dyn_entries {
            match d.d_tag {
                DT_STRTAB => strtab_vaddr = Some(d.d_val),
                DT_NEEDED => needed_offsets.push(d.d_val as usize),
                _ => {}
            }
        }

        if let Some(str_va) = strtab_vaddr
            && let Some(str_off) = self.vaddr_to_offset(str_va)
        {
            for off in needed_offsets {
                if let Ok(name) = self.read_string_at(str_off + off)
                    && !name.is_empty()
                {
                    needed.push(name.to_string());
                }
            }
        }
        needed
    }
}

/// Topologically orders libraries (dependencies/leaves first, roots/dependents last)
/// using their `DT_NEEDED` edges, breaking cycles cleanly and keeping `primary` last.
pub fn topological_sort_libs<F>(names: &[String], get_needed: F, primary: Option<&str>) -> Vec<usize>
where
    F: Fn(usize) -> Vec<String>,
{
    let n = names.len();
    if n == 0 {
        return Vec::new();
    }

    let basenames: Vec<&str> = names
        .iter()
        .map(|s| s.rsplit('/').next().unwrap_or(s.as_str()))
        .collect();
    let mut name_to_idx = std::collections::HashMap::with_capacity(n);
    for (idx, base) in basenames.iter().enumerate() {
        name_to_idx.entry(*base).or_insert(idx);
    }

    // deps[i] = set of internal library indices that library i depends on
    let mut deps: Vec<Vec<usize>> = vec![Vec::new(); n];
    let mut dependents: Vec<Vec<usize>> = vec![Vec::new(); n];
    let mut in_degree: Vec<usize> = vec![0; n];

    for i in 0..n {
        for dep_name in get_needed(i) {
            let dep_base = dep_name.rsplit('/').next().unwrap_or(dep_name.as_str());
            if let Some(&dep_idx) = name_to_idx.get(dep_base) {
                if dep_idx != i && !deps[i].contains(&dep_idx) {
                    deps[i].push(dep_idx);
                    dependents[dep_idx].push(i);
                    in_degree[i] += 1;
                }
            }
        }
    }

    let priority_key = |idx: usize| -> (u8, &str) {
        let b = basenames[idx];
        let tier = if primary == Some(b) {
            3
        } else if b.contains("c++_shared") || b.contains("gnustl") {
            0
        } else {
            1
        };
        (tier, b)
    };

    let mut placed = vec![false; n];
    let mut order = Vec::with_capacity(n);

    while order.len() < n {
        // Pick an unplaced node with minimum unmet dependencies (0 for acyclic leaves),
        // breaking ties with priority_key so C++ runtimes load early and `primary` last.
        let best = (0..n)
            .filter(|&i| !placed[i])
            .min_by_key(|&i| (in_degree[i], priority_key(i)));

        let Some(chosen) = best else {
            break;
        };
        placed[chosen] = true;
        order.push(chosen);
        for &child in &dependents[chosen] {
            if !placed[child] && in_degree[child] > 0 {
                in_degree[child] -= 1;
            }
        }
    }

    order
}
