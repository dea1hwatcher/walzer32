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
}
