pub const ELF_MAGIC: [u8; 4] = [0x7F, b'E', b'L', b'F'];
pub const ELFCLASS32: u8 = 1;
pub const ELFDATA2LSB: u8 = 1;
pub const EV_CURRENT: u8 = 1;

pub const ET_EXEC: u16 = 2;
pub const ET_DYN: u16 = 3;

pub const EM_ARM: u16 = 40;

// Program header types (p_type)
pub const PT_NULL: u32 = 0;
pub const PT_LOAD: u32 = 1;
pub const PT_DYNAMIC: u32 = 2;
pub const PT_INTERP: u32 = 3;
pub const PT_NOTE: u32 = 4;
pub const PT_SHLIB: u32 = 5;
pub const PT_PHDR: u32 = 6;
pub const PT_TLS: u32 = 7;
pub const PT_GNU_RELRO: u32 = 0x6474_e552;
pub const PT_ARM_EXIDX: u32 = 0x7000_0001;

// Program header flags (p_flags)
pub const PF_X: u32 = 1;
pub const PF_W: u32 = 2;
pub const PF_R: u32 = 4;

// Dynamic array tags (d_tag)
pub const DT_NULL: u32 = 0;
pub const DT_NEEDED: u32 = 1;
pub const DT_PLTRELSZ: u32 = 2;
pub const DT_PLTGOT: u32 = 3;
pub const DT_HASH: u32 = 4;
pub const DT_STRTAB: u32 = 5;
pub const DT_SYMTAB: u32 = 6;
pub const DT_RELA: u32 = 7;
pub const DT_RELASZ: u32 = 8;
pub const DT_RELAENT: u32 = 9;
pub const DT_STRSZ: u32 = 10;
pub const DT_SYMENT: u32 = 11;
pub const DT_INIT: u32 = 12;
pub const DT_FINI: u32 = 13;
pub const DT_SONAME: u32 = 14;
pub const DT_REL: u32 = 17;
pub const DT_RELSZ: u32 = 18;
pub const DT_RELENT: u32 = 19;
pub const DT_PLTREL: u32 = 20;
pub const DT_JMPREL: u32 = 23;
pub const DT_INIT_ARRAY: u32 = 25;
pub const DT_INIT_ARRAYSZ: u32 = 26;
pub const DT_FINI_ARRAY: u32 = 27;
pub const DT_FINI_ARRAYSZ: u32 = 28;
pub const DT_GNU_HASH: u32 = 0x6fff_fef5;
pub const DT_VERSYM: u32 = 0x6fff_fff0;
pub const DT_VERDEF: u32 = 0x6fff_fffc;
pub const DT_VERDEFNUM: u32 = 0x6fff_fffd;
pub const DT_VERNEED: u32 = 0x6fff_fffe;
pub const DT_VERNEEDNUM: u32 = 0x6fff_ffff;

// GNU Versym flags & values
pub const VERSYM_HIDDEN: u16 = 0x8000;
pub const VERSYM_VERSION: u16 = 0x7fff;
pub const VER_NDX_LOCAL: u16 = 0;
pub const VER_NDX_GLOBAL: u16 = 1;

// RTLD constants
pub const RTLD_DEFAULT: u32 = 0;
pub const RTLD_NEXT: u32 = 0xFFFF_FFFE;

// ARM32 Relocation types
pub const R_ARM_NONE: u8 = 0;
pub const R_ARM_PC24: u8 = 1;
pub const R_ARM_ABS32: u8 = 2;
pub const R_ARM_REL32: u8 = 3;
pub const R_ARM_TLS_DTPMOD32: u8 = 17;
pub const R_ARM_TLS_DTPOFF32: u8 = 18;
pub const R_ARM_TLS_TPOFF32: u8 = 19;
pub const R_ARM_GLOB_DAT: u8 = 21;
pub const R_ARM_JUMP_SLOT: u8 = 22;
pub const R_ARM_RELATIVE: u8 = 23;
pub const R_ARM_TLS_GD32: u8 = 104;
pub const R_ARM_TLS_LDM32: u8 = 105;
pub const R_ARM_TLS_LDO32: u8 = 106;
pub const R_ARM_TLS_IE32: u8 = 107;
pub const R_ARM_TLS_LE32: u8 = 108;

// Symbol types & bindings
pub const STB_LOCAL: u8 = 0;
pub const STB_GLOBAL: u8 = 1;
pub const STB_WEAK: u8 = 2;

pub const STT_NOTYPE: u8 = 0;
pub const STT_OBJECT: u8 = 1;
pub const STT_FUNC: u8 = 2;
pub const STT_SECTION: u8 = 3;
pub const STT_FILE: u8 = 4;

pub const SHN_UNDEF: u16 = 0;

#[derive(Debug, Clone, Copy)]
pub struct Elf32Ehdr {
    pub e_type: u16,
    pub e_machine: u16,
    pub e_version: u32,
    pub e_entry: u32,
    pub e_phoff: u32,
    pub e_shoff: u32,
    pub e_flags: u32,
    pub e_ehsize: u16,
    pub e_phentsize: u16,
    pub e_phnum: u16,
    pub e_shentsize: u16,
    pub e_shnum: u16,
    pub e_shstrndx: u16,
}

#[derive(Debug, Clone, Copy)]
pub struct Elf32Phdr {
    pub p_type: u32,
    pub p_offset: u32,
    pub p_vaddr: u32,
    pub p_paddr: u32,
    pub p_filesz: u32,
    pub p_memsz: u32,
    pub p_flags: u32,
    pub p_align: u32,
}

#[derive(Debug, Clone, Copy)]
pub struct Elf32Dyn {
    pub d_tag: u32,
    pub d_val: u32,
}

#[derive(Debug, Clone, Copy)]
pub struct Elf32Rel {
    pub r_offset: u32,
    pub r_info: u32,
}

impl Elf32Rel {
    #[inline(always)]
    pub fn r_sym(&self) -> u32 {
        self.r_info >> 8
    }

    #[inline(always)]
    pub fn r_type(&self) -> u8 {
        (self.r_info & 0xFF) as u8
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Elf32Sym {
    pub st_name: u32,
    pub st_value: u32,
    pub st_size: u32,
    pub st_info: u8,
    pub st_other: u8,
    pub st_shndx: u16,
}

impl Elf32Sym {
    #[inline(always)]
    pub fn st_bind(&self) -> u8 {
        self.st_info >> 4
    }

    #[inline(always)]
    pub fn st_type(&self) -> u8 {
        self.st_info & 0xF
    }

    #[inline(always)]
    pub fn is_thumb_func(&self) -> bool {
        self.st_type() == STT_FUNC && (self.st_value & 1) != 0
    }
}
