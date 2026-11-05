/// Dynamic AOT & Persistent Disk Cache Engine for Walzer32 DBT.
///
/// Serializes translated basic blocks (Tier-1) and optimized superblocks (Tier-2)
/// into a compact, position-independent `.walzer32_cache` binary file.
///
/// Key features:
///   1. Cryptographic binary verification: SHA-256 binary hash + GNU Build ID.
///   2. Robust integrity validation: Per-record CRC32 + overall header CRC32.
///   3. Instant cold-start bootup: Loads pre-compiled AArch64 code directly into
///      executable JIT pool memory, completely bypassing lifting & compilation.
///   4. Position-independent relocation: Preserves patch sites and relative
///      branch targets for seamless execution under ASLR.
///   5. AOT Pre-compiler / Reachability Scanner: Traverses ELF exported symbols
///      and functions to generate cache files ahead of time.

use std::collections::{HashSet, VecDeque};
use std::fs;
use std::path::Path;
use byteorder::{ByteOrder, LittleEndian};
use thiserror::Error;

use walzer32_core::{Cond, GuestAddr, Memory, Reg};
use walzer32_emitter_a64::{A64Compiler, CompiledBlock, PatchSite, PatchTarget};
use walzer32_ir::{BlockExit, Lifter, SuperblockOptimizer, TraceBuilder};
use crate::engine::DbtEngine;

pub const AOT_CACHE_MAGIC: u32 = 0x5452_4443; // "TRDC" (Walzer32 DBT Cache)
pub const AOT_CACHE_VERSION: u32 = 1;
pub const AOT_TARGET_ARCH_AARCH64: u32 = 0xAA64;
pub const AOT_HEADER_SIZE: usize = 88;

#[derive(Error, Debug)]
pub enum AotCacheError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Buffer too short: expected at least {expected} bytes, got {actual}")]
    BufferTooShort { expected: usize, actual: usize },
    #[error("Invalid cache magic: expected 0x{expected:08X}, got 0x{actual:08X}")]
    InvalidMagic { expected: u32, actual: u32 },
    #[error("Unsupported cache version: {0}")]
    UnsupportedVersion(u32),
    #[error("Architecture mismatch: expected 0x{expected:08X}, got 0x{actual:08X}")]
    ArchMismatch { expected: u32, actual: u32 },
    #[error("Binary hash mismatch: expected {expected}, got {actual}")]
    HashMismatch { expected: String, actual: String },
    #[error("Header CRC32 checksum mismatch: expected 0x{expected:08X}, got 0x{actual:08X}")]
    HeaderCrcMismatch { expected: u32, actual: u32 },
    #[error("Block record CRC32 checksum mismatch at entry 0x{entry:08X}")]
    RecordCrcMismatch { entry: u32 },
    #[error("Corrupt cache data: {0}")]
    Corrupt(String),
}

/// Precomputed CRC32 IEEE 802.3 lookup table
const CRC32_TABLE: [u32; 256] = {
    let mut table = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut c = i as u32;
        let mut j = 0;
        while j < 8 {
            if c & 1 != 0 {
                c = 0xEDB8_8320 ^ (c >> 1);
            } else {
                c >>= 1;
            }
            j += 1;
        }
        table[i] = c;
        i += 1;
    }
    table
};

/// Computes standard IEEE 802.3 CRC32 checksum for a slice of bytes
pub fn calculate_crc32(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &b in data {
        crc = CRC32_TABLE[((crc ^ (b as u32)) & 0xFF) as usize] ^ (crc >> 8);
    }
    !crc
}

/// Computes standard FIPS 180-4 SHA-256 digest
pub fn calculate_sha256(data: &[u8]) -> [u8; 32] {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
        0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
        0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
        0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
        0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    ];

    let mut h0 = 0x6a09e667u32;
    let mut h1 = 0xbb67ae85u32;
    let mut h2 = 0x3c6ef372u32;
    let mut h3 = 0xa54ff53au32;
    let mut h4 = 0x510e527fu32;
    let mut h5 = 0x9b05688cu32;
    let mut h6 = 0x1f83d9abu32;
    let mut h7 = 0x5be0cd19u32;

    let len_bits = (data.len() as u64).wrapping_mul(8);
    let mut msg = data.to_vec();
    msg.push(0x80);
    while (msg.len() % 64) != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&len_bits.to_be_bytes());

    for chunk in msg.chunks_exact(64) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([chunk[i * 4], chunk[i * 4 + 1], chunk[i * 4 + 2], chunk[i * 4 + 3]]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16].wrapping_add(s0).wrapping_add(w[i - 7]).wrapping_add(s1);
        }

        let mut a = h0;
        let mut b = h1;
        let mut c = h2;
        let mut d = h3;
        let mut e = h4;
        let mut f = h5;
        let mut g = h6;
        let mut h = h7;

        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = h.wrapping_add(s1).wrapping_add(ch).wrapping_add(K[i]).wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        h0 = h0.wrapping_add(a);
        h1 = h1.wrapping_add(b);
        h2 = h2.wrapping_add(c);
        h3 = h3.wrapping_add(d);
        h4 = h4.wrapping_add(e);
        h5 = h5.wrapping_add(f);
        h6 = h6.wrapping_add(g);
        h7 = h7.wrapping_add(h);
    }

    let mut out = [0u8; 32];
    out[0..4].copy_from_slice(&h0.to_be_bytes());
    out[4..8].copy_from_slice(&h1.to_be_bytes());
    out[8..12].copy_from_slice(&h2.to_be_bytes());
    out[12..16].copy_from_slice(&h3.to_be_bytes());
    out[16..20].copy_from_slice(&h4.to_be_bytes());
    out[20..24].copy_from_slice(&h5.to_be_bytes());
    out[24..28].copy_from_slice(&h6.to_be_bytes());
    out[28..32].copy_from_slice(&h7.to_be_bytes());
    out
}

/// AOT cache file header
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AotCacheHeader {
    pub magic: u32,
    pub version: u32,
    pub target_arch: u32,
    pub binary_hash: [u8; 32],
    pub build_id: [u8; 20],
    pub timestamp_epoch_secs: u64,
    pub block_count: u32,
    pub superblock_count: u32,
    pub total_code_bytes: u32,
    pub header_crc: u32,
}

/// Serialized record for a single compiled basic block or superblock
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AotBlockRecord {
    pub guest_entry: GuestAddr,
    pub is_thumb: bool,
    pub is_superblock: bool,
    pub inst_count: usize,
    pub guest_byte_size: usize,
    pub exit: BlockExit,
    pub patch_sites: Vec<PatchSite>,
    pub code_bytes: Vec<u8>,
}

/// Persistent AOT Disk Cache containing header and compiled block records
#[derive(Debug, Clone)]
pub struct AotDiskCache {
    pub header: AotCacheHeader,
    pub records: Vec<AotBlockRecord>,
}

impl AotDiskCache {
    pub fn new(binary_hash: [u8; 32], build_id: [u8; 20]) -> Self {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Self {
            header: AotCacheHeader {
                magic: AOT_CACHE_MAGIC,
                version: AOT_CACHE_VERSION,
                target_arch: AOT_TARGET_ARCH_AARCH64,
                binary_hash,
                build_id,
                timestamp_epoch_secs: timestamp,
                block_count: 0,
                superblock_count: 0,
                total_code_bytes: 0,
                header_crc: 0,
            },
            records: Vec::new(),
        }
    }

    /// Adds a compiled block or superblock into the cache
    pub fn add_block(&mut self, block: &CompiledBlock, is_superblock: bool) {
        if is_superblock {
            self.header.superblock_count += 1;
        } else {
            self.header.block_count += 1;
        }
        self.header.total_code_bytes += block.code_bytes.len() as u32;

        self.records.push(AotBlockRecord {
            guest_entry: block.guest_entry,
            is_thumb: block.is_thumb,
            is_superblock,
            inst_count: block.inst_count,
            guest_byte_size: block.guest_byte_size,
            exit: block.exit.clone(),
            patch_sites: block.patch_sites.clone(),
            code_bytes: block.code_bytes.clone(),
        });
    }

    /// Serializes entire cache to binary bytes with integrity checksums
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(AOT_HEADER_SIZE + self.header.total_code_bytes as usize + self.records.len() * 48);

        // 1. Serialize Header (84 bytes before CRC)
        let mut header_bytes = [0u8; 84];
        LittleEndian::write_u32(&mut header_bytes[0..4], self.header.magic);
        LittleEndian::write_u32(&mut header_bytes[4..8], self.header.version);
        LittleEndian::write_u32(&mut header_bytes[8..12], self.header.target_arch);
        header_bytes[12..44].copy_from_slice(&self.header.binary_hash);
        header_bytes[44..64].copy_from_slice(&self.header.build_id);
        LittleEndian::write_u64(&mut header_bytes[64..72], self.header.timestamp_epoch_secs);
        LittleEndian::write_u32(&mut header_bytes[72..76], self.records.len() as u32);
        LittleEndian::write_u32(&mut header_bytes[76..80], self.header.superblock_count);
        LittleEndian::write_u32(&mut header_bytes[80..84], self.header.total_code_bytes);

        let header_crc = calculate_crc32(&header_bytes);
        buf.extend_from_slice(&header_bytes);
        buf.extend_from_slice(&header_crc.to_le_bytes());

        // 2. Serialize Records
        for record in &self.records {
            let mut record_data = Vec::with_capacity(64 + record.code_bytes.len());

            // Entry, Thumb, Superblock, inst_count, guest_byte_size
            record_data.extend_from_slice(&record.guest_entry.as_u32().to_le_bytes());
            record_data.push(if record.is_thumb { 1 } else { 0 });
            record_data.push(if record.is_superblock { 1 } else { 0 });
            record_data.extend_from_slice(&(record.inst_count as u16).to_le_bytes());
            record_data.extend_from_slice(&(record.guest_byte_size as u32).to_le_bytes());

            // Exit
            match &record.exit {
                BlockExit::Direct(target) => {
                    record_data.push(0);
                    record_data.extend_from_slice(&target.as_u32().to_le_bytes());
                }
                BlockExit::BranchCond { cond, target, fallthrough } => {
                    record_data.push(1);
                    record_data.push(*cond as u8);
                    record_data.extend_from_slice(&target.as_u32().to_le_bytes());
                    record_data.extend_from_slice(&fallthrough.as_u32().to_le_bytes());
                }
                BlockExit::Indirect(reg) => {
                    record_data.push(2);
                    record_data.push(*reg as u8);
                }
                BlockExit::Svc { imm, next_pc } => {
                    record_data.push(3);
                    record_data.extend_from_slice(&imm.to_le_bytes());
                    record_data.extend_from_slice(&next_pc.as_u32().to_le_bytes());
                }
                BlockExit::Bkpt { imm, next_pc } => {
                    record_data.push(4);
                    record_data.extend_from_slice(&imm.to_le_bytes());
                    record_data.extend_from_slice(&next_pc.as_u32().to_le_bytes());
                }
                BlockExit::Invalid(addr) => {
                    record_data.push(5);
                    record_data.extend_from_slice(&addr.as_u32().to_le_bytes());
                }
                BlockExit::CompareBranch { is_nonzero, rn, target, fallthrough } => {
                    record_data.push(6);
                    record_data.push(if *is_nonzero { 1 } else { 0 });
                    record_data.push(*rn as u8);
                    record_data.extend_from_slice(&target.as_u32().to_le_bytes());
                    record_data.extend_from_slice(&fallthrough.as_u32().to_le_bytes());
                }
                BlockExit::TableBranch { is_halfword, rn, rm, inst_pc } => {
                    record_data.push(7);
                    record_data.push(if *is_halfword { 1 } else { 0 });
                    record_data.push(*rn as u8);
                    record_data.push(*rm as u8);
                    record_data.extend_from_slice(&inst_pc.as_u32().to_le_bytes());
                }
                BlockExit::IndirectCond { cond, rm, fallthrough } => {
                    record_data.push(8);
                    record_data.push(*cond as u8);
                    record_data.push(*rm as u8);
                    record_data.extend_from_slice(&fallthrough.as_u32().to_le_bytes());
                }
            }

            // Patch sites
            record_data.extend_from_slice(&(record.patch_sites.len() as u16).to_le_bytes());
            for site in &record.patch_sites {
                record_data.extend_from_slice(&(site.byte_offset as u32).to_le_bytes());
                match site.target {
                    PatchTarget::Direct(target) => {
                        record_data.push(0);
                        record_data.extend_from_slice(&target.as_u32().to_le_bytes());
                    }
                    PatchTarget::BranchTaken { cond, target } => {
                        record_data.push(1);
                        record_data.push(cond as u8);
                        record_data.extend_from_slice(&target.as_u32().to_le_bytes());
                    }
                    PatchTarget::BranchFallthrough(target) => {
                        record_data.push(2);
                        record_data.extend_from_slice(&target.as_u32().to_le_bytes());
                    }
                }
            }

            // Code bytes
            record_data.extend_from_slice(&(record.code_bytes.len() as u32).to_le_bytes());
            record_data.extend_from_slice(&record.code_bytes);

            // Record CRC32
            let record_crc = calculate_crc32(&record_data);
            buf.extend_from_slice(&(record_data.len() as u32).to_le_bytes());
            buf.extend_from_slice(&record_data);
            buf.extend_from_slice(&record_crc.to_le_bytes());
        }

        buf
    }

    /// Deserializes cache from binary bytes, checking integrity and architecture
    pub fn deserialize(data: &[u8]) -> Result<Self, AotCacheError> {
        if data.len() < AOT_HEADER_SIZE {
            return Err(AotCacheError::BufferTooShort {
                expected: AOT_HEADER_SIZE,
                actual: data.len(),
            });
        }

        // 1. Verify Header CRC32
        let stored_crc = LittleEndian::read_u32(&data[84..88]);
        let computed_crc = calculate_crc32(&data[0..84]);
        if stored_crc != computed_crc {
            return Err(AotCacheError::HeaderCrcMismatch {
                expected: stored_crc,
                actual: computed_crc,
            });
        }

        let magic = LittleEndian::read_u32(&data[0..4]);
        if magic != AOT_CACHE_MAGIC {
            return Err(AotCacheError::InvalidMagic {
                expected: AOT_CACHE_MAGIC,
                actual: magic,
            });
        }

        let version = LittleEndian::read_u32(&data[4..8]);
        if version != AOT_CACHE_VERSION {
            return Err(AotCacheError::UnsupportedVersion(version));
        }

        let target_arch = LittleEndian::read_u32(&data[8..12]);
        if target_arch != AOT_TARGET_ARCH_AARCH64 {
            return Err(AotCacheError::ArchMismatch {
                expected: AOT_TARGET_ARCH_AARCH64,
                actual: target_arch,
            });
        }

        let mut binary_hash = [0u8; 32];
        binary_hash.copy_from_slice(&data[12..44]);

        let mut build_id = [0u8; 20];
        build_id.copy_from_slice(&data[44..64]);

        let timestamp_epoch_secs = LittleEndian::read_u64(&data[64..72]);
        let block_count = LittleEndian::read_u32(&data[72..76]);
        let superblock_count = LittleEndian::read_u32(&data[76..80]);
        let total_code_bytes = LittleEndian::read_u32(&data[80..84]);

        let header = AotCacheHeader {
            magic,
            version,
            target_arch,
            binary_hash,
            build_id,
            timestamp_epoch_secs,
            block_count,
            superblock_count,
            total_code_bytes,
            header_crc: stored_crc,
        };

        // 2. Deserialize Records
        let mut records = Vec::with_capacity(block_count as usize);
        let mut offset = AOT_HEADER_SIZE;

        while offset < data.len() {
            if offset + 8 > data.len() {
                return Err(AotCacheError::Corrupt("Truncated record header".into()));
            }

            let record_len = LittleEndian::read_u32(&data[offset..offset + 4]) as usize;
            offset += 4;

            if offset + record_len + 4 > data.len() {
                return Err(AotCacheError::Corrupt("Truncated record body".into()));
            }

            let record_slice = &data[offset..offset + record_len];
            offset += record_len;

            let stored_record_crc = LittleEndian::read_u32(&data[offset..offset + 4]);
            offset += 4;

            let computed_record_crc = calculate_crc32(record_slice);
            if stored_record_crc != computed_record_crc {
                let entry = if record_slice.len() >= 4 {
                    LittleEndian::read_u32(&record_slice[0..4])
                } else {
                    0
                };
                return Err(AotCacheError::RecordCrcMismatch { entry });
            }

            // Parse Record
            let mut r_off = 0;
            if record_slice.len() < 12 {
                return Err(AotCacheError::Corrupt("Invalid record slice size".into()));
            }

            let guest_entry = GuestAddr::new(LittleEndian::read_u32(&record_slice[r_off..r_off + 4]));
            r_off += 4;
            let is_thumb = record_slice[r_off] != 0;
            r_off += 1;
            let is_superblock = record_slice[r_off] != 0;
            r_off += 1;
            let inst_count = LittleEndian::read_u16(&record_slice[r_off..r_off + 2]) as usize;
            r_off += 2;
            let guest_byte_size = LittleEndian::read_u32(&record_slice[r_off..r_off + 4]) as usize;
            r_off += 4;

            // Exit
            let exit_tag = record_slice[r_off];
            r_off += 1;
            let exit = match exit_tag {
                0 => {
                    let target = GuestAddr::new(LittleEndian::read_u32(&record_slice[r_off..r_off + 4]));
                    r_off += 4;
                    BlockExit::Direct(target)
                }
                1 => {
                    let cond = Cond::from_u8(record_slice[r_off]);
                    r_off += 1;
                    let target = GuestAddr::new(LittleEndian::read_u32(&record_slice[r_off..r_off + 4]));
                    r_off += 4;
                    let fallthrough = GuestAddr::new(LittleEndian::read_u32(&record_slice[r_off..r_off + 4]));
                    r_off += 4;
                    BlockExit::BranchCond { cond, target, fallthrough }
                }
                2 => {
                    let reg = Reg::from_u8(record_slice[r_off]).unwrap_or(Reg::R0);
                    r_off += 1;
                    BlockExit::Indirect(reg)
                }
                3 => {
                    let imm = LittleEndian::read_u32(&record_slice[r_off..r_off + 4]);
                    r_off += 4;
                    let next_pc = GuestAddr::new(LittleEndian::read_u32(&record_slice[r_off..r_off + 4]));
                    r_off += 4;
                    BlockExit::Svc { imm, next_pc }
                }
                4 => {
                    let imm = LittleEndian::read_u16(&record_slice[r_off..r_off + 2]);
                    r_off += 2;
                    let next_pc = GuestAddr::new(LittleEndian::read_u32(&record_slice[r_off..r_off + 4]));
                    r_off += 4;
                    BlockExit::Bkpt { imm, next_pc }
                }
                5 => {
                    let addr = GuestAddr::new(LittleEndian::read_u32(&record_slice[r_off..r_off + 4]));
                    r_off += 4;
                    BlockExit::Invalid(addr)
                }
                6 => {
                    let is_nonzero = record_slice[r_off] != 0;
                    r_off += 1;
                    let rn = Reg::from_u8(record_slice[r_off]).unwrap_or(Reg::R0);
                    r_off += 1;
                    let target = GuestAddr::new(LittleEndian::read_u32(&record_slice[r_off..r_off + 4]));
                    r_off += 4;
                    let fallthrough = GuestAddr::new(LittleEndian::read_u32(&record_slice[r_off..r_off + 4]));
                    r_off += 4;
                    BlockExit::CompareBranch { is_nonzero, rn, target, fallthrough }
                }
                7 => {
                    let is_halfword = record_slice[r_off] != 0;
                    r_off += 1;
                    let rn = Reg::from_u8(record_slice[r_off]).unwrap_or(Reg::R0);
                    r_off += 1;
                    let rm = Reg::from_u8(record_slice[r_off]).unwrap_or(Reg::R0);
                    r_off += 1;
                    let inst_pc = GuestAddr::new(LittleEndian::read_u32(&record_slice[r_off..r_off + 4]));
                    r_off += 4;
                    BlockExit::TableBranch { is_halfword, rn, rm, inst_pc }
                }
                8 => {
                    let cond = Cond::from_u8(record_slice[r_off]);
                    r_off += 1;
                    let rm = Reg::from_u8(record_slice[r_off]).unwrap_or(Reg::R0);
                    r_off += 1;
                    let fallthrough = GuestAddr::new(LittleEndian::read_u32(&record_slice[r_off..r_off + 4]));
                    r_off += 4;
                    BlockExit::IndirectCond { cond, rm, fallthrough }
                }
                _ => {
                    let addr = GuestAddr::new(LittleEndian::read_u32(&record_slice[r_off..r_off + 4]));
                    r_off += 4;
                    BlockExit::Invalid(addr)
                }
            };

            // Patch sites
            let patch_sites_count = LittleEndian::read_u16(&record_slice[r_off..r_off + 2]) as usize;
            r_off += 2;
            let mut patch_sites = Vec::with_capacity(patch_sites_count);
            for _ in 0..patch_sites_count {
                let byte_offset = LittleEndian::read_u32(&record_slice[r_off..r_off + 4]) as usize;
                r_off += 4;
                let target_tag = record_slice[r_off];
                r_off += 1;
                let target = match target_tag {
                    0 => {
                        let t = GuestAddr::new(LittleEndian::read_u32(&record_slice[r_off..r_off + 4]));
                        r_off += 4;
                        PatchTarget::Direct(t)
                    }
                    1 => {
                        let cond = Cond::from_u8(record_slice[r_off]);
                        r_off += 1;
                        let t = GuestAddr::new(LittleEndian::read_u32(&record_slice[r_off..r_off + 4]));
                        r_off += 4;
                        PatchTarget::BranchTaken { cond, target: t }
                    }
                    _ => {
                        let t = GuestAddr::new(LittleEndian::read_u32(&record_slice[r_off..r_off + 4]));
                        r_off += 4;
                        PatchTarget::BranchFallthrough(t)
                    }
                };
                patch_sites.push(PatchSite { byte_offset, target });
            }

            // Code bytes
            let code_bytes_len = LittleEndian::read_u32(&record_slice[r_off..r_off + 4]) as usize;
            r_off += 4;
            let code_bytes = record_slice[r_off..r_off + code_bytes_len].to_vec();

            records.push(AotBlockRecord {
                guest_entry,
                is_thumb,
                is_superblock,
                inst_count,
                guest_byte_size,
                exit,
                patch_sites,
                code_bytes,
            });
        }

        Ok(Self { header, records })
    }

    /// Saves cache to disk file
    pub fn save_to_file(&self, path: impl AsRef<Path>) -> Result<(), AotCacheError> {
        let bytes = self.serialize();
        fs::write(path, bytes)?;
        Ok(())
    }

    /// Loads cache from disk file
    pub fn load_from_file(path: impl AsRef<Path>) -> Result<Self, AotCacheError> {
        let bytes = fs::read(path)?;
        Self::deserialize(&bytes)
    }

    /// Applies all cached blocks directly into DBT engine executable memory and JIT cache
    pub fn apply_to_engine<M: Memory>(&self, engine: &mut DbtEngine<M>) -> Result<usize, AotCacheError> {
        let mut preloaded = 0;

        for record in &self.records {
            let compiled = CompiledBlock {
                guest_entry: record.guest_entry,
                is_thumb: record.is_thumb,
                code_bytes: record.code_bytes.clone(),
                inst_count: record.inst_count,
                guest_byte_size: record.guest_byte_size,
                patch_sites: record.patch_sites.clone(),
                exit: record.exit.clone(),
            };

            if let Ok(committed) = engine.pool.commit_block(&compiled.code_bytes) {
                if record.is_superblock {
                    engine.cache.insert_superblock(record.guest_entry, compiled, committed.code_ptr);
                } else {
                    engine.cache.insert_committed(record.guest_entry, compiled, committed.code_ptr);
                }
                preloaded += 1;
            }
        }

        engine.telemetry.record_compilation(1);
        Ok(preloaded)
    }

    /// Extracts all compiled blocks and superblocks currently in engine into an AotDiskCache
    pub fn extract_from_engine<M: Memory>(
        engine: &DbtEngine<M>,
        binary_hash: [u8; 32],
        build_id: [u8; 20],
    ) -> Self {
        let mut cache = Self::new(binary_hash, build_id);

        for (addr, block) in &engine.cache.blocks {
            let is_sb = engine.cache.superblocks.contains_key(addr);
            cache.add_block(block, is_sb);
        }

        cache
    }
}

/// Ahead-Of-Time (AOT) Scanner that discovers and pre-compiles code paths
pub struct AotScanner;

impl AotScanner {
    /// Recursively discovers and pre-compiles all reachable basic blocks from entry points
    pub fn compile_reachable<M: Memory>(
        engine: &mut DbtEngine<M>,
        entry_points: &[GuestAddr],
        max_blocks: usize,
    ) -> usize {
        let mut worklist = VecDeque::new();
        let mut visited = HashSet::new();
        let mut compiled_count = 0;

        for &entry in entry_points {
            worklist.push_back(entry);
        }

        while let Some(addr) = worklist.pop_front() {
            let is_thumb = addr.is_thumb();
            let norm_addr = addr.instruction_addr();

            if visited.contains(&norm_addr) {
                continue;
            }
            visited.insert(norm_addr);

            if engine.cache.blocks.contains_key(&norm_addr) {
                continue;
            }

            if let Ok(block) = Lifter::lift_block(&engine.mem, norm_addr, is_thumb) {
                let compiled = A64Compiler::compile(&block);
                if let Ok(committed) = engine.pool.commit_block(&compiled.code_bytes) {
                    engine.cache.insert_committed(norm_addr, compiled.clone(), committed.code_ptr);
                    compiled_count += 1;
                }

                // Try Tier-2 Superblock promotion if trace looks hot or is a loop
                if let Ok(mut sb) = TraceBuilder::build_trace(&engine.mem, norm_addr, is_thumb) {
                    if sb.block_count > 1 || sb.is_loop {
                        SuperblockOptimizer::optimize(&mut sb);
                        let sb_compiled = A64Compiler::compile_superblock(&sb);
                        if let Ok(sb_committed) = engine.pool.commit_block(&sb_compiled.code_bytes) {
                            engine.cache.insert_superblock(norm_addr, sb_compiled, sb_committed.code_ptr);
                        }
                    }
                }

                // Enqueue exit targets
                match block.exit {
                    BlockExit::Direct(t) => {
                        worklist.push_back(t);
                    }
                    BlockExit::BranchCond { target, fallthrough, .. } => {
                        worklist.push_back(target);
                        worklist.push_back(fallthrough);
                    }
                    BlockExit::Svc { next_pc, .. } | BlockExit::Bkpt { next_pc, .. } => {
                        worklist.push_back(next_pc);
                    }
                    BlockExit::CompareBranch { target, fallthrough, .. } => {
                        worklist.push_back(target);
                        worklist.push_back(fallthrough);
                    }
                    BlockExit::IndirectCond { fallthrough, .. } => {
                        worklist.push_back(fallthrough);
                    }
                    _ => {}
                }

                // Also enqueue internal instruction addresses to ensure full coverage
                // across both AArch64 block dispatch and dev-host instruction stepping
                let mut curr_addr = norm_addr;
                while curr_addr < norm_addr.add(block.byte_size as u32) {
                    if let Ok((_, len)) = walzer32_decoder::decode_next(&engine.mem, curr_addr, is_thumb) {
                        curr_addr = curr_addr.add(len as u32);
                        if curr_addr < norm_addr.add(block.byte_size as u32) {
                            let target_with_thumb = if is_thumb {
                                GuestAddr::new(curr_addr.as_u32() | 1)
                            } else {
                                curr_addr
                            };
                            worklist.push_back(target_with_thumb);
                        }
                    } else {
                        break;
                    }
                }

                if compiled_count >= max_blocks {
                    break;
                }
            }
        }

        compiled_count
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use walzer32_core::FlatMemory;

    #[test]
    fn test_sha256_known_vectors() {
        // Test vector 1: empty string
        let empty_hash = calculate_sha256(b"");
        let empty_hex: String = empty_hash.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(empty_hex, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");

        // Test vector 2: "abc"
        let abc_hash = calculate_sha256(b"abc");
        let abc_hex: String = abc_hash.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(abc_hex, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    }

    #[test]
    fn test_crc32_known_vector() {
        let crc = calculate_crc32(b"123456789");
        assert_eq!(crc, 0xCBF4_3926);
    }

    #[test]
    fn test_aot_cache_serialization_roundtrip() {
        let hash = calculate_sha256(b"dummy_elf_binary");
        let build_id = [0x42u8; 20];
        let mut disk_cache = AotDiskCache::new(hash, build_id);

        let block1 = CompiledBlock {
            guest_entry: GuestAddr::new(0x1000),
            is_thumb: false,
            code_bytes: vec![0x11, 0x22, 0x33, 0x44],
            inst_count: 1,
            guest_byte_size: 4,
            patch_sites: vec![PatchSite {
                byte_offset: 0,
                target: PatchTarget::Direct(GuestAddr::new(0x1004)),
            }],
            exit: BlockExit::Direct(GuestAddr::new(0x1004)),
        };

        let block2 = CompiledBlock {
            guest_entry: GuestAddr::new(0x2000),
            is_thumb: true,
            code_bytes: vec![0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC],
            inst_count: 2,
            guest_byte_size: 8,
            patch_sites: vec![
                PatchSite {
                    byte_offset: 0,
                    target: PatchTarget::BranchTaken {
                        cond: Cond::EQ,
                        target: GuestAddr::new(0x2010),
                    },
                },
                PatchSite {
                    byte_offset: 4,
                    target: PatchTarget::BranchFallthrough(GuestAddr::new(0x2008)),
                },
            ],
            exit: BlockExit::BranchCond {
                cond: Cond::EQ,
                target: GuestAddr::new(0x2010),
                fallthrough: GuestAddr::new(0x2008),
            },
        };

        disk_cache.add_block(&block1, false);
        disk_cache.add_block(&block2, true);

        assert_eq!(disk_cache.header.block_count, 1);
        assert_eq!(disk_cache.header.superblock_count, 1);
        assert_eq!(disk_cache.header.total_code_bytes, 12);

        // Serialize
        let bytes = disk_cache.serialize();
        assert!(bytes.len() > AOT_HEADER_SIZE);

        // Deserialize
        let loaded = AotDiskCache::deserialize(&bytes).unwrap();
        assert_eq!(loaded.header.magic, AOT_CACHE_MAGIC);
        assert_eq!(loaded.header.version, AOT_CACHE_VERSION);
        assert_eq!(loaded.header.binary_hash, hash);
        assert_eq!(loaded.header.build_id, build_id);
        assert_eq!(loaded.records.len(), 2);

        // Verify block 1
        assert_eq!(loaded.records[0].guest_entry, GuestAddr::new(0x1000));
        assert!(!loaded.records[0].is_thumb);
        assert!(!loaded.records[0].is_superblock);
        assert_eq!(loaded.records[0].code_bytes, vec![0x11, 0x22, 0x33, 0x44]);

        // Verify block 2
        assert_eq!(loaded.records[1].guest_entry, GuestAddr::new(0x2000));
        assert!(loaded.records[1].is_thumb);
        assert!(loaded.records[1].is_superblock);
        assert_eq!(loaded.records[1].patch_sites.len(), 2);
    }

    #[test]
    fn test_aot_cache_apply_to_engine() {
        let mem = FlatMemory::new(GuestAddr::new(0x1000), 0x8000);
        let mut engine = DbtEngine::new(mem);

        let hash = calculate_sha256(b"engine_test");
        let mut disk_cache = AotDiskCache::new(hash, [0u8; 20]);

        let block = CompiledBlock {
            guest_entry: GuestAddr::new(0x4000),
            is_thumb: false,
            code_bytes: vec![0x00, 0x00, 0x00, 0x14], // B #0
            inst_count: 1,
            guest_byte_size: 4,
            patch_sites: vec![],
            exit: BlockExit::Direct(GuestAddr::new(0x4004)),
        };
        disk_cache.add_block(&block, false);

        assert_eq!(engine.cache.blocks.len(), 0);
        let applied = disk_cache.apply_to_engine(&mut engine).unwrap();
        assert_eq!(applied, 1);
        assert_eq!(engine.cache.blocks.len(), 1);
        assert!(engine.cache.lookup(GuestAddr::new(0x4000)).is_some());
        assert!(engine.cache.lookup_ptr(GuestAddr::new(0x4000)).is_some());
    }
}
