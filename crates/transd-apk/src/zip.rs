use std::collections::HashMap;
use byteorder::{ByteOrder, LittleEndian};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ZipError {
    #[error("Invalid ZIP archive: End of Central Directory not found")]
    EocdNotFound,
    #[error("Truncated ZIP data")]
    Truncated,
    #[error("Invalid signature: expected 0x{expected:08x}, got 0x{actual:08x}")]
    InvalidSignature { expected: u32, actual: u32 },
    #[error("Unsupported compression method: {0}")]
    UnsupportedCompression(u16),
    #[error("Decompression failed: {0}")]
    DecompressError(String),
}

/// Metadata and location for a file stored inside a ZIP archive
#[derive(Debug, Clone)]
pub struct ZipEntry {
    pub name: String,
    pub compression_method: u16,
    pub compressed_size: usize,
    pub uncompressed_size: usize,
    pub crc32: u32,
    pub local_header_offset: usize,
}

pub struct ZipArchive<'a> {
    data: &'a [u8],
    pub entries: HashMap<String, ZipEntry>,
}

impl<'a> ZipArchive<'a> {
    pub fn new(data: &'a [u8]) -> Result<Self, ZipError> {
        let mut archive = Self {
            data,
            entries: HashMap::new(),
        };

        archive.parse_central_directory()?;
        Ok(archive)
    }

    fn parse_central_directory(&mut self) -> Result<(), ZipError> {
        if self.data.len() < 22 {
            return Err(ZipError::EocdNotFound);
        }

        // Search backward for End of Central Directory record (signature 0x06054b50)
        let mut eocd_offset = None;
        let search_start = self.data.len().saturating_sub(65536 + 22);
        for i in (search_start..=(self.data.len() - 22)).rev() {
            if LittleEndian::read_u32(&self.data[i..i + 4]) == 0x06054B50 {
                eocd_offset = Some(i);
                break;
            }
        }

        let eocd = match eocd_offset {
            Some(off) => off,
            None => return Err(ZipError::EocdNotFound),
        };

        let total_entries = LittleEndian::read_u16(&self.data[eocd + 10..eocd + 12]) as usize;
        let cd_size = LittleEndian::read_u32(&self.data[eocd + 12..eocd + 16]) as usize;
        let cd_offset = LittleEndian::read_u32(&self.data[eocd + 16..eocd + 20]) as usize;

        if cd_offset + cd_size > self.data.len() {
            return Err(ZipError::Truncated);
        }

        let mut cur = cd_offset;
        for _ in 0..total_entries {
            if cur + 46 > self.data.len() {
                break;
            }

            let sig = LittleEndian::read_u32(&self.data[cur..cur + 4]);
            if sig != 0x02014B50 {
                break;
            }

            let method = LittleEndian::read_u16(&self.data[cur + 10..cur + 12]);
            let crc = LittleEndian::read_u32(&self.data[cur + 16..cur + 20]);
            let comp_size = LittleEndian::read_u32(&self.data[cur + 20..cur + 24]) as usize;
            let uncomp_size = LittleEndian::read_u32(&self.data[cur + 24..cur + 28]) as usize;
            let name_len = LittleEndian::read_u16(&self.data[cur + 28..cur + 30]) as usize;
            let extra_len = LittleEndian::read_u16(&self.data[cur + 30..cur + 32]) as usize;
            let comment_len = LittleEndian::read_u16(&self.data[cur + 32..cur + 34]) as usize;
            let local_header_offset = LittleEndian::read_u32(&self.data[cur + 42..cur + 46]) as usize;

            let name_bytes = &self.data[cur + 46..cur + 46 + name_len];
            let name = String::from_utf8_lossy(name_bytes).to_string();

            self.entries.insert(
                name.clone(),
                ZipEntry {
                    name,
                    compression_method: method,
                    compressed_size: comp_size,
                    uncompressed_size: uncomp_size,
                    crc32: crc,
                    local_header_offset,
                },
            );

            cur += 46 + name_len + extra_len + comment_len;
        }

        Ok(())
    }

    /// Reads and decompresses a file by name from the ZIP archive
    pub fn read_file(&self, name: &str) -> Result<Vec<u8>, ZipError> {
        let entry = self.entries.get(name).ok_or(ZipError::EocdNotFound)?;
        let off = entry.local_header_offset;

        if off + 30 > self.data.len() {
            return Err(ZipError::Truncated);
        }

        let sig = LittleEndian::read_u32(&self.data[off..off + 4]);
        if sig != 0x04034B50 {
            return Err(ZipError::InvalidSignature {
                expected: 0x04034B50,
                actual: sig,
            });
        }

        let name_len = LittleEndian::read_u16(&self.data[off + 26..off + 28]) as usize;
        let extra_len = LittleEndian::read_u16(&self.data[off + 28..off + 30]) as usize;
        let data_start = off + 30 + name_len + extra_len;
        let data_end = data_start + entry.compressed_size;

        if data_end > self.data.len() {
            return Err(ZipError::Truncated);
        }

        let raw_data = &self.data[data_start..data_end];

        match entry.compression_method {
            0 => {
                // Stored (uncompressed)
                Ok(raw_data.to_vec())
            }
            8 => {
                // Deflated
                Self::inflate(raw_data, entry.uncompressed_size)
            }
            other => Err(ZipError::UnsupportedCompression(other)),
        }
    }

    /// Basic RFC 1951 Deflate decompression implementation
    fn inflate(input: &[u8], expected_size: usize) -> Result<Vec<u8>, ZipError> {
        struct BitReader<'i> {
            input: &'i [u8],
            byte_pos: usize,
            bit_buf: u64,
            bit_count: usize,
        }

        impl<'i> BitReader<'i> {
            fn new(input: &'i [u8]) -> Self {
                Self {
                    input,
                    byte_pos: 0,
                    bit_buf: 0,
                    bit_count: 0,
                }
            }

            fn read_bits(&mut self, n: usize) -> Result<u32, ZipError> {
                while self.bit_count < n {
                    if self.byte_pos >= self.input.len() {
                        return Err(ZipError::DecompressError("Unexpected EOF in bitstream".into()));
                    }
                    self.bit_buf |= (self.input[self.byte_pos] as u64) << self.bit_count;
                    self.byte_pos += 1;
                    self.bit_count += 8;
                }
                let val = (self.bit_buf & ((1 << n) - 1)) as u32;
                self.bit_buf >>= n;
                self.bit_count -= n;
                Ok(val)
            }

            fn align_byte(&mut self) {
                self.bit_buf = 0;
                self.bit_count = 0;
            }
        }

        let mut output = Vec::with_capacity(expected_size);
        let mut reader = BitReader::new(input);

        let mut bfinal = false;
        while !bfinal {
            let bfinal_bit = reader.read_bits(1)?;
            bfinal = bfinal_bit != 0;
            let btype = reader.read_bits(2)?;

            match btype {
                0 => {
                    // Non-compressed block: align to byte boundary
                    reader.align_byte();
                    if reader.byte_pos + 4 > reader.input.len() {
                        return Err(ZipError::DecompressError("Truncated uncompressed block".into()));
                    }
                    let len = LittleEndian::read_u16(&reader.input[reader.byte_pos..reader.byte_pos + 2]) as usize;
                    reader.byte_pos += 4; // len + nlen
                    if reader.byte_pos + len > reader.input.len() {
                        return Err(ZipError::DecompressError("Truncated uncompressed data".into()));
                    }
                    output.extend_from_slice(&reader.input[reader.byte_pos..reader.byte_pos + len]);
                    reader.byte_pos += len;
                }
                1 => {
                    // Fixed Huffman block
                    loop {
                        let mut code = 0u32;
                        let mut len = 0;
                        let symbol;
                        loop {
                            let bit = reader.read_bits(1)?;
                            code = (code << 1) | bit;
                            len += 1;
                            if len == 7 && code <= 0x17 {
                                symbol = 256 + code;
                                break;
                            } else if len == 8 && code >= 0x30 && code <= 0xBF {
                                symbol = code - 0x30;
                                break;
                            } else if len == 8 && code >= 0xC0 && code <= 0xC7 {
                                symbol = 280 + (code - 0xC0);
                                break;
                            } else if len == 9 && code >= 0x190 && code <= 0x1FF {
                                symbol = 144 + (code - 0x190);
                                break;
                            }
                            if len > 9 {
                                return Err(ZipError::DecompressError("Invalid fixed Huffman symbol".into()));
                            }
                        }

                        if symbol < 256 {
                            output.push(symbol as u8);
                        } else if symbol == 256 {
                            break; // End of block
                        } else {
                            // Length code (257..285)
                            let (base_len, extra_bits) = match symbol {
                                257..=264 => (symbol - 254, 0),
                                265..=268 => (11 + (symbol - 265) * 2, 1),
                                269..=272 => (19 + (symbol - 269) * 4, 2),
                                273..=276 => (35 + (symbol - 273) * 8, 3),
                                277..=280 => (67 + (symbol - 277) * 16, 4),
                                281..=284 => (131 + (symbol - 281) * 32, 5),
                                285 => (258, 0),
                                _ => return Err(ZipError::DecompressError("Unknown length symbol".into())),
                            };
                            let match_len = base_len + if extra_bits > 0 { reader.read_bits(extra_bits)? } else { 0 };

                            // Distance code: 5 bits fixed
                            let dist_sym = reader.read_bits(5)?;
                            let (base_dist, dist_extra) = match dist_sym {
                                0..=3 => (dist_sym + 1, 0),
                                4..=29 => (1 + (1 << ((dist_sym >> 1) + 1)) + ((dist_sym & 1) << (dist_sym >> 1)), (dist_sym as usize >> 1) - 1),
                                _ => return Err(ZipError::DecompressError("Invalid dist symbol".into())),
                            };
                            let match_dist = base_dist + if dist_extra > 0 { reader.read_bits(dist_extra)? } else { 0 };

                            if (match_dist as usize) > output.len() {
                                return Err(ZipError::DecompressError("Distance past output start".into()));
                            }

                            let start = output.len() - match_dist as usize;
                            for i in 0..match_len as usize {
                                let b = output[start + i];
                                output.push(b);
                            }
                        }
                    }
                }
                _ => {
                    // For dynamic Huffman or other modes, fallback if uncompressed size is 0
                    if output.len() == expected_size {
                        break;
                    }
                    return Err(ZipError::UnsupportedCompression(btype as u16));
                }
            }
        }

        Ok(output)
    }
}
