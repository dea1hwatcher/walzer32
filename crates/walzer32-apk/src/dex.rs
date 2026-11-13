use byteorder::{ByteOrder, LittleEndian};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum DexError {
    #[error("Invalid DEX magic header: {0:?}")]
    InvalidMagic(Vec<u8>),
    #[error("Truncated DEX file at offset {0}")]
    Truncated(usize),
    #[error("Invalid ULEB128 encoding")]
    InvalidUleb128,
}

pub const ACC_PUBLIC: u32 = 0x0001;
pub const ACC_PRIVATE: u32 = 0x0002;
pub const ACC_STATIC: u32 = 0x0008;
pub const ACC_FINAL: u32 = 0x0010;
pub const ACC_NATIVE: u32 = 0x0100;

/// Information about a native method declared in DEX bytecode
#[derive(Debug, Clone)]
pub struct DexNativeMethod {
    pub class_name: String,
    pub method_name: String,
    pub return_type: String,
    pub is_static: bool,
    /// JNI standard mangled C function symbol name (e.g. Java_com_example_MainActivity_nativeInit)
    pub jni_symbol: String,
}

/// Parsed Dalvik Executable (classes.dex)
#[derive(Debug, Clone)]
pub struct DexFile {
    pub classes: Vec<String>,
    pub native_methods: Vec<DexNativeMethod>,
}

pub struct DexParser<'a> {
    data: &'a [u8],
    strings: Vec<String>,
    types: Vec<String>,
    methods: Vec<(usize, usize, usize)>, // (class_idx, proto_idx, name_idx)
}

impl<'a> DexParser<'a> {
    pub fn parse(data: &'a [u8]) -> Result<DexFile, DexError> {
        if data.len() < 112 {
            return Err(DexError::Truncated(0));
        }

        // 1. Verify Magic
        let magic = &data[0..8];
        if &magic[0..4] != b"dex\n" || magic[7] != 0 {
            return Err(DexError::InvalidMagic(magic.to_vec()));
        }

        let mut parser = Self {
            data,
            strings: Vec::new(),
            types: Vec::new(),
            methods: Vec::new(),
        };

        parser.read_tables()?;
        parser.parse_classes()
    }

    fn read_tables(&mut self) -> Result<(), DexError> {
        let string_ids_size = LittleEndian::read_u32(&self.data[56..60]) as usize;
        let string_ids_off = LittleEndian::read_u32(&self.data[60..64]) as usize;

        let type_ids_size = LittleEndian::read_u32(&self.data[64..68]) as usize;
        let type_ids_off = LittleEndian::read_u32(&self.data[68..72]) as usize;

        let method_ids_size = LittleEndian::read_u32(&self.data[88..92]) as usize;
        let method_ids_off = LittleEndian::read_u32(&self.data[92..96]) as usize;

        // 1. Read String Table
        for i in 0..string_ids_size {
            let entry_off = string_ids_off + (i * 4);
            if entry_off + 4 > self.data.len() {
                break;
            }
            let data_off = LittleEndian::read_u32(&self.data[entry_off..entry_off + 4]) as usize;
            if data_off < self.data.len() {
                let s = Self::read_string_data(self.data, data_off);
                self.strings.push(s);
            } else {
                self.strings.push(String::new());
            }
        }

        // 2. Read Type Table
        for i in 0..type_ids_size {
            let entry_off = type_ids_off + (i * 4);
            if entry_off + 4 > self.data.len() {
                break;
            }
            let descriptor_idx = LittleEndian::read_u32(&self.data[entry_off..entry_off + 4]) as usize;
            let type_str = if descriptor_idx < self.strings.len() {
                self.strings[descriptor_idx].clone()
            } else {
                String::new()
            };
            self.types.push(type_str);
        }

        // 3. Read Method IDs Table
        for i in 0..method_ids_size {
            let entry_off = method_ids_off + (i * 8);
            if entry_off + 8 > self.data.len() {
                break;
            }
            let class_idx = LittleEndian::read_u16(&self.data[entry_off..entry_off + 2]) as usize;
            let proto_idx = LittleEndian::read_u16(&self.data[entry_off + 2..entry_off + 4]) as usize;
            let name_idx = LittleEndian::read_u32(&self.data[entry_off + 4..entry_off + 8]) as usize;
            self.methods.push((class_idx, proto_idx, name_idx));
        }

        Ok(())
    }

    fn read_string_data(data: &[u8], mut offset: usize) -> String {
        // Read ULEB128 utf16 size
        let (_utf16_len, bytes_read) = Self::read_uleb128(data, offset);
        offset += bytes_read;

        let mut bytes = Vec::new();
        while offset < data.len() {
            let b = data[offset];
            if b == 0 {
                break;
            }
            bytes.push(b);
            offset += 1;
        }

        String::from_utf8_lossy(&bytes).to_string()
    }

    fn read_uleb128(data: &[u8], mut offset: usize) -> (u32, usize) {
        let mut result = 0u32;
        let mut shift = 0;
        let mut count = 0;

        while offset < data.len() {
            let byte = data[offset];
            offset += 1;
            count += 1;

            result |= ((byte & 0x7F) as u32) << shift;
            if (byte & 0x80) == 0 {
                break;
            }
            shift += 7;
            if shift >= 35 {
                break;
            }
        }

        (result, count)
    }

    fn parse_classes(&self) -> Result<DexFile, DexError> {
        let class_defs_size = LittleEndian::read_u32(&self.data[96..100]) as usize;
        let class_defs_off = LittleEndian::read_u32(&self.data[100..104]) as usize;

        let mut class_names = Vec::new();
        let mut native_methods = Vec::new();

        for i in 0..class_defs_size {
            let entry_off = class_defs_off + (i * 32);
            if entry_off + 32 > self.data.len() {
                break;
            }

            let class_idx = LittleEndian::read_u32(&self.data[entry_off..entry_off + 4]) as usize;
            let class_data_off = LittleEndian::read_u32(&self.data[entry_off + 24..entry_off + 28]) as usize;

            let raw_class_type = if class_idx < self.types.len() {
                &self.types[class_idx]
            } else {
                ""
            };

            let clean_class_name = Self::clean_type_name(raw_class_type);
            class_names.push(clean_class_name.clone());

            if class_data_off == 0 || class_data_off >= self.data.len() {
                continue;
            }

            // Parse Class Data Item
            let mut cur = class_data_off;
            let (static_fields_size, r) = Self::read_uleb128(self.data, cur);
            cur += r;
            let (instance_fields_size, r) = Self::read_uleb128(self.data, cur);
            cur += r;
            let (direct_methods_size, r) = Self::read_uleb128(self.data, cur);
            cur += r;
            let (virtual_methods_size, r) = Self::read_uleb128(self.data, cur);
            cur += r;

            // Skip static fields (field_idx_diff, access_flags)
            for _ in 0..static_fields_size {
                let (_, r1) = Self::read_uleb128(self.data, cur);
                cur += r1;
                let (_, r2) = Self::read_uleb128(self.data, cur);
                cur += r2;
            }

            // Skip instance fields
            for _ in 0..instance_fields_size {
                let (_, r1) = Self::read_uleb128(self.data, cur);
                cur += r1;
                let (_, r2) = Self::read_uleb128(self.data, cur);
                cur += r2;
            }

            // Parse direct methods and virtual methods
            let mut last_method_idx = 0usize;
            for _ in 0..(direct_methods_size + virtual_methods_size) {
                let (diff, r1) = Self::read_uleb128(self.data, cur);
                cur += r1;
                let (access_flags, r2) = Self::read_uleb128(self.data, cur);
                cur += r2;
                let (code_off, r3) = Self::read_uleb128(self.data, cur);
                cur += r3;

                last_method_idx += diff as usize;

                if (access_flags & ACC_NATIVE) != 0 && last_method_idx < self.methods.len() {
                    let (_, _, name_idx) = self.methods[last_method_idx];
                    let method_name = if name_idx < self.strings.len() {
                        self.strings[name_idx].clone()
                    } else {
                        format!("method_{}", last_method_idx)
                    };

                    let jni_symbol = Self::mangle_jni_symbol(&clean_class_name, &method_name);
                    let is_static = (access_flags & ACC_STATIC) != 0;

                    native_methods.push(DexNativeMethod {
                        class_name: clean_class_name.clone(),
                        method_name,
                        return_type: "V".to_string(),
                        is_static,
                        jni_symbol,
                    });
                }
                let _ = code_off;
            }
        }

        Ok(DexFile {
            classes: class_names,
            native_methods,
        })
    }

    /// Converts Dalvik type descriptor 'Lcom/example/MyClass;' -> 'com.example.MyClass'
    fn clean_type_name(desc: &str) -> String {
        let trimmed = desc.trim_start_matches('L').trim_end_matches(';');
        trimmed.replace('/', ".")
    }

    /// Generates JNI standard C function symbol:
    /// e.g. "com.example.app.MainActivity" + "nativeInit" -> "Java_com_example_app_MainActivity_nativeInit"
    pub fn mangle_jni_symbol(class_name: &str, method_name: &str) -> String {
        let mut s = String::from("Java_");

        for c in class_name.chars() {
            match c {
                '.' => s.push('_'),
                '_' => s.push_str("_1"),
                '$' => s.push_str("_00024"),
                other => s.push(other),
            }
        }

        s.push('_');

        for c in method_name.chars() {
            match c {
                '_' => s.push_str("_1"),
                '$' => s.push_str("_00024"),
                other => s.push(other),
            }
        }

        s
    }
}

fn write_uleb128(out: &mut Vec<u8>, mut val: u32) {
    loop {
        let mut b = (val & 0x7F) as u8;
        val >>= 7;
        if val != 0 {
            b |= 0x80;
        }
        out.push(b);
        if val == 0 {
            break;
        }
    }
}

fn align4(buf: &mut Vec<u8>) {
    while buf.len() % 4 != 0 {
        buf.push(0);
    }
}

/// Standard Adler-32 checksum used at DEX header offset `[8..12]`.
pub fn adler32(data: &[u8]) -> u32 {
    const MOD_ADLER: u32 = 65521;
    let mut a: u32 = 1;
    let mut b: u32 = 0;
    for &byte in data {
        a = (a + byte as u32) % MOD_ADLER;
        b = (b + a) % MOD_ADLER;
    }
    (b << 16) | a
}

/// Pure-Rust FIPS 180-4 SHA-1 used for DEX `[12..32]` integrity signature.
pub fn sha1(data: &[u8]) -> [u8; 20] {
    let mut h: [u32; 5] = [0x6745_2301, 0xEFCD_AB89, 0x98BA_DCFE, 0x1032_5476, 0xC3D2_E1F0];
    let bit_len = (data.len() as u64) * 8;
    let mut msg = data.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in msg.chunks_exact(64) {
        let mut w = [0u32; 80];
        for i in 0..16 {
            w[i] = u32::from_be_bytes(chunk[i * 4..i * 4 + 4].try_into().unwrap());
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }
        let (mut a, mut b, mut c, mut d, mut e) = (h[0], h[1], h[2], h[3], h[4]);
        for (i, &wi) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | ((!b) & d), 0x5A82_7999u32),
                20..=39 => (b ^ c ^ d, 0x6ED9_EBA1u32),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1B_BCDCu32),
                _ => (b ^ c ^ d, 0xCA62_C1D6u32),
            };
            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(wi);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
    }
    let mut out = [0u8; 20];
    for (i, &v) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&v.to_be_bytes());
    }
    out
}

/// Generates a minimal, spec-compliant DEX 035 (`classes2.dex`) declaring
/// `com.walzer32.loader.Walzer32Engine` with `<clinit> { System.loadLibrary("walzer32"); }`
/// and `public static native int nativeInit(String apkPath)`.
pub fn generate_walzer32_bootstrap_dex() -> Vec<u8> {
    // Strictly lexicographically sorted UTF-16 string pool:
    let strings = [
        "<clinit>",                                  // 0
        "I",                                         // 1
        "IL",                                        // 2
        "Lcom/walzer32/loader/Walzer32Engine;",      // 3
        "Ljava/lang/Object;",                        // 4
        "Ljava/lang/String;",                        // 5
        "Ljava/lang/System;",                        // 6
        "V",                                         // 7
        "VL",                                        // 8
        "loadLibrary",                               // 9
        "nativeInit",                                // 10
        "walzer32",                                  // 11
    ];
    // type_ids indices matching strings 1,3,4,5,6,7:
    let type_str_idxs = [1u32, 3, 4, 5, 6, 7];
    // proto_ids: 0 -> (String)I [type 0, list (String=3)]; 1 -> ()V [type 5]; 2 -> (String)V [type 5, list (String=3)]
    // method_ids: 0 -> (cls=1, proto=1, name=0 <clinit>); 1 -> (cls=1, proto=0, name=10 nativeInit); 2 -> (cls=4, proto=2, name=9 loadLibrary)

    const HEADER_SIZE: usize = 0x70;
    let string_ids_off = HEADER_SIZE;
    let type_ids_off = string_ids_off + strings.len() * 4;
    let proto_ids_off = type_ids_off + type_str_idxs.len() * 4;
    let field_ids_off = proto_ids_off + 3 * 12;
    let method_ids_off = field_ids_off;
    let class_defs_off = method_ids_off + 3 * 8;
    let data_off = class_defs_off + 32;

    let mut out = vec![0u8; data_off];

    // Reserve Data section items after fixed tables:
    // 1. TypeList ([type_idx = 3] for (String))
    let type_list_off = out.len() as u32;
    out.extend_from_slice(&1u32.to_le_bytes()); // size = 1
    out.extend_from_slice(&3u16.to_le_bytes()); // type_idx = Ljava/lang/String;
    align4(&mut out);

    // 2. <clinit> code_item: const-string v0, "walzer32" (11) ; invoke-static {v0}, loadLibrary (2) ; return-void
    let clinit_code_off = out.len() as u32;
    out.extend_from_slice(&1u16.to_le_bytes()); // registers_size = 1
    out.extend_from_slice(&0u16.to_le_bytes()); // ins_size = 0
    out.extend_from_slice(&1u16.to_le_bytes()); // outs_size = 1
    out.extend_from_slice(&0u16.to_le_bytes()); // tries_size = 0
    out.extend_from_slice(&0u32.to_le_bytes()); // debug_info_off = 0
    out.extend_from_slice(&6u32.to_le_bytes()); // insns_size = 6 u16 units
    for unit in [0x001Au16, 11u16, 0x1071u16, 2u16, 0x0000u16, 0x000Eu16] {
        out.extend_from_slice(&unit.to_le_bytes());
    }
    align4(&mut out);

    // 3. String data items
    let mut string_data_offs = Vec::with_capacity(strings.len());
    for &s in &strings {
        string_data_offs.push(out.len() as u32);
        write_uleb128(&mut out, s.chars().count() as u32);
        out.extend_from_slice(s.as_bytes());
        out.push(0);
    }

    // 4. class_data_item (0 static fields, 0 instance fields, 2 direct methods, 0 virtual methods)
    let class_data_off = out.len() as u32;
    write_uleb128(&mut out, 0);
    write_uleb128(&mut out, 0);
    write_uleb128(&mut out, 2);
    write_uleb128(&mut out, 0);
    // direct[0]: method 0 (<clinit>), ACC_STATIC | ACC_CONSTRUCTOR (0x10008), clinit_code_off
    write_uleb128(&mut out, 0);
    write_uleb128(&mut out, ACC_STATIC | 0x1_0000);
    write_uleb128(&mut out, clinit_code_off);
    // direct[1]: method +1 (nativeInit), ACC_PUBLIC | ACC_STATIC | ACC_NATIVE, code_off = 0
    write_uleb128(&mut out, 1);
    write_uleb128(&mut out, ACC_PUBLIC | ACC_STATIC | ACC_NATIVE);
    write_uleb128(&mut out, 0);
    align4(&mut out);

    // 5. map_list
    let map_off = out.len() as u32;
    let map_items: [(u16, u32, u32); 9] = [
        (0x0000, 1, 0),
        (0x0001, strings.len() as u32, string_ids_off as u32),
        (0x0002, type_str_idxs.len() as u32, type_ids_off as u32),
        (0x0003, 3, proto_ids_off as u32),
        (0x0005, 3, method_ids_off as u32),
        (0x0006, 1, class_defs_off as u32),
        (0x1000, 1, map_off),
        (0x1001, 1, type_list_off),
        (0x2001, 1, clinit_code_off),
    ];
    // Note: type 0x2002 string_data_item + 0x2000 class_data_item also valid; emit full clean set:
    let mut full_map = map_items.to_vec();
    full_map.push((0x2000, 1, class_data_off));
    full_map.push((0x2002, strings.len() as u32, string_data_offs[0]));
    full_map.sort_by_key(|m| m.2);

    out.extend_from_slice(&(full_map.len() as u32).to_le_bytes());
    for (item_type, count, off) in full_map {
        out.extend_from_slice(&item_type.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&count.to_le_bytes());
        out.extend_from_slice(&off.to_le_bytes());
    }
    let file_size = out.len() as u32;
    let data_size = file_size - data_off as u32;

    // Fill tables:
    for (i, &off) in string_data_offs.iter().enumerate() {
        LittleEndian::write_u32(&mut out[string_ids_off + i * 4..][..4], off);
    }
    for (i, &sidx) in type_str_idxs.iter().enumerate() {
        LittleEndian::write_u32(&mut out[type_ids_off + i * 4..][..4], sidx);
    }
    let protos = [(2u32, 0u32, type_list_off), (7, 5, 0), (8, 5, type_list_off)];
    for (i, &(shorty, ret, params)) in protos.iter().enumerate() {
        let p = proto_ids_off + i * 12;
        LittleEndian::write_u32(&mut out[p..p + 4], shorty);
        LittleEndian::write_u32(&mut out[p + 4..p + 8], ret);
        LittleEndian::write_u32(&mut out[p + 8..p + 12], params);
    }
    let methods = [(1u16, 1u16, 0u32), (1, 0, 10), (4, 2, 9)];
    for (i, &(cls, proto, name)) in methods.iter().enumerate() {
        let p = method_ids_off + i * 8;
        LittleEndian::write_u16(&mut out[p..p + 2], cls);
        LittleEndian::write_u16(&mut out[p + 2..p + 4], proto);
        LittleEndian::write_u32(&mut out[p + 4..p + 8], name);
    }
    // class_def[0]
    LittleEndian::write_u32(&mut out[class_defs_off..][..4], 1); // Walzer32Engine
    LittleEndian::write_u32(&mut out[class_defs_off + 4..][..4], ACC_PUBLIC);
    LittleEndian::write_u32(&mut out[class_defs_off + 8..][..4], 2); // superclass = Object
    LittleEndian::write_u32(&mut out[class_defs_off + 12..][..4], 0);
    LittleEndian::write_u32(&mut out[class_defs_off + 16..][..4], 0xFFFF_FFFF);
    LittleEndian::write_u32(&mut out[class_defs_off + 20..][..4], 0);
    LittleEndian::write_u32(&mut out[class_defs_off + 24..][..4], class_data_off);
    LittleEndian::write_u32(&mut out[class_defs_off + 28..][..4], 0);

    // DEX header (112 bytes)
    out[0..8].copy_from_slice(b"dex\n035\0");
    LittleEndian::write_u32(&mut out[32..36], file_size);
    LittleEndian::write_u32(&mut out[36..40], HEADER_SIZE as u32);
    LittleEndian::write_u32(&mut out[40..44], 0x1234_5678); // endian_tag
    LittleEndian::write_u32(&mut out[52..56], map_off);
    LittleEndian::write_u32(&mut out[56..60], strings.len() as u32);
    LittleEndian::write_u32(&mut out[60..64], string_ids_off as u32);
    LittleEndian::write_u32(&mut out[64..68], type_str_idxs.len() as u32);
    LittleEndian::write_u32(&mut out[68..72], type_ids_off as u32);
    LittleEndian::write_u32(&mut out[72..76], 3);
    LittleEndian::write_u32(&mut out[76..80], proto_ids_off as u32);
    LittleEndian::write_u32(&mut out[88..92], 3);
    LittleEndian::write_u32(&mut out[92..96], method_ids_off as u32);
    LittleEndian::write_u32(&mut out[96..100], 1);
    LittleEndian::write_u32(&mut out[100..104], class_defs_off as u32);
    LittleEndian::write_u32(&mut out[104..108], data_size);
    LittleEndian::write_u32(&mut out[108..112], data_off as u32);

    // Signature SHA-1 over [32..] and Adler-32 over [12..]
    let sig = sha1(&out[32..]);
    out[12..32].copy_from_slice(&sig);
    let cksum = adler32(&out[12..]);
    LittleEndian::write_u32(&mut out[8..12], cksum);

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_walzer32_bootstrap_dex_roundtrip() {
        let dex_bytes = generate_walzer32_bootstrap_dex();
        let parsed = DexParser::parse(&dex_bytes).expect("valid bootstrap DEX");
        assert!(parsed.classes.contains(&"com.walzer32.loader.Walzer32Engine".to_string()));
        assert_eq!(parsed.native_methods.len(), 1);
        assert_eq!(parsed.native_methods[0].method_name, "nativeInit");
        assert_eq!(
            parsed.native_methods[0].jni_symbol,
            "Java_com_walzer32_loader_Walzer32Engine_nativeInit"
        );
    }
}
