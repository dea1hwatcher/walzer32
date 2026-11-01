use byteorder::{ByteOrder, LittleEndian};
use std::collections::HashMap;
use transd_core::{GuestAddr, Memory, MemoryError};

pub const PROP_NAME_MAX: usize = 32;
pub const PROP_VALUE_MAX: usize = 92;
pub const PROP_INFO_SIZE: u32 = 128;

/// Manages Android System Properties (`__system_property_get`, `__system_property_find`, `__system_property_read`)
#[derive(Debug, Clone)]
pub struct PropertyStore {
    properties: HashMap<String, String>,
    prop_heap_cur: GuestAddr,
    prop_heap_limit: GuestAddr,
    prop_addrs: HashMap<String, GuestAddr>,
}

impl PropertyStore {
    pub fn new(heap_start: GuestAddr, heap_size: u32) -> Self {
        let mut store = Self {
            properties: HashMap::new(),
            prop_heap_cur: heap_start,
            prop_heap_limit: heap_start.add(heap_size),
            prop_addrs: HashMap::new(),
        };
        store.init_default_properties();
        store
    }

    pub fn init_default_properties(&mut self) {
        let defaults = [
            ("ro.product.cpu.abi", "armeabi-v7a"),
            ("ro.product.cpu.abilist", "armeabi-v7a,armeabi"),
            ("ro.product.cpu.abilist32", "armeabi-v7a,armeabi"),
            ("ro.product.cpu.abilist64", ""),
            ("ro.product.cpu.abi2", "armeabi"),
            ("ro.build.version.sdk", "28"),
            ("ro.build.version.release", "9"),
            ("ro.build.version.preview_sdk", "0"),
            ("ro.build.version.codename", "REL"),
            ("ro.build.version.all_codenames", "REL"),
            ("ro.product.model", "Transd Virtual ARMv7 Device"),
            ("ro.product.brand", "Transd"),
            ("ro.product.name", "transd_v7a"),
            ("ro.product.device", "transd"),
            ("ro.product.board", "transd"),
            ("ro.product.manufacturer", "Transd"),
            (
                "ro.build.fingerprint",
                "Transd/transd_v7a/transd:9/PQ3A.190801.002/1000000:user/release-keys",
            ),
            ("ro.build.id", "PQ3A.190801.002"),
            ("ro.build.type", "user"),
            ("ro.build.tags", "release-keys"),
            ("ro.debuggable", "0"),
            ("ro.hardware", "qcom"),
            ("debug.transd.engine", "dbt-arm32"),
            ("debug.transd.version", "0.1.0"),
        ];

        for (k, v) in defaults {
            self.properties.insert(k.to_string(), v.to_string());
        }
    }

    pub fn get(&self, name: &str) -> Option<&str> {
        self.properties.get(name).map(|s| s.as_str())
    }

    pub fn set(&mut self, name: &str, value: &str) {
        self.properties.insert(name.to_string(), value.to_string());
    }

    pub fn all_properties(&self) -> &HashMap<String, String> {
        &self.properties
    }

    /// Serializes properties in build.prop format (sorted)
    pub fn to_build_prop(&self) -> String {
        let mut keys: Vec<&String> = self.properties.keys().collect();
        keys.sort();
        let mut out = String::new();
        for k in keys {
            out.push_str(k);
            out.push('=');
            out.push_str(&self.properties[k]);
            out.push('\n');
        }
        out
    }

    /// Implements `int __system_property_get(const char *name, char *value)`
    /// Returns length of value written (not including null terminator), or 0 if not found.
    pub fn system_property_get(
        &self,
        name: &str,
        value_out: GuestAddr,
        mem: &mut (impl Memory + ?Sized),
    ) -> Result<i32, MemoryError> {
        if let Some(val) = self.get(name) {
            let bytes = val.as_bytes();
            let copy_len = bytes.len().min(PROP_VALUE_MAX - 1);
            let mut buf = vec![0u8; copy_len + 1];
            buf[..copy_len].copy_from_slice(&bytes[..copy_len]);
            buf[copy_len] = 0; // null terminator
            mem.write_bytes(value_out, &buf)?;
            Ok(copy_len as i32)
        } else {
            // Write empty null terminator
            mem.write_u8(value_out, 0)?;
            Ok(0)
        }
    }

    /// Implements `const prop_info *__system_property_find(const char *name)`
    /// Returns pointer to `prop_info` structure in guest memory, or NULL (0) if not found.
    pub fn system_property_find(
        &mut self,
        name: &str,
        mem: &mut (impl Memory + ?Sized),
    ) -> Result<GuestAddr, MemoryError> {
        let val_opt = self.properties.get(name).cloned();
        if let Some(val) = val_opt {
            if let Some(&cached_addr) = self.prop_addrs.get(name) {
                return Ok(cached_addr);
            }

            // Allocate 128 bytes in prop_heap
            let slot_addr = self.prop_heap_cur;
            let next_addr = slot_addr.add(PROP_INFO_SIZE);
            if next_addr > self.prop_heap_limit {
                return Ok(GuestAddr::new(0)); // OOM
            }
            self.prop_heap_cur = next_addr;

            // struct prop_info layout:
            // 0..32: name (32 bytes)
            // 32..36: serial (u32 = 1)
            // 36..128: value (92 bytes)
            let mut info_bytes = [0u8; 128];
            let name_bytes = name.as_bytes();
            let name_len = name_bytes.len().min(PROP_NAME_MAX - 1);
            info_bytes[..name_len].copy_from_slice(&name_bytes[..name_len]);

            // serial
            LittleEndian::write_u32(&mut info_bytes[32..36], 1);

            let val_bytes = val.as_bytes();
            let val_len = val_bytes.len().min(PROP_VALUE_MAX - 1);
            info_bytes[36..36 + val_len].copy_from_slice(&val_bytes[..val_len]);

            mem.write_bytes(slot_addr, &info_bytes)?;
            self.prop_addrs.insert(name.to_string(), slot_addr);

            Ok(slot_addr)
        } else {
            Ok(GuestAddr::new(0))
        }
    }

    /// Implements `int __system_property_read(const prop_info *pi, char *name, char *value)`
    /// Returns length of value written.
    pub fn system_property_read(
        &self,
        prop_info_addr: GuestAddr,
        name_out: GuestAddr,
        value_out: GuestAddr,
        mem: &mut (impl Memory + ?Sized),
    ) -> Result<i32, MemoryError> {
        if prop_info_addr.as_u32() == 0 {
            return Ok(-1);
        }

        let mut info_bytes = [0u8; 128];
        mem.read_bytes(prop_info_addr, &mut info_bytes)?;

        // If name_out != NULL, write name
        if name_out.as_u32() != 0 {
            let name_slice = &info_bytes[0..32];
            let name_len = name_slice.iter().position(|&b| b == 0).unwrap_or(31);
            let mut name_buf = vec![0u8; name_len + 1];
            name_buf[..name_len].copy_from_slice(&name_slice[..name_len]);
            name_buf[name_len] = 0;
            mem.write_bytes(name_out, &name_buf)?;
        }

        // Read value
        let val_slice = &info_bytes[36..128];
        let val_len = val_slice.iter().position(|&b| b == 0).unwrap_or(91);

        if value_out.as_u32() != 0 {
            let mut val_buf = vec![0u8; val_len + 1];
            val_buf[..val_len].copy_from_slice(&val_slice[..val_len]);
            val_buf[val_len] = 0;
            mem.write_bytes(value_out, &val_buf)?;
        }

        Ok(val_len as i32)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use transd_core::FlatMemory;

    #[test]
    fn test_property_store_defaults_and_get() {
        let mut mem = FlatMemory::new(GuestAddr::new(0x1000), 0x4000);
        let store = PropertyStore::new(GuestAddr::new(0x1000), 0x1000);

        assert_eq!(store.get("ro.build.version.sdk"), Some("28"));
        assert_eq!(store.get("ro.product.cpu.abi"), Some("armeabi-v7a"));
        assert_eq!(store.get("ro.nonexistent"), None);

        let out_addr = GuestAddr::new(0x2000);
        let len = store
            .system_property_get("ro.build.version.sdk", out_addr, &mut mem)
            .unwrap();
        assert_eq!(len, 2);

        let mut buf = [0u8; 3];
        mem.read_bytes(out_addr, &mut buf).unwrap();
        assert_eq!(&buf, b"28\0");
    }

    #[test]
    fn test_property_find_and_read() {
        let mut mem = FlatMemory::new(GuestAddr::new(0x1000), 0x4000);
        let mut store = PropertyStore::new(GuestAddr::new(0x1000), 0x1000);

        let pi_addr = store
            .system_property_find("ro.product.cpu.abi", &mut mem)
            .unwrap();
        assert_ne!(pi_addr.as_u32(), 0);

        let name_out = GuestAddr::new(0x3000);
        let val_out = GuestAddr::new(0x3040);
        let len = store
            .system_property_read(pi_addr, name_out, val_out, &mut mem)
            .unwrap();
        assert_eq!(len, 11);

        let mut name_buf = [0u8; 19];
        mem.read_bytes(name_out, &mut name_buf).unwrap();
        assert_eq!(&name_buf, b"ro.product.cpu.abi\0");

        let mut val_buf = [0u8; 12];
        mem.read_bytes(val_out, &mut val_buf).unwrap();
        assert_eq!(&val_buf, b"armeabi-v7a\0");
    }
}
