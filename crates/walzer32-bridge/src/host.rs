/// HostBridge — runtime dlopen/dlsym bridge for Android host libraries.
///
/// On Android (target_os = "android") this module opens the real system shared
/// libraries (libGLESv2.so, libEGL.so, liblog.so, libc.so) and resolves
/// function pointers by name.  On dev-host (non-Android Linux / Windows) it
/// returns `None` for every lookup so callers transparently fall back to the
/// stub implementations in `GlesBridge` and `BionicBridge`.
///
/// 32-bit → 64-bit argument marshalling:
///   * Integer arguments: `u32 as u64` (zero-extends, same bit pattern for
///     32-bit values stored in ARM registers).
///   * Guest pointer arguments: `GuestAddr(u32)` → host pointer obtained by
///     slicing into the flat guest memory region.  The `ArgMarshaller` holds a
///     `(*const u8, usize)` slice descriptor so it can safely do this without
///     a lifetime parameter tied to the borrow checker.
///
/// Safety contract:
///   Any `*const c_void` returned by `resolve` must be called with the correct
///   number and types of arguments, matching the underlying C ABI.  Wrong
///   usage is UB — this is inherent to FFI.

use std::collections::HashMap;
use std::ffi::{CStr, c_void};
#[cfg(target_os = "android")]
use std::ffi::CString;

/// Result of a symbol lookup: a raw function pointer.
pub type RawFnPtr = *mut c_void;

/// Resolved handle to an opened shared library.
#[derive(Debug)]
pub struct LibHandle(*mut c_void);

unsafe impl Send for LibHandle {}
unsafe impl Sync for LibHandle {}

impl LibHandle {
    pub fn is_null(&self) -> bool {
        self.0.is_null()
    }
}

#[cfg(target_os = "android")]
impl Drop for LibHandle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { libc::dlclose(self.0) };
        }
    }
}

#[cfg(not(target_os = "android"))]
impl Drop for LibHandle {
    fn drop(&mut self) {}
}

// ─────────────────────────────────────────────────────────────────────────────
// HostBridge
// ─────────────────────────────────────────────────────────────────────────────

/// Bridge to real Android host libraries via dlopen/dlsym.
pub struct HostBridge {
    /// Opened library handles (kept alive so symbols remain valid).
    _handles: Vec<LibHandle>,
    /// Cache: symbol name → raw function pointer.
    symbols: HashMap<String, RawFnPtr>,
}

unsafe impl Send for HostBridge {}
unsafe impl Sync for HostBridge {}

impl HostBridge {
    /// Returns `true` when running on an actual Android device / emulator.
    pub fn available() -> bool {
        cfg!(target_os = "android")
    }

    /// Open the standard Android graphics + log libraries.
    ///
    /// On non-Android this is a no-op and `available()` returns `false`.
    pub fn new() -> Self {
        #[allow(unused_mut)]
        let mut bridge = Self {
            _handles: Vec::new(),
            symbols: HashMap::new(),
        };

        #[cfg(target_os = "android")]
        {
            // Libraries to open.  Order matters: later opens override symbols
            // with the same name (irrelevant here since names are unique).
            let libs = [
                "libEGL.so\0",
                "libGLESv2.so\0",
                "libGLESv3.so\0",
                "libvulkan.so\0",
                "libandroid.so\0",
                "libaaudio.so\0",
                "liblog.so\0",
                "libc.so\0",
                "libm.so\0",
            ];
            for lib in &libs {
                // SAFETY: lib is a valid NUL-terminated C string literal.
                let handle = unsafe {
                    libc::dlopen(
                        lib.as_ptr() as *const libc::c_char,
                        libc::RTLD_NOW | libc::RTLD_GLOBAL,
                    )
                };
                if !handle.is_null() {
                    bridge._handles.push(LibHandle(handle));
                }
            }
        }

        bridge
    }

    /// Look up `symbol` in the already-opened libraries.
    ///
    /// Returns `Some(ptr)` on Android when the symbol is found, `None` on
    /// dev-host or when the symbol does not exist.
    pub fn resolve(&mut self, symbol: &str) -> Option<RawFnPtr> {
        if let Some(&ptr) = self.symbols.get(symbol) {
            return if ptr.is_null() { None } else { Some(ptr) };
        }

        let ptr = self.dlsym_raw(symbol);
        // Cache result (including None → null entry to avoid repeated lookups)
        self.symbols.insert(symbol.to_string(), ptr.unwrap_or(std::ptr::null_mut()));
        ptr
    }

    #[cfg(target_os = "android")]
    fn dlsym_raw(&self, symbol: &str) -> Option<RawFnPtr> {
        let cname = CString::new(symbol).ok()?;
        // Search explicitly dlopen'd library handles first (later opens take precedence);
        // on Android Bionic, RTLD_DEFAULT skips handles opened in separate namespace groups.
        for handle in self._handles.iter().rev() {
            let ptr = unsafe { libc::dlsym(handle.0, cname.as_ptr()) };
            if !ptr.is_null() {
                return Some(ptr);
            }
        }
        let ptr = unsafe { libc::dlsym(libc::RTLD_DEFAULT, cname.as_ptr()) };
        if ptr.is_null() { None } else { Some(ptr) }
    }

    #[cfg(not(target_os = "android"))]
    fn dlsym_raw(&self, _symbol: &str) -> Option<RawFnPtr> {
        None
    }

    /// Resolve multiple symbols at once; returns a `Vec` with `None` entries
    /// for missing symbols.
    pub fn resolve_batch(&mut self, symbols: &[&str]) -> Vec<Option<RawFnPtr>> {
        symbols.iter().map(|s| self.resolve(s)).collect()
    }
}

impl Default for HostBridge {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ArgMarshaller — 32-bit guest → 64-bit host argument conversion
// ─────────────────────────────────────────────────────────────────────────────

/// Marshals 32-bit guest register values into 64-bit host call arguments.
///
/// Holds a raw pointer + length into the flat guest memory so it can derive
/// host pointer arguments without holding a Rust reference (which would
/// require lifetime parameters incompatible with FFI dispatch).
pub struct ArgMarshaller {
    /// Base address of the guest flat memory region in host address space.
    mem_base: *const u8,
    /// Total size of the guest memory region (for bounds checks).
    mem_size: usize,
}

impl ArgMarshaller {
    /// Create a marshaller over the given guest memory slice.
    ///
    /// # Safety
    /// `mem_base` must remain valid for the lifetime of this marshaller.
    pub unsafe fn new(mem_base: *const u8, mem_size: usize) -> Self {
        Self { mem_base, mem_size }
    }

    /// Zero-extend a 32-bit guest integer argument to 64-bit.
    #[inline(always)]
    pub fn int(&self, v: u32) -> u64 {
        v as u64
    }

    /// Sign-extend a 32-bit guest signed integer argument to 64-bit.
    #[inline(always)]
    pub fn int_signed(&self, v: u32) -> i64 {
        v as i32 as i64
    }

    /// Convert a guest virtual address (u32) to a host raw pointer.
    ///
    /// Returns `None` if the address is 0 (null) or out of bounds.
    pub fn ptr(&self, guest_addr: u32) -> Option<*const c_void> {
        if guest_addr == 0 {
            return None;
        }
        let offset = guest_addr as usize;
        if offset >= self.mem_size {
            return None;
        }
        // SAFETY: bounds checked above; mem_base is valid per constructor contract.
        Some(unsafe { self.mem_base.add(offset) as *const c_void })
    }

    /// Like `ptr` but returns a mutable pointer.
    pub fn ptr_mut(&self, guest_addr: u32) -> Option<*mut c_void> {
        self.ptr(guest_addr).map(|p| p as *mut c_void)
    }

    /// Return a byte slice view of `len` bytes at `guest_addr`.
    ///
    /// Returns `None` on null or out-of-bounds access.
    pub fn slice(&self, guest_addr: u32, len: usize) -> Option<&[u8]> {
        let offset = guest_addr as usize;
        let end = offset.checked_add(len)?;
        if end > self.mem_size {
            return None;
        }
        // SAFETY: range checked; mem_base valid per constructor.
        Some(unsafe { std::slice::from_raw_parts(self.mem_base.add(offset), len) })
    }

    /// Return a NUL-terminated C string at `guest_addr`.
    pub fn cstr(&self, guest_addr: u32) -> Option<&CStr> {
        let offset = guest_addr as usize;
        if offset >= self.mem_size {
            return None;
        }
        let remaining = &unsafe {
            std::slice::from_raw_parts(self.mem_base.add(offset), self.mem_size - offset)
        };
        // Find the NUL terminator within bounds.
        let nul_pos = remaining.iter().position(|&b| b == 0)?;
        // SAFETY: the slice up to nul_pos+1 is valid and NUL-terminated.
        Some(unsafe {
            CStr::from_bytes_with_nul_unchecked(&remaining[..=nul_pos])
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_host_bridge_available_returns_bool() {
        // Just verify it compiles and doesn't panic on dev host.
        let available = HostBridge::available();
        // On dev host (Windows/Linux x86-64) this should be false.
        if cfg!(target_os = "android") {
            assert!(available);
        } else {
            assert!(!available);
        }
    }

    #[test]
    fn test_host_bridge_resolve_returns_none_on_devhost() {
        let mut bridge = HostBridge::new();
        // On non-Android, all lookups must return None (no dlopen available).
        if !HostBridge::available() {
            assert!(bridge.resolve("glClear").is_none());
            assert!(bridge.resolve("eglGetDisplay").is_none());
            assert!(bridge.resolve("__android_log_print").is_none());
        }
    }

    #[test]
    fn test_arg_marshaller_int() {
        let mem = [0u8; 64];
        let m = unsafe { ArgMarshaller::new(mem.as_ptr(), mem.len()) };
        assert_eq!(m.int(0xDEAD_BEEFu32), 0x0000_0000_DEAD_BEEFu64);
        assert_eq!(m.int_signed(0xFFFF_FFFFu32), -1i64);
    }

    #[test]
    fn test_arg_marshaller_ptr_null() {
        let mem = [0u8; 64];
        let m = unsafe { ArgMarshaller::new(mem.as_ptr(), mem.len()) };
        assert!(m.ptr(0).is_none());
    }

    #[test]
    fn test_arg_marshaller_ptr_valid() {
        let mem = [0xAAu8; 64];
        let m = unsafe { ArgMarshaller::new(mem.as_ptr(), mem.len()) };
        let host_ptr = m.ptr(4).unwrap();
        // The host pointer should be mem.as_ptr() + 4
        assert_eq!(host_ptr as usize, mem.as_ptr() as usize + 4);
    }

    #[test]
    fn test_arg_marshaller_ptr_oob() {
        let mem = [0u8; 64];
        let m = unsafe { ArgMarshaller::new(mem.as_ptr(), mem.len()) };
        assert!(m.ptr(64).is_none());
        assert!(m.ptr(0xFFFF_FFFF).is_none());
    }

    #[test]
    fn test_arg_marshaller_slice() {
        let mem = b"Hello, World!".to_vec();
        let m = unsafe { ArgMarshaller::new(mem.as_ptr(), mem.len()) };
        let s = m.slice(0, 5).unwrap();
        assert_eq!(s, b"Hello");
    }

    #[test]
    fn test_arg_marshaller_cstr() {
        let mem = b"walzer32\0extra".to_vec();
        let m = unsafe { ArgMarshaller::new(mem.as_ptr(), mem.len()) };
        let cs = m.cstr(0).unwrap();
        assert_eq!(cs.to_str().unwrap(), "walzer32");
    }
}
