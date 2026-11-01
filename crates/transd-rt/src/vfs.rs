use std::collections::HashMap;
use std::sync::Arc;
use transd_core::{GuestAddr, Memory, MemoryError};

/// Standard Linux errnos returned as negative numbers to guest syscalls
pub const ENOENT: i32 = -2;
pub const EBADF: i32 = -9;
pub const EACCES: i32 = -13;
pub const EINVAL: i32 = -22;
pub const ESPIPE: i32 = -29;

/// Standard file seek whence options
pub const SEEK_SET: i32 = 0;
pub const SEEK_CUR: i32 = 1;
pub const SEEK_END: i32 = 2;

/// Standard Linux file mode constants for stat64
pub const S_IFREG: u32 = 0o100000;
pub const S_IFDIR: u32 = 0o040000;
pub const S_IRUSR: u32 = 0o0400;
pub const S_IWUSR: u32 = 0o0200;
pub const S_IRGRP: u32 = 0o0040;
pub const S_IROTH: u32 = 0o0004;

/// Standard 32-bit ARM Linux `struct stat64`
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct Stat64 {
    pub st_dev: u64,
    pub __pad0: u32,
    pub __st_ino: u32,
    pub st_mode: u32,
    pub st_nlink: u32,
    pub st_uid: u32,
    pub st_gid: u32,
    pub st_rdev: u64,
    pub __pad3: u32,
    pub st_size: i64,
    pub st_blksize: u32,
    pub st_blocks: u64,
    pub st_atime: u32,
    pub st_atime_nsec: u32,
    pub st_mtime: u32,
    pub st_mtime_nsec: u32,
    pub st_ctime: u32,
    pub st_ctime_nsec: u32,
    pub st_ino: u64,
}

impl Stat64 {
    /// Writes the stat64 structure directly to guest memory in ARM32 little-endian format
    pub fn write_to_memory(&self, mem: &mut dyn Memory, addr: GuestAddr) -> Result<(), MemoryError> {
        let mut bytes = [0u8; 104];
        let dev = self.st_dev.to_le_bytes();
        bytes[0..8].copy_from_slice(&dev);
        bytes[8..12].copy_from_slice(&self.__pad0.to_le_bytes());
        bytes[12..16].copy_from_slice(&self.__st_ino.to_le_bytes());
        bytes[16..20].copy_from_slice(&self.st_mode.to_le_bytes());
        bytes[20..24].copy_from_slice(&self.st_nlink.to_le_bytes());
        bytes[24..28].copy_from_slice(&self.st_uid.to_le_bytes());
        bytes[28..32].copy_from_slice(&self.st_gid.to_le_bytes());
        bytes[32..40].copy_from_slice(&self.st_rdev.to_le_bytes());
        bytes[40..44].copy_from_slice(&self.__pad3.to_le_bytes());
        bytes[44..52].copy_from_slice(&self.st_size.to_le_bytes());
        bytes[52..56].copy_from_slice(&self.st_blksize.to_le_bytes());
        bytes[56..64].copy_from_slice(&self.st_blocks.to_le_bytes());
        bytes[64..68].copy_from_slice(&self.st_atime.to_le_bytes());
        bytes[68..72].copy_from_slice(&self.st_atime_nsec.to_le_bytes());
        bytes[72..76].copy_from_slice(&self.st_mtime.to_le_bytes());
        bytes[76..80].copy_from_slice(&self.st_mtime_nsec.to_le_bytes());
        bytes[80..84].copy_from_slice(&self.st_ctime.to_le_bytes());
        bytes[84..88].copy_from_slice(&self.st_ctime_nsec.to_le_bytes());
        bytes[88..96].copy_from_slice(&self.st_ino.to_le_bytes());

        mem.write_bytes(addr, &bytes)?;
        Ok(())
    }
}

/// Helper function to read a null-terminated C string from guest memory
pub fn read_cstring_from_mem(
    mem: &dyn Memory,
    addr: GuestAddr,
    max_len: usize,
) -> Result<String, MemoryError> {
    let mut bytes = Vec::new();
    let mut offset = 0;
    while offset < max_len {
        let b = mem.read_u8(addr.add(offset as u32))?;
        if b == 0 {
            break;
        }
        bytes.push(b);
        offset += 1;
    }
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

#[derive(Debug, Clone)]
pub struct OpenFile {
    pub content: Arc<Vec<u8>>,
    pub cursor: usize,
    pub flags: u32,
}

/// Virtual File System for Android environment virtualization and Bionic path redirection
#[derive(Debug, Clone)]
pub struct VirtualFileSystem {
    /// In-memory synthetic virtual files (e.g. /proc/cpuinfo, /system/build.prop)
    pub virtual_files: HashMap<String, Arc<Vec<u8>>>,
    /// Prefix redirection mapping (e.g. /system/lib/ -> /data/transd/system/lib/)
    pub redirects: Vec<(String, String)>,
    /// Open file descriptors (starting from fd 3)
    pub open_fds: HashMap<u32, OpenFile>,
    next_fd: u32,
}

impl Default for VirtualFileSystem {
    fn default() -> Self {
        Self::new()
    }
}

impl VirtualFileSystem {
    /// Creates a new VirtualFileSystem initialized with standard ARMv7 Android files
    pub fn new() -> Self {
        let mut vfs = Self {
            virtual_files: HashMap::new(),
            redirects: Vec::new(),
            open_fds: HashMap::new(),
            next_fd: 3,
        };

        vfs.init_default_android_environment();
        vfs
    }

    /// Initializes standard Android ARMv7-A system files:
    /// - /proc/cpuinfo (Qualcomm MSM8998 ARMv7-A with NEON, VFPv3, VFPv4, IDIVA, IDIVT)
    /// - /proc/version
    /// - /sys/devices/system/cpu/online
    /// - /sys/devices/system/cpu/present
    /// - /sys/devices/system/cpu/possible
    /// - /system/build.prop
    pub fn init_default_android_environment(&mut self) {
        let cpuinfo = "\
processor\t: 0
model name\t: ARMv7 Processor rev 4 (v7l)
BogoMIPS\t: 38.40
Features\t: half thumb fastmult vfp edsp neon vfpv3 tls vfpv4 idiva idivt
CPU implementer\t: 0x41
CPU architecture: 7
CPU variant\t: 0x0
CPU part\t: 0xc07
CPU revision\t: 4

processor\t: 1
model name\t: ARMv7 Processor rev 4 (v7l)
BogoMIPS\t: 38.40
Features\t: half thumb fastmult vfp edsp neon vfpv3 tls vfpv4 idiva idivt
CPU implementer\t: 0x41
CPU architecture: 7
CPU variant\t: 0x0
CPU part\t: 0xc07
CPU revision\t: 4

Hardware\t: Qualcomm Technologies, Inc MSM8998
Revision\t: 0000
Serial\t\t: 0000000000000000
";
        self.register_file("/proc/cpuinfo", cpuinfo.as_bytes().to_vec());

        let version = "Linux version 4.14.180-perf+ (android-build@google.com) (clang version 10.0.7) #1 SMP PREEMPT Thu Jan 1 00:00:00 UTC 2026\n";
        self.register_file("/proc/version", version.as_bytes().to_vec());

        self.register_file("/sys/devices/system/cpu/online", b"0-7\n".to_vec());
        self.register_file("/sys/devices/system/cpu/present", b"0-7\n".to_vec());
        self.register_file("/sys/devices/system/cpu/possible", b"0-7\n".to_vec());

        let build_prop = "\
ro.product.cpu.abi=armeabi-v7a
ro.product.cpu.abilist=armeabi-v7a,armeabi
ro.product.cpu.abilist32=armeabi-v7a,armeabi
ro.product.cpu.abilist64=
ro.build.version.sdk=28
ro.build.version.release=9
ro.product.model=Transd Virtual ARMv7 Device
ro.product.brand=Transd
ro.product.manufacturer=Transd
";
        self.register_file("/system/build.prop", build_prop.as_bytes().to_vec());
    }

    /// Registers or overwrites a synthetic virtual file in the VFS
    pub fn register_file(&mut self, path: &str, content: Vec<u8>) {
        self.virtual_files.insert(path.to_string(), Arc::new(content));
    }

    /// Adds a prefix path redirection rule (e.g. from "/system/lib/" to "/data/transd/system/lib/")
    pub fn add_redirect(&mut self, from: &str, to: &str) {
        self.redirects.push((from.to_string(), to.to_string()));
    }

    /// Resolves path using redirection rules
    pub fn resolve_path(&self, path: &str) -> String {
        for (from, to) in &self.redirects {
            if path.starts_with(from) {
                return format!("{}{}", to, &path[from.len()..]);
            }
        }
        path.to_string()
    }

    /// Opens a virtual file by path, returning a guest file descriptor (>= 3) or -errno
    pub fn open(&mut self, raw_path: &str, flags: u32) -> Result<u32, i32> {
        let resolved = self.resolve_path(raw_path);
        if let Some(content) = self.virtual_files.get(&resolved).cloned() {
            let fd = self.next_fd;
            self.next_fd += 1;
            self.open_fds.insert(
                fd,
                OpenFile {
                    content,
                    cursor: 0,
                    flags,
                },
            );
            Ok(fd)
        } else {
            Err(ENOENT)
        }
    }

    /// Closes an open guest file descriptor
    pub fn close(&mut self, fd: u32) -> Result<(), i32> {
        if self.open_fds.remove(&fd).is_some() {
            Ok(())
        } else {
            Err(EBADF)
        }
    }

    /// Reads bytes from an open guest file descriptor into a buffer
    pub fn read(&mut self, fd: u32, buf: &mut [u8]) -> Result<usize, i32> {
        let file = self.open_fds.get_mut(&fd).ok_or(EBADF)?;
        if file.cursor >= file.content.len() {
            return Ok(0); // EOF
        }

        let available = file.content.len() - file.cursor;
        let to_read = available.min(buf.len());
        buf[..to_read].copy_from_slice(&file.content[file.cursor..file.cursor + to_read]);
        file.cursor += to_read;
        Ok(to_read)
    }

    /// Adjusts file cursor using standard whence options (SEEK_SET, SEEK_CUR, SEEK_END)
    pub fn seek(&mut self, fd: u32, offset: i64, whence: i32) -> Result<u64, i32> {
        let file = self.open_fds.get_mut(&fd).ok_or(EBADF)?;
        let new_cursor = match whence {
            SEEK_SET => offset,
            SEEK_CUR => (file.cursor as i64) + offset,
            SEEK_END => (file.content.len() as i64) + offset,
            _ => return Err(EINVAL),
        };

        if new_cursor < 0 {
            return Err(EINVAL);
        }

        file.cursor = new_cursor as usize;
        Ok(file.cursor as u64)
    }

    /// Queries file metadata by path
    pub fn stat64(&self, raw_path: &str) -> Result<Stat64, i32> {
        let resolved = self.resolve_path(raw_path);
        if let Some(content) = self.virtual_files.get(&resolved) {
            let mut st = Stat64::default();
            st.st_mode = S_IFREG | S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
            st.st_nlink = 1;
            st.st_size = content.len() as i64;
            st.st_blksize = 4096;
            st.st_blocks = ((content.len() + 511) / 512) as u64;
            Ok(st)
        } else {
            Err(ENOENT)
        }
    }

    /// Queries file metadata by open descriptor
    pub fn fstat64(&self, fd: u32) -> Result<Stat64, i32> {
        let file = self.open_fds.get(&fd).ok_or(EBADF)?;
        let mut st = Stat64::default();
        st.st_mode = S_IFREG | S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
        st.st_nlink = 1;
        st.st_size = file.content.len() as i64;
        st.st_blksize = 4096;
        st.st_blocks = ((file.content.len() + 511) / 512) as u64;
        Ok(st)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vfs_proc_cpuinfo() {
        let mut vfs = VirtualFileSystem::new();
        let fd = vfs.open("/proc/cpuinfo", 0).expect("failed to open /proc/cpuinfo");
        assert!(fd >= 3);

        let mut buf = vec![0u8; 128];
        let n = vfs.read(fd, &mut buf).expect("read failed");
        assert!(n > 0);
        let s = String::from_utf8_lossy(&buf[..n]);
        assert!(s.contains("ARMv7 Processor"));

        // Seek to end
        let end_pos = vfs.seek(fd, 0, SEEK_END).expect("seek end");
        assert!(end_pos > 100);

        // Read at EOF returns 0
        let n_eof = vfs.read(fd, &mut buf).expect("read at eof");
        assert_eq!(n_eof, 0);

        vfs.close(fd).expect("close");
        assert_eq!(vfs.read(fd, &mut buf), Err(EBADF));
    }

    #[test]
    fn test_vfs_path_redirection() {
        let mut vfs = VirtualFileSystem::new();
        vfs.register_file("/opt/fake/libc.so", b"ARM32_LIBC".to_vec());
        vfs.add_redirect("/system/lib/", "/opt/fake/");

        let resolved = vfs.resolve_path("/system/lib/libc.so");
        assert_eq!(resolved, "/opt/fake/libc.so");

        let fd = vfs.open("/system/lib/libc.so", 0).expect("open redirected");
        let mut buf = vec![0u8; 32];
        let n = vfs.read(fd, &mut buf).expect("read redirected");
        assert_eq!(&buf[..n], b"ARM32_LIBC");
        vfs.close(fd).unwrap();
    }

    #[test]
    fn test_vfs_stat64() {
        let vfs = VirtualFileSystem::new();
        let st = vfs.stat64("/system/build.prop").expect("stat build.prop");
        assert!(st.st_size > 0);
        assert_eq!(st.st_mode & S_IFREG, S_IFREG);
    }
}
