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
    pub path: String,
    pub content: Arc<Vec<u8>>,
    pub cursor: usize,
    pub flags: u32,
}

#[derive(Debug, Clone)]
pub struct AshmemRegion {
    pub fd: u32,
    pub name: String,
    pub size: usize,
    pub prot_mask: u32,
    pub is_initialized: bool,
    pub data: Arc<std::sync::Mutex<Vec<u8>>>,
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
    /// Open Ashmem / Memfd shared memory regions
    pub ashmem_regions: HashMap<u32, AshmemRegion>,
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
            ashmem_regions: HashMap::new(),
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
        self.register_file_arc(path, Arc::new(content));
    }

    /// Registers or overwrites a synthetic virtual file using a shared Arc buffer
    pub fn register_file_arc(&mut self, path: &str, content: Arc<Vec<u8>>) {
        self.virtual_files.insert(path.to_string(), content);
    }

    /// Mounts an Android OBB expansion file using a shared Arc buffer to eliminate duplication
    pub fn mount_obb_arc(&mut self, package_name: &str, version: u32, content: Arc<Vec<u8>>) {
        let path1 = format!("/sdcard/Android/obb/{package_name}/main.{version}.{package_name}.obb");
        let path2 = format!("/storage/emulated/0/Android/obb/{package_name}/main.{version}.{package_name}.obb");
        let path3 = format!("/data/media/0/Android/obb/{package_name}/main.{version}.{package_name}.obb");
        self.virtual_files.insert(path1, Arc::clone(&content));
        self.virtual_files.insert(path2, Arc::clone(&content));
        self.virtual_files.insert(path3, content);
    }

    /// Mounts an Android patch OBB expansion file using a shared Arc buffer
    pub fn mount_patch_obb_arc(&mut self, package_name: &str, version: u32, content: Arc<Vec<u8>>) {
        let path1 = format!("/sdcard/Android/obb/{package_name}/patch.{version}.{package_name}.obb");
        let path2 = format!("/storage/emulated/0/Android/obb/{package_name}/patch.{version}.{package_name}.obb");
        let path3 = format!("/data/media/0/Android/obb/{package_name}/patch.{version}.{package_name}.obb");
        self.virtual_files.insert(path1, Arc::clone(&content));
        self.virtual_files.insert(path2, Arc::clone(&content));
        self.virtual_files.insert(path3, content);
    }

    /// Resolves an openat relative or absolute path against dirfd
    pub fn resolve_at_path(&self, dirfd: i32, path: &str) -> String {
        if path.starts_with('/') {
            return path.to_string();
        }
        if dirfd == -100 {
            // AT_FDCWD
            format!("/{}", path.trim_start_matches('/'))
        } else if let Some(base) = self.fd_path(dirfd as u32) {
            format!("{}/{}", base.trim_end_matches('/'), path.trim_start_matches('/'))
        } else {
            path.to_string()
        }
    }

    /// Opens a file relative to a directory file descriptor (POSIX openat)
    pub fn openat(&mut self, dirfd: i32, path: &str, flags: u32) -> Result<u32, i32> {
        let resolved = self.resolve_at_path(dirfd, path);
        self.open(&resolved, flags)
    }

    /// Mounts an Android OBB expansion file at the standard system paths:
    /// - /sdcard/Android/obb/{package_name}/main.{version}.{package_name}.obb
    /// - /storage/emulated/0/Android/obb/{package_name}/main.{version}.{package_name}.obb
    /// - /data/media/0/Android/obb/{package_name}/main.{version}.{package_name}.obb
    pub fn mount_obb(&mut self, package_name: &str, version: u32, content: Vec<u8>) {
        let arc = Arc::new(content);
        let path1 = format!("/sdcard/Android/obb/{package_name}/main.{version}.{package_name}.obb");
        let path2 = format!("/storage/emulated/0/Android/obb/{package_name}/main.{version}.{package_name}.obb");
        let path3 = format!("/data/media/0/Android/obb/{package_name}/main.{version}.{package_name}.obb");
        self.virtual_files.insert(path1, Arc::clone(&arc));
        self.virtual_files.insert(path2, Arc::clone(&arc));
        self.virtual_files.insert(path3, arc);
    }

    /// Mounts an Android patch OBB expansion file at the standard system paths:
    /// - /sdcard/Android/obb/{package_name}/patch.{version}.{package_name}.obb
    /// - /storage/emulated/0/Android/obb/{package_name}/patch.{version}.{package_name}.obb
    /// - /data/media/0/Android/obb/{package_name}/patch.{version}.{package_name}.obb
    pub fn mount_patch_obb(&mut self, package_name: &str, version: u32, content: Vec<u8>) {
        let arc = Arc::new(content);
        let path1 = format!("/sdcard/Android/obb/{package_name}/patch.{version}.{package_name}.obb");
        let path2 = format!("/storage/emulated/0/Android/obb/{package_name}/patch.{version}.{package_name}.obb");
        let path3 = format!("/data/media/0/Android/obb/{package_name}/patch.{version}.{package_name}.obb");
        self.virtual_files.insert(path1, Arc::clone(&arc));
        self.virtual_files.insert(path2, Arc::clone(&arc));
        self.virtual_files.insert(path3, arc);
    }

    /// Mounts a package's private app data directory in VFS (/data/data/{package_name}/)
    pub fn mount_app_data_dir(&mut self, package_name: &str) {
        let base_path = format!("/data/data/{package_name}");
        let user_path = format!("/data/user/0/{package_name}");
        self.add_redirect(&user_path, &base_path);
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

    /// Looks up virtual file content by path after applying path redirections
    pub fn get_file(&self, raw_path: &str) -> Option<Arc<Vec<u8>>> {
        let resolved = self.resolve_path(raw_path);
        self.virtual_files.get(&resolved).cloned()
    }

    /// Opens a virtual file by path, returning a guest file descriptor (>= 3) or -errno
    pub fn open(&mut self, raw_path: &str, flags: u32) -> Result<u32, i32> {
        let resolved = self.resolve_path(raw_path);

        // Special handling for Android /dev/ashmem anonymous shared memory device
        if resolved == "/dev/ashmem" {
            let fd = self.next_fd;
            self.next_fd += 1;
            self.ashmem_regions.insert(
                fd,
                AshmemRegion {
                    fd,
                    name: "dev/ashmem".to_string(),
                    size: 0,
                    prot_mask: 0x7,
                    is_initialized: false,
                    data: Arc::new(std::sync::Mutex::new(Vec::new())),
                },
            );
            return Ok(fd);
        }

        let is_dir = self.list_dir(&resolved).is_some();
        if let Some(content) = self.virtual_files.get(&resolved).cloned() {
            let fd = self.next_fd;
            self.next_fd += 1;
            self.open_fds.insert(
                fd,
                OpenFile {
                    path: resolved,
                    content,
                    cursor: 0,
                    flags,
                },
            );
            Ok(fd)
        } else if is_dir {
            let fd = self.next_fd;
            self.next_fd += 1;
            self.open_fds.insert(
                fd,
                OpenFile {
                    path: resolved,
                    content: Arc::new(Vec::new()),
                    cursor: 0,
                    flags,
                },
            );
            Ok(fd)
        } else {
            Err(ENOENT)
        }
    }

    /// Creates a memory-backed anonymous file (memfd)
    pub fn create_memfd(&mut self, name: &str, _flags: u32) -> Result<u32, i32> {
        let fd = self.next_fd;
        self.next_fd += 1;
        self.ashmem_regions.insert(
            fd,
            AshmemRegion {
                fd,
                name: name.to_string(),
                size: 0,
                prot_mask: 0x7,
                is_initialized: true,
                data: Arc::new(std::sync::Mutex::new(Vec::new())),
            },
        );
        Ok(fd)
    }

    /// Closes an open guest file descriptor
    pub fn close(&mut self, fd: u32) -> Result<(), i32> {
        if self.open_fds.remove(&fd).is_some() || self.ashmem_regions.remove(&fd).is_some() {
            Ok(())
        } else {
            Err(EBADF)
        }
    }

    /// Reads bytes from an open guest file descriptor into a buffer
    pub fn read(&mut self, fd: u32, buf: &mut [u8]) -> Result<usize, i32> {
        if let Some(ashmem) = self.ashmem_regions.get(&fd) {
            if let Ok(lock) = ashmem.data.lock() {
                let available = lock.len().min(buf.len());
                buf[..available].copy_from_slice(&lock[..available]);
                return Ok(available);
            }
        }

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

    /// Writes bytes to an open guest file descriptor (e.g. ashmem / memfd / open file)
    pub fn write(&mut self, fd: u32, buf: &[u8]) -> Result<usize, i32> {
        if let Some(ashmem) = self.ashmem_regions.get_mut(&fd) {
            if let Ok(mut lock) = ashmem.data.lock() {
                let count = buf.len();
                if lock.len() < count {
                    lock.resize(count, 0);
                }
                lock[..count].copy_from_slice(buf);
                return Ok(count);
            }
        }

        if let Some(file) = self.open_fds.get_mut(&fd) {
            let count = buf.len();
            let path = file.path.clone();
            let content = Arc::make_mut(&mut file.content);
            if file.cursor + count > content.len() {
                content.resize(file.cursor + count, 0);
            }
            content[file.cursor..file.cursor + count].copy_from_slice(buf);
            file.cursor += count;
            let updated = Arc::clone(&file.content);
            self.virtual_files.insert(path, updated);
            return Ok(count);
        }

        Err(EBADF)
    }

    /// Handles IOCTL commands (specifically Android ashmem ioctls)
    pub fn ioctl(
        &mut self,
        fd: u32,
        cmd: u32,
        arg: u32,
        mem: &mut dyn Memory,
    ) -> Result<u32, i32> {
        if let Some(ashmem) = self.ashmem_regions.get_mut(&fd) {
            match cmd {
                crate::syscall::ashmem_cmd::ASHMEM_SET_NAME => {
                    let name_addr = GuestAddr::new(arg);
                    if let Ok(name) = read_cstring_from_mem(mem, name_addr, 256) {
                        ashmem.name = name;
                        Ok(0)
                    } else {
                        Err(14) // -EFAULT
                    }
                }
                crate::syscall::ashmem_cmd::ASHMEM_GET_NAME => {
                    let name_addr = GuestAddr::new(arg);
                    let mut bytes = ashmem.name.as_bytes().to_vec();
                    bytes.push(0);
                    if mem.write_bytes(name_addr, &bytes).is_ok() {
                        Ok(0)
                    } else {
                        Err(14) // -EFAULT
                    }
                }
                crate::syscall::ashmem_cmd::ASHMEM_SET_SIZE
                | crate::syscall::ashmem_cmd::ASHMEM_SET_SIZE_64 => {
                    let size = arg as usize;
                    ashmem.size = size;
                    if let Ok(mut lock) = ashmem.data.lock() {
                        lock.resize(size, 0);
                    }
                    ashmem.is_initialized = true;
                    Ok(0)
                }
                crate::syscall::ashmem_cmd::ASHMEM_GET_SIZE => {
                    Ok(ashmem.size as u32)
                }
                crate::syscall::ashmem_cmd::ASHMEM_SET_PROT_MASK
                | crate::syscall::ashmem_cmd::ASHMEM_SET_PROT_MASK_64 => {
                    ashmem.prot_mask = arg;
                    Ok(0)
                }
                crate::syscall::ashmem_cmd::ASHMEM_GET_PROT_MASK => {
                    Ok(ashmem.prot_mask)
                }
                crate::syscall::ashmem_cmd::ASHMEM_IS_INITIALIZED => {
                    Ok(if ashmem.is_initialized { 1 } else { 0 })
                }
                _ => Err(22), // -EINVAL
            }
        } else {
            Err(EBADF)
        }
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

    /// Lists the basenames of virtual files whose paths start with `dir_prefix`.
    /// `dir_prefix` must end with `/` (e.g. `/proc/`).
    /// Returns `None` if no virtual files live under that prefix.
    pub fn list_dir(&self, dir_prefix: &str) -> Option<Vec<String>> {
        let prefix = if dir_prefix.ends_with('/') {
            dir_prefix.to_string()
        } else {
            format!("{}/", dir_prefix)
        };

        let mut names: Vec<String> = self
            .virtual_files
            .keys()
            .filter_map(|path| {
                if path.starts_with(&prefix) {
                    // Take only the immediate child component (one level deep)
                    let rest = &path[prefix.len()..];
                    let component = rest.split('/').next().unwrap_or("");
                    if !component.is_empty() {
                        Some(component.to_string())
                    } else {
                        None
                    }
                } else {
                    None
                }
            })
            .collect();

        // Dedup (multiple files under the same sub-dir produce duplicate dir names)
        names.sort();
        names.dedup();

        if names.is_empty() {
            None
        } else {
            Some(names)
        }
    }

    /// Returns the VFS path associated with an open file descriptor, if any.
    pub fn fd_path(&self, fd: u32) -> Option<String> {
        if let Some(file) = self.open_fds.get(&fd) {
            return Some(file.path.clone());
        }
        None
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
