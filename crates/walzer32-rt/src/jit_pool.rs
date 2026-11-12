/// JitPool — manages a growable pool of executable JIT pages.
///
/// Each compiled block is appended into the current page; when the page is
/// full a fresh one is allocated. Once committed, a block's code is immutable
/// (the page switches to R+X). If the block ever needs re-compilation the old
/// allocation is kept (pages are never partially freed) and the new version
/// gets a new slot — the JitCache entry is simply replaced.
///
/// On x86-64 dev-host (Windows) a single PAGE_EXECUTE_READWRITE region is
/// used; the actual `flush_icache` is a no-op there.

use crate::jit_memory::{JitPage, PAGE_SIZE};
#[cfg(unix)]
use crate::jit_memory::flush_icache;

/// Address of a compiled block in the host process address space.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostCodePtr(pub *const u8);

unsafe impl Send for HostCodePtr {}
unsafe impl Sync for HostCodePtr {}

/// Descriptor returned after committing a compiled block into the pool.
#[derive(Debug, Clone)]
pub struct CommittedBlock {
    /// Pointer to the start of the AArch64 machine code for this block.
    pub code_ptr: HostCodePtr,
    /// Byte length of the code.
    pub code_len: usize,
}

impl CommittedBlock {
    /// Cast to a C function pointer suitable for direct dispatch.
    ///
    /// # Safety
    /// The code at `code_ptr` must be valid AArch64 with the expected ABI.
    pub unsafe fn as_fn<F: Copy>(&self) -> F {
        let addr = self.code_ptr.0 as usize;
        unsafe { std::mem::transmute_copy(&addr) }
    }
}

/// Page allocation unit size: 64 KB gives ample room for many blocks per page
/// while keeping `mmap` call frequency low.
const POOL_PAGE_SIZE: usize = PAGE_SIZE * 16; // 64 KB

pub struct JitPool {
    /// Active (writable, not yet committed) page.
    current: Option<JitPage>,
    /// Committed (R+X) pages — kept alive so their code pointers remain valid.
    committed_pages: Vec<JitPage>,
    /// Total bytes of code committed.
    pub total_bytes: usize,
}

impl JitPool {
    pub fn new() -> Self {
        Self {
            current: None,
            committed_pages: Vec::new(),
            total_bytes: 0,
        }
    }

    /// Number of backing JIT pages currently managed by the pool (active + archived).
    pub fn page_count(&self) -> usize {
        self.committed_pages.len() + usize::from(self.current.is_some())
    }

    /// Total bytes of compiled machine code currently allocated in the pool
    pub fn allocated_bytes(&self) -> usize {
        self.total_bytes
    }

    /// Commit `code_bytes` into an executable page and return a descriptor.
    ///
    /// Appends into the active page while capacity remains (and dual-mapping or host RWX
    /// allows live appends after execution). When the active page fills up or requires
    /// W^X `mprotect` commitment, it is archived into `committed_pages` and a fresh page
    /// is allocated.
    pub fn commit_block(&mut self, code_bytes: &[u8]) -> std::io::Result<CommittedBlock> {
        let needed = code_bytes.len();

        // Ensure we have a page with enough room.
        let needs_new_page = match &self.current {
            None => true,
            Some(p) => (p.is_committed() && !p.supports_live_append()) || (p.len() + needed > p.capacity()),
        };

        if needs_new_page {
            // Commit and archive the old page if one exists.
            if let Some(mut old) = self.current.take() {
                if !old.is_committed() {
                    old.commit()?;
                }
                self.committed_pages.push(old);
            }
            // Allocate a fresh page large enough for at least this block.
            let page_size = POOL_PAGE_SIZE.max(needed.next_power_of_two().max(PAGE_SIZE));
            self.current = Some(JitPage::allocate(page_size)?);
        }

        let page = self.current.as_mut().unwrap();
        let offset = page.write(code_bytes)?;

        // Eagerly flush I-cache for this specific range so the block is
        // immediately callable. Full mprotect → R+X happens when page is full.
        #[cfg(unix)]
        {
            // Get base pointer via offset arithmetic from a known-safe index.
            // SAFETY: offset was just returned by page.write(); it is valid.
            let base_ptr = unsafe {
                // We need the raw pointer of the page — expose via a helper.
                page.code_ptr_at(offset)
            };
            flush_icache(base_ptr as *mut u8, code_bytes.len());
        }

        // On Windows dev host the page is EXECUTE_READWRITE — callable as-is.

        let code_ptr = HostCodePtr(unsafe { page.code_ptr_at(offset) });
        self.total_bytes += code_bytes.len();

        Ok(CommittedBlock {
            code_ptr,
            code_len: code_bytes.len(),
        })
    }

    /// Forcibly commit the current (partially filled) page to R+X if it cannot accept
    /// live appends while remaining executable. Call this before dispatching any block in the pool.
    pub fn flush_current(&mut self) -> std::io::Result<()> {
        if let Some(page) = &self.current {
            if page.supports_live_append() {
                return Ok(());
            }
        }
        if let Some(mut page) = self.current.take() {
            if !page.is_committed() {
                page.commit()?;
            }
            self.committed_pages.push(page);
        }
        Ok(())
    }

    /// Patches machine code at the given executable host address using dual mapping or W^X toggling
    /// # Safety
    /// host_rx_ptr must point to an executable JIT block allocated by this pool.
    pub unsafe fn patch_code(
        &mut self,
        host_rx_ptr: *const u8,
        byte_offset: usize,
        patch_fn: impl FnOnce(&mut [u8]),
    ) -> bool {
        for page in self.current.iter().chain(self.committed_pages.iter()) {
            if page.contains_rx_ptr(host_rx_ptr) {
                return unsafe { page.patch_bytes(host_rx_ptr, byte_offset, 4, patch_fn) };
            }
        }
        false
    }
}

impl Default for JitPool {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_jit_pool_packs_blocks_across_flushes() {
        let mut pool = JitPool::new();
        let block = [0u8; 256];

        let first = pool.commit_block(&block).unwrap();
        pool.flush_current().unwrap();
        let second = pool.commit_block(&block).unwrap();
        pool.flush_current().unwrap();

        assert_eq!(pool.allocated_bytes(), 512);
        assert_eq!(pool.page_count(), 1);
        assert_eq!(
            (second.code_ptr.0 as usize) - (first.code_ptr.0 as usize),
            block.len()
        );
    }
}
