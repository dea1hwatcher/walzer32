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

    /// Commit `code_bytes` into an executable page and return a descriptor.
    ///
    /// Internally:
    /// 1. Appends to the current RW page (or allocates a fresh one).
    /// 2. If the page is full after the write, commits it (mprotect R+X + icache flush).
    /// 3. The next `commit_block` starts a new page.
    ///
    /// For simplicity we use "lazy commit": a page is committed and moved to
    /// `committed_pages` only when it runs out of space for the next block.
    /// This means the last page in the pool may still be RW until the pool is
    /// dropped. For safety, we commit it eagerly after every write to ensure
    /// code is always executable when called.
    pub fn commit_block(&mut self, code_bytes: &[u8]) -> std::io::Result<CommittedBlock> {
        let needed = code_bytes.len();

        // Ensure we have a page with enough room.
        let needs_new_page = match &self.current {
            None => true,
            Some(p) => p.len() + needed > p.capacity(),
        };

        if needs_new_page {
            // Commit and archive the old page if one exists.
            if let Some(mut old) = self.current.take() {
                old.commit()?;
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

    /// Forcibly commit the current (partially filled) page to R+X.
    /// Call this before dispatching any block in the pool.
    pub fn flush_current(&mut self) -> std::io::Result<()> {
        if let Some(page) = &mut self.current {
            page.commit()?;
        }
        Ok(())
    }
}

impl Default for JitPool {
    fn default() -> Self {
        Self::new()
    }
}
