use std::collections::{HashMap, HashSet};
use walzer32_core::GuestAddr;
use walzer32_emitter_a64::{CompiledBlock, PatchTarget};
use crate::jit_memory::flush_icache;
use crate::jit_pool::HostCodePtr;

/// Direct JIT Code Cache managing compiled blocks, inter-block jump chaining,
/// page tracking for Self-Modifying Code (SMC), and reverse unchaining.
#[derive(Default)]
pub struct JitCache {
    /// Mapping from Guest entry address to compiled block metadata
    pub blocks: HashMap<GuestAddr, CompiledBlock>,
    /// Mapping from Guest entry address to executable code pointer in JIT pool
    pub code_ptrs: HashMap<GuestAddr, HostCodePtr>,
    /// Control-flow graph edges (source guest address -> target guest addresses)
    pub outgoing_edges: HashMap<GuestAddr, Vec<GuestAddr>>,
    /// Reverse control-flow graph edges (target guest address -> set of source guest addresses)
    pub incoming_edges: HashMap<GuestAddr, HashSet<GuestAddr>>,
    /// Page table mapping 4KB page PFN (`addr >> 12`) to guest block entry addresses spanning that page
    pub page_to_blocks: HashMap<u32, HashSet<GuestAddr>>,
    /// Hit, miss, and chaining statistics
    pub hits: u64,
    pub misses: u64,
    pub chained_jumps: u64,
    pub unchained_jumps: u64,
    pub smc_invalidations: u64,
    /// Execution profile hit counters per guest block address
    pub exec_counts: HashMap<GuestAddr, u32>,
    /// Tier-2 compiled Superblocks (multi-block optimized traces)
    pub superblocks: HashMap<GuestAddr, CompiledBlock>,
    /// Tier-2 statistics
    pub tier2_dispatches: u64,
    pub tier2_compilations: u64,
}

impl JitCache {
    pub const HOT_THRESHOLD: u32 = 20;

    pub fn new() -> Self {
        Self::default()
    }

    /// Records block execution and returns true if it reaches the hotness threshold
    #[inline]
    pub fn record_exec(&mut self, addr: GuestAddr) -> bool {
        let count = self.exec_counts.entry(addr).or_insert(0);
        *count = count.saturating_add(1);
        *count == Self::HOT_THRESHOLD
    }

    /// Checks if a guest address has already been compiled into a Tier-2 Superblock
    #[inline]
    pub fn has_superblock(&self, addr: GuestAddr) -> bool {
        self.superblocks.contains_key(&addr)
    }

    /// Inserts a compiled Tier-2 Superblock, seamlessly replacing the Tier-1 block
    pub fn insert_superblock(&mut self, addr: GuestAddr, block: CompiledBlock, ptr: HostCodePtr) {
        self.tier2_compilations += 1;
        self.code_ptrs.insert(addr, ptr);
        self.register_pages_for(addr, block.guest_byte_size);
        self.superblocks.insert(addr, block.clone());
        self.blocks.insert(addr, block);
        self.resolve_chaining_for(addr);
    }

    #[inline(always)]
    pub fn lookup(&mut self, addr: GuestAddr) -> Option<&CompiledBlock> {
        if let Some(block) = self.blocks.get(&addr) {
            self.hits += 1;
            Some(block)
        } else {
            self.misses += 1;
            None
        }
    }

    #[inline(always)]
    pub fn peek(&self, addr: GuestAddr) -> Option<&CompiledBlock> {
        self.blocks.get(&addr)
    }

    #[inline(always)]
    pub fn peek_ptr(&self, addr: GuestAddr) -> Option<HostCodePtr> {
        self.code_ptrs.get(&addr).copied()
    }

    #[inline(always)]
    pub fn lookup_ptr(&mut self, addr: GuestAddr) -> Option<HostCodePtr> {
        self.code_ptrs.get(&addr).copied()
    }

    pub fn insert(&mut self, addr: GuestAddr, block: CompiledBlock) {
        self.register_pages_for(addr, block.guest_byte_size);
        self.blocks.insert(addr, block);
        self.resolve_chaining_for(addr);
    }

    pub fn insert_committed(&mut self, addr: GuestAddr, block: CompiledBlock, ptr: HostCodePtr) {
        self.code_ptrs.insert(addr, ptr);
        self.register_pages_for(addr, block.guest_byte_size);
        self.blocks.insert(addr, block);
        self.resolve_chaining_for(addr);
    }

    fn register_pages_for(&mut self, addr: GuestAddr, size: usize) {
        let start_page = addr.as_u32() >> 12;
        let end_addr = addr.as_u32().saturating_add(size.max(1) as u32 - 1);
        let end_page = end_addr >> 12;
        for pfn in start_page..=end_page {
            self.page_to_blocks.entry(pfn).or_default().insert(addr);
        }
    }

    fn unregister_pages_for(&mut self, addr: GuestAddr, size: usize) {
        let start_page = addr.as_u32() >> 12;
        let end_addr = addr.as_u32().saturating_add(size.max(1) as u32 - 1);
        let end_page = end_addr >> 12;
        for pfn in start_page..=end_page {
            if let Some(set) = self.page_to_blocks.get_mut(&pfn) {
                set.remove(&addr);
            }
            if self.page_to_blocks.get(&pfn).is_some_and(|s| s.is_empty()) {
                self.page_to_blocks.remove(&pfn);
            }
        }
    }

    /// Resolves block chaining links whenever a new block is added
    pub fn resolve_chaining_for(&mut self, addr: GuestAddr) {
        let mut new_edges = Vec::new();

        if let Some(block) = self.blocks.get(&addr) {
            for site in &block.patch_sites {
                let target_addr = match site.target {
                    PatchTarget::Direct(t) => t,
                    PatchTarget::BranchTaken { target, .. } => target,
                    PatchTarget::BranchFallthrough(t) => t,
                };
                if self.blocks.contains_key(&target_addr) {
                    new_edges.push(target_addr);
                    self.incoming_edges.entry(target_addr).or_default().insert(addr);
                    self.chained_jumps += 1;
                }
            }
        }

        if !new_edges.is_empty() {
            self.outgoing_edges.insert(addr, new_edges);
        }

        // Also check if any existing blocks were waiting to chain TO this new block
        for (&src_addr, src_block) in &self.blocks {
            if src_addr == addr {
                continue;
            }
            for site in &src_block.patch_sites {
                let target_addr = match site.target {
                    PatchTarget::Direct(t) => t,
                    PatchTarget::BranchTaken { target, .. } => target,
                    PatchTarget::BranchFallthrough(t) => t,
                };
                if target_addr == addr {
                    self.outgoing_edges.entry(src_addr).or_default().push(addr);
                    self.incoming_edges.entry(addr).or_default().insert(src_addr);
                    self.chained_jumps += 1;
                }
            }
        }
    }

    /// Unchains all caller blocks that have direct branches jumping to `target`.
    /// Restores the original fallback exit stub in executable memory and flushes instruction cache.
    pub fn unchain_incoming(&mut self, target: GuestAddr) {
        if let Some(callers) = self.incoming_edges.remove(&target) {
            for src_addr in callers {
                if let (Some(src_block), Some(src_ptr)) = (self.blocks.get(&src_addr), self.code_ptrs.get(&src_addr)) {
                    for site in &src_block.patch_sites {
                        let site_target = match site.target {
                            PatchTarget::Direct(t) => t,
                            PatchTarget::BranchTaken { target: t, .. } => t,
                            PatchTarget::BranchFallthrough(t) => t,
                        };
                        if site_target == target && site.byte_offset + 4 <= src_block.code_bytes.len() {
                            unsafe {
                                let dest = (src_ptr.0 as usize + site.byte_offset) as *mut u8;
                                std::ptr::copy_nonoverlapping(
                                    src_block.code_bytes[site.byte_offset..].as_ptr(),
                                    dest,
                                    4,
                                );
                                flush_icache(dest, 4);
                            }
                            self.unchained_jumps += 1;
                        }
                    }
                }
                if let Some(out) = self.outgoing_edges.get_mut(&src_addr) {
                    out.retain(|&dst| dst != target);
                }
            }
        }
    }

    /// Invalidates a single basic block by address, unchaining any incoming jumps
    pub fn invalidate_block(&mut self, addr: GuestAddr) -> bool {
        self.unchain_incoming(addr);

        if let Some(targets) = self.outgoing_edges.remove(&addr) {
            for target in targets {
                if let Some(incoming) = self.incoming_edges.get_mut(&target) {
                    incoming.remove(&addr);
                }
            }
        }

        self.superblocks.remove(&addr);
        self.exec_counts.remove(&addr);

        if let Some(block) = self.blocks.remove(&addr) {
            self.unregister_pages_for(addr, block.guest_byte_size);
            self.code_ptrs.remove(&addr);
            self.smc_invalidations += 1;
            true
        } else {
            self.code_ptrs.remove(&addr);
            false
        }
    }

    /// Invalidates any compiled blocks overlapping the guest address range `[start, start + len)`
    pub fn invalidate_range(&mut self, start: GuestAddr, len: usize) -> usize {
        if len == 0 {
            return 0;
        }
        let end = start.as_u32().saturating_add(len as u32);
        let start_page = start.as_u32() >> 12;
        let end_page = (end.saturating_sub(1)) >> 12;

        let mut candidate_blocks = HashSet::new();
        for pfn in start_page..=end_page {
            if let Some(set) = self.page_to_blocks.get(&pfn) {
                candidate_blocks.extend(set.iter().copied());
            }
        }

        let mut count = 0;
        for entry in candidate_blocks {
            if let Some(block) = self.blocks.get(&entry) {
                let block_start = entry.as_u32();
                let block_end = block_start.saturating_add(block.guest_byte_size.max(1) as u32);
                if block_start < end && block_end > start.as_u32() && self.invalidate_block(entry) {
                    count += 1;
                }
            }
        }
        count
    }

    /// Invalidates all blocks residing on a specific 4KB page
    pub fn invalidate_page(&mut self, pfn: u32) -> usize {
        let blocks = self.page_to_blocks.get(&pfn).cloned();
        let mut count = 0;
        if let Some(blocks) = blocks {
            for addr in blocks {
                if self.invalidate_block(addr) {
                    count += 1;
                }
            }
        }
        count
    }

    /// Returns true if the given 4KB page contains compiled JIT blocks
    pub fn is_code_page(&self, pfn: u32) -> bool {
        self.page_to_blocks.contains_key(&pfn)
    }

    /// Legacy invalidate wrapper
    pub fn invalidate(&mut self, addr: GuestAddr) {
        self.invalidate_block(addr);
    }

    pub fn clear(&mut self) {
        let addrs: Vec<GuestAddr> = self.blocks.keys().copied().collect();
        for addr in addrs {
            self.unchain_incoming(addr);
        }
        self.blocks.clear();
        self.superblocks.clear();
        self.exec_counts.clear();
        self.code_ptrs.clear();
        self.outgoing_edges.clear();
        self.incoming_edges.clear();
        self.page_to_blocks.clear();
        self.chained_jumps = 0;
    }

    pub fn count(&self) -> usize {
        self.blocks.len()
    }
}

/// Thread-safe concurrent wrapper around JitCache for multi-threaded DBT execution
#[derive(Clone, Default)]
pub struct ConcurrentJitCache {
    inner: std::sync::Arc<std::sync::RwLock<JitCache>>,
}

impl ConcurrentJitCache {
    pub fn new() -> Self {
        Self {
            inner: std::sync::Arc::new(std::sync::RwLock::new(JitCache::new())),
        }
    }

    pub fn lookup(&self, addr: GuestAddr) -> Option<CompiledBlock> {
        let mut cache = self.inner.write().unwrap();
        cache.lookup(addr).cloned()
    }

    pub fn lookup_ptr(&self, addr: GuestAddr) -> Option<HostCodePtr> {
        let mut cache = self.inner.write().unwrap();
        cache.lookup_ptr(addr)
    }

    pub fn insert(&self, addr: GuestAddr, block: CompiledBlock) {
        let mut cache = self.inner.write().unwrap();
        cache.insert(addr, block);
    }

    pub fn insert_committed(&self, addr: GuestAddr, block: CompiledBlock, ptr: HostCodePtr) {
        let mut cache = self.inner.write().unwrap();
        cache.insert_committed(addr, block, ptr);
    }

    pub fn invalidate_block(&self, addr: GuestAddr) -> bool {
        let mut cache = self.inner.write().unwrap();
        cache.invalidate_block(addr)
    }

    pub fn invalidate_range(&self, start: GuestAddr, len: usize) -> usize {
        let mut cache = self.inner.write().unwrap();
        cache.invalidate_range(start, len)
    }

    pub fn invalidate_page(&self, pfn: u32) -> usize {
        let mut cache = self.inner.write().unwrap();
        cache.invalidate_page(pfn)
    }

    pub fn is_code_page(&self, pfn: u32) -> bool {
        let cache = self.inner.read().unwrap();
        cache.is_code_page(pfn)
    }

    pub fn count(&self) -> usize {
        self.inner.read().unwrap().count()
    }

    pub fn clear(&self) {
        self.inner.write().unwrap().clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use walzer32_emitter_a64::PatchSite;
    use walzer32_ir::BlockExit;

    #[test]
    fn test_jit_cache_chaining() {
        let mut cache = JitCache::new();

        // Block A at 0x1000 jumps to Block B at 0x1020
        let block_a = CompiledBlock {
            guest_entry: GuestAddr::new(0x1000),
            is_thumb: false,
            code_bytes: vec![0; 16],
            inst_count: 3,
            guest_byte_size: 16,
            patch_sites: vec![PatchSite {
                byte_offset: 12,
                target: PatchTarget::Direct(GuestAddr::new(0x1020)),
            }],
            exit: BlockExit::Direct(GuestAddr::new(0x1020)),
        };

        // Insert Block A (Block B not yet in cache)
        cache.insert(GuestAddr::new(0x1000), block_a);
        assert_eq!(cache.chained_jumps, 0);

        // Block B at 0x1020
        let block_b = CompiledBlock {
            guest_entry: GuestAddr::new(0x1020),
            is_thumb: false,
            code_bytes: vec![0; 16],
            inst_count: 2,
            guest_byte_size: 16,
            patch_sites: vec![],
            exit: BlockExit::Direct(GuestAddr::new(0x1040)),
        };

        // Insert Block B -> should automatically resolve incoming edge from Block A!
        cache.insert(GuestAddr::new(0x1020), block_b);
        assert!(cache.chained_jumps >= 1);
        assert!(cache.outgoing_edges.get(&GuestAddr::new(0x1000)).unwrap().contains(&GuestAddr::new(0x1020)));
        assert!(cache.incoming_edges.get(&GuestAddr::new(0x1020)).unwrap().contains(&GuestAddr::new(0x1000)));
    }

    #[test]
    fn test_jit_cache_smc_range_and_unchaining() {
        let mut cache = JitCache::new();

        let block_a = CompiledBlock {
            guest_entry: GuestAddr::new(0x2000),
            is_thumb: false,
            code_bytes: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
            inst_count: 4,
            guest_byte_size: 16,
            patch_sites: vec![PatchSite {
                byte_offset: 12,
                target: PatchTarget::Direct(GuestAddr::new(0x2030)),
            }],
            exit: BlockExit::Direct(GuestAddr::new(0x2030)),
        };

        let block_b = CompiledBlock {
            guest_entry: GuestAddr::new(0x2030),
            is_thumb: false,
            code_bytes: vec![20; 16],
            inst_count: 4,
            guest_byte_size: 16,
            patch_sites: vec![],
            exit: BlockExit::Direct(GuestAddr::new(0x2080)),
        };

        let mut fake_jit_mem = vec![0u8; 64];
        let ptr_a = HostCodePtr(fake_jit_mem.as_mut_ptr());

        cache.insert_committed(GuestAddr::new(0x2000), block_a, ptr_a);
        cache.insert(GuestAddr::new(0x2030), block_b);

        assert_eq!(cache.count(), 2);
        assert!(cache.is_code_page(0x2000 >> 12));
        assert!(cache.outgoing_edges.get(&GuestAddr::new(0x2000)).unwrap().contains(&GuestAddr::new(0x2030)));

        // Now guest modifies code at 0x2034 (inside Block B: 0x2030..0x2040)
        let invalidated = cache.invalidate_range(GuestAddr::new(0x2034), 4);
        assert_eq!(invalidated, 1);
        assert_eq!(cache.count(), 1);
        assert!(cache.lookup(GuestAddr::new(0x2030)).is_none());
        assert!(cache.lookup(GuestAddr::new(0x2000)).is_some());

        // Verify incoming edges to 0x2030 were cleared and outgoing edge from 0x2000 was removed
        assert!(cache.incoming_edges.get(&GuestAddr::new(0x2030)).is_none());
        assert!(cache.outgoing_edges.get(&GuestAddr::new(0x2000)).unwrap().is_empty());
    }
}
