use std::collections::HashMap;
use transd_core::GuestAddr;
use transd_emitter_a64::{CompiledBlock, PatchTarget};

/// Direct JIT Code Cache managing compiled blocks and inter-block jump chaining
#[derive(Default)]
pub struct JitCache {
    /// Mapping from Guest entry address to compiled block metadata
    pub blocks: HashMap<GuestAddr, CompiledBlock>,
    /// Control-flow graph edges (source guest address -> target guest addresses)
    pub outgoing_edges: HashMap<GuestAddr, Vec<GuestAddr>>,
    /// Hit, miss, and chaining statistics
    pub hits: u64,
    pub misses: u64,
    pub chained_jumps: u64,
}

impl JitCache {
    pub fn new() -> Self {
        Self::default()
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

    pub fn insert(&mut self, addr: GuestAddr, block: CompiledBlock) {
        self.blocks.insert(addr, block);
        self.resolve_chaining_for(addr);
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
                    self.chained_jumps += 1;
                }
            }
        }
    }

    pub fn invalidate(&mut self, addr: GuestAddr) {
        self.blocks.remove(&addr);
        self.outgoing_edges.remove(&addr);
    }

    pub fn clear(&mut self) {
        self.blocks.clear();
        self.outgoing_edges.clear();
        self.chained_jumps = 0;
    }

    pub fn count(&self) -> usize {
        self.blocks.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use transd_emitter_a64::PatchSite;
    use transd_ir::BlockExit;

    #[test]
    fn test_jit_cache_chaining() {
        let mut cache = JitCache::new();

        // Block A at 0x1000 jumps to Block B at 0x1020
        let block_a = CompiledBlock {
            guest_entry: GuestAddr::new(0x1000),
            is_thumb: false,
            code_bytes: vec![0; 16],
            inst_count: 3,
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
            patch_sites: vec![],
            exit: BlockExit::Direct(GuestAddr::new(0x1040)),
        };

        // Insert Block B -> should automatically resolve incoming edge from Block A!
        cache.insert(GuestAddr::new(0x1020), block_b);
        assert!(cache.chained_jumps >= 1);
        assert!(cache.outgoing_edges.get(&GuestAddr::new(0x1000)).unwrap().contains(&GuestAddr::new(0x1020)));
    }
}
