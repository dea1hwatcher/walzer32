use std::collections::HashMap;
use transd_core::GuestAddr;
use transd_emitter_a64::CompiledBlock;

/// JIT Code Cache managing compiled blocks
#[derive(Default)]
pub struct JitCache {
    /// Mapping from Guest entry address to compiled block metadata
    blocks: HashMap<GuestAddr, CompiledBlock>,
    /// Hit and miss statistics
    pub hits: u64,
    pub misses: u64,
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
    }

    pub fn invalidate(&mut self, addr: GuestAddr) {
        self.blocks.remove(&addr);
    }

    pub fn clear(&mut self) {
        self.blocks.clear();
    }

    pub fn count(&self) -> usize {
        self.blocks.len()
    }
}
