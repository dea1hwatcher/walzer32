#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
#[repr(transparent)]
pub struct GuestAddr(pub u32);

impl GuestAddr {
    #[inline(always)]
    pub const fn new(addr: u32) -> Self {
        Self(addr)
    }

    #[inline(always)]
    pub const fn as_u32(self) -> u32 {
        self.0
    }

    #[inline(always)]
    pub const fn as_usize(self) -> usize {
        self.0 as usize
    }

    #[inline(always)]
    pub const fn offset(self, off: i32) -> Self {
        Self(self.0.wrapping_add(off as u32))
    }

    #[inline(always)]
    pub const fn add(self, bytes: u32) -> Self {
        Self(self.0.wrapping_add(bytes))
    }

    #[inline(always)]
    pub const fn sub(self, bytes: u32) -> Self {
        Self(self.0.wrapping_sub(bytes))
    }

    #[inline(always)]
    pub const fn is_aligned_to(self, align: u32) -> bool {
        (self.0 & (align - 1)) == 0
    }

    /// Masks out the Thumb bit (bit 0) to get the aligned instruction address
    #[inline(always)]
    pub const fn instruction_addr(self) -> Self {
        Self(self.0 & !1)
    }

    /// Checks if this address points to Thumb mode (bit 0 is 1)
    #[inline(always)]
    pub const fn is_thumb(self) -> bool {
        (self.0 & 1) != 0
    }
}

impl std::fmt::Display for GuestAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "0x{:08x}", self.0)
    }
}

impl std::fmt::LowerHex for GuestAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:08x}", self.0)
    }
}

impl From<u32> for GuestAddr {
    #[inline(always)]
    fn from(val: u32) -> Self {
        Self(val)
    }
}

impl From<GuestAddr> for u32 {
    #[inline(always)]
    fn from(addr: GuestAddr) -> Self {
        addr.0
    }
}
