pub mod fixups;
pub mod header;
pub mod loader;
pub mod parser;

pub use fixups::{sanitize_elf_headers, ElfFixupReport};
pub use header::*;
pub use loader::{
    CompositeResolver, DsoRegistry, ElfLoader, LoadedLibrary, LoaderError, NullResolver,
    SymbolBinding, SymbolInfo, SymbolResolver, TlsTemplateInfo,
};
pub use parser::{ElfError, ElfParser};
