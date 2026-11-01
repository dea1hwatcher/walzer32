use std::collections::HashMap;
use transd_core::GuestAddr;
use transd_elf::{
    DsoRegistry, LoadedLibrary, SymbolBinding, SymbolInfo, RTLD_DEFAULT, RTLD_NEXT,
};

#[test]
fn test_dso_registry_weak_preemption() {
    let mut registry = DsoRegistry::new();

    // Library 1 (e.g. libweak.so) provides weak symbol "compute"
    let mut syms_lib1 = HashMap::new();
    syms_lib1.insert("compute".to_string(), GuestAddr::new(0x1000));

    let mut details_lib1 = HashMap::new();
    details_lib1.insert(
        "compute".to_string(),
        vec![SymbolInfo {
            name: "compute".to_string(),
            addr: GuestAddr::new(0x1000),
            size: 32,
            binding: SymbolBinding::Weak,
            version: None,
            is_default_version: true,
        }],
    );

    let lib1 = LoadedLibrary {
        load_base: GuestAddr::new(0x1000_0000),
        total_size: 0x2000,
        soname: Some("libweak.so".to_string()),
        needed: Vec::new(),
        entry_point: GuestAddr::new(0x1000_0000),
        init_func: None,
        init_array: Vec::new(),
        fini_array: Vec::new(),
        symbols: syms_lib1,
        symbol_details: details_lib1,
        tls_template: None,
        ..Default::default()
    };
    let h1 = registry.register(lib1);

    // Initial query should return the weak symbol (0x1000)
    assert_eq!(
        registry.dlsym(RTLD_DEFAULT, "compute", None),
        Some(GuestAddr::new(0x1000))
    );

    // Library 2 (e.g. libstrong.so) provides strong global symbol "compute"
    let mut syms_lib2 = HashMap::new();
    syms_lib2.insert("compute".to_string(), GuestAddr::new(0x2000));

    let mut details_lib2 = HashMap::new();
    details_lib2.insert(
        "compute".to_string(),
        vec![SymbolInfo {
            name: "compute".to_string(),
            addr: GuestAddr::new(0x2000),
            size: 48,
            binding: SymbolBinding::Global,
            version: None,
            is_default_version: true,
        }],
    );

    let lib2 = LoadedLibrary {
        load_base: GuestAddr::new(0x2000_0000),
        total_size: 0x4000,
        soname: Some("libstrong.so".to_string()),
        needed: Vec::new(),
        entry_point: GuestAddr::new(0x2000_0000),
        init_func: None,
        init_array: Vec::new(),
        fini_array: Vec::new(),
        symbols: syms_lib2,
        symbol_details: details_lib2,
        tls_template: None,
        ..Default::default()
    };
    let h2 = registry.register(lib2);

    // With lib2 registered, RTLD_DEFAULT should preempt weak 0x1000 with strong 0x2000!
    assert_eq!(
        registry.dlsym(RTLD_DEFAULT, "compute", None),
        Some(GuestAddr::new(0x2000))
    );

    // Querying explicitly by lib1 handle still returns 0x1000
    assert_eq!(registry.dlsym(h1, "compute", None), Some(GuestAddr::new(0x1000)));

    // Querying explicitly by lib2 handle returns 0x2000
    assert_eq!(registry.dlsym(h2, "compute", None), Some(GuestAddr::new(0x2000)));
}

#[test]
fn test_dso_registry_rtld_next() {
    let mut registry = DsoRegistry::new();

    // DSO 1 has hook for "malloc"
    let mut syms1 = HashMap::new();
    syms1.insert("malloc".to_string(), GuestAddr::new(0xAAA0));
    let lib1 = LoadedLibrary {
        load_base: GuestAddr::new(0x1000_0000),
        total_size: 0x1000,
        soname: Some("libhook.so".to_string()),
        needed: Vec::new(),
        entry_point: GuestAddr::new(0),
        init_func: None,
        init_array: Vec::new(),
        fini_array: Vec::new(),
        symbols: syms1,
        symbol_details: HashMap::new(),
        tls_template: None,
        ..Default::default()
    };
    let h1 = registry.register(lib1);

    // DSO 2 has libc "malloc"
    let mut syms2 = HashMap::new();
    syms2.insert("malloc".to_string(), GuestAddr::new(0xBBB0));
    let lib2 = LoadedLibrary {
        load_base: GuestAddr::new(0x2000_0000),
        total_size: 0x1000,
        soname: Some("libc.so".to_string()),
        needed: Vec::new(),
        entry_point: GuestAddr::new(0),
        init_func: None,
        init_array: Vec::new(),
        fini_array: Vec::new(),
        symbols: syms2,
        symbol_details: HashMap::new(),
        tls_template: None,
        ..Default::default()
    };
    let _h2 = registry.register(lib2);

    // RTLD_DEFAULT returns the first match: 0xAAA0
    assert_eq!(
        registry.dlsym(RTLD_DEFAULT, "malloc", None),
        Some(GuestAddr::new(0xAAA0))
    );

    // RTLD_NEXT called from libhook (h1) returns the NEXT definition: 0xBBB0
    assert_eq!(
        registry.dlsym(RTLD_NEXT, "malloc", Some(h1)),
        Some(GuestAddr::new(0xBBB0))
    );
}

#[test]
fn test_gnu_symbol_version_resolution() {
    let mut details = HashMap::new();
    details.insert(
        "fopen".to_string(),
        vec![
            SymbolInfo {
                name: "fopen".to_string(),
                addr: GuestAddr::new(0x3010),
                size: 20,
                binding: SymbolBinding::Global,
                version: Some("LIBC".to_string()),
                is_default_version: false,
            },
            SymbolInfo {
                name: "fopen".to_string(),
                addr: GuestAddr::new(0x3020),
                size: 24,
                binding: SymbolBinding::Global,
                version: Some("LIBC_PRIVATE".to_string()),
                is_default_version: true,
            },
        ],
    );

    let lib = LoadedLibrary {
        load_base: GuestAddr::new(0x3000_0000),
        total_size: 0x5000,
        soname: Some("libc.so".to_string()),
        needed: Vec::new(),
        entry_point: GuestAddr::new(0),
        init_func: None,
        init_array: Vec::new(),
        fini_array: Vec::new(),
        symbols: HashMap::new(),
        symbol_details: details,
        tls_template: None,
        ..Default::default()
    };

    // Unversioned query defaults to default version (LIBC_PRIVATE -> 0x3020)
    assert_eq!(lib.find_symbol("fopen"), Some(GuestAddr::new(0x3020)));

    // Explicit version in function name
    assert_eq!(
        lib.find_symbol("fopen@LIBC"),
        Some(GuestAddr::new(0x3010))
    );
    assert_eq!(
        lib.find_symbol("fopen@@LIBC_PRIVATE"),
        Some(GuestAddr::new(0x3020))
    );
    assert_eq!(lib.find_symbol("fopen@UNKNOWN"), None);
}
