use std::collections::HashMap;
use walzer32_bridge::{BionicBridge, BionicFuncId, BIONIC_SVC_MAGIC};
use walzer32_core::{CpuState, FlatMemory, GuestAddr, Memory, Reg};
use walzer32_elf::{LoadedLibrary, SymbolBinding, SymbolInfo, SymbolResolver, RTLD_DEFAULT};

#[test]
fn test_bionic_dlopen_and_dlsym() {
    let mut mem = FlatMemory::new(GuestAddr::new(0x1000_0000), 0x20_000);
    let mut bridge = BionicBridge::new(
        GuestAddr::new(0x1000_0000),
        GuestAddr::new(0x1000_2000),
        0x10_000,
    );
    bridge.install_stubs(&mut mem).unwrap();

    let mut cpu = CpuState::new();

    // 1. dlopen(NULL) -> RTLD_DEFAULT
    cpu.set_reg(Reg::R0, 0); // NULL
    cpu.set_reg(Reg::R1, 0);
    bridge
        .handle_svc(BIONIC_SVC_MAGIC | BionicFuncId::Dlopen as u32, &mut cpu, &mut mem)
        .unwrap();
    assert_eq!(cpu.reg(Reg::R0), RTLD_DEFAULT);

    // 2. Register mock DSO "libgame.so" with exported symbol "GameInit"
    let mut syms = HashMap::new();
    syms.insert("GameInit".to_string(), GuestAddr::new(0x5000_1000));
    let mut details = HashMap::new();
    details.insert(
        "GameInit".to_string(),
        vec![SymbolInfo {
            name: "GameInit".to_string(),
            addr: GuestAddr::new(0x5000_1000),
            size: 64,
            binding: SymbolBinding::Global,
            version: None,
            is_default_version: true,
        }],
    );
    let lib = LoadedLibrary {
        load_base: GuestAddr::new(0x5000_0000),
        total_size: 0x4000,
        soname: Some("libgame.so".to_string()),
        needed: Vec::new(),
        entry_point: GuestAddr::new(0x5000_0000),
        init_func: None,
        init_array: Vec::new(),
        fini_array: Vec::new(),
        symbols: syms,
        symbol_details: details,
        tls_template: None,
        ..Default::default()
    };
    let lib_handle = bridge.register_library(lib);

    // 3. dlopen("libgame.so") -> should return lib_handle
    let path_addr = GuestAddr::new(0x1000_5000);
    mem.write_bytes(path_addr, b"libgame.so\0").unwrap();
    cpu.set_reg(Reg::R0, path_addr.as_u32());
    cpu.set_reg(Reg::R1, 0);
    bridge
        .handle_svc(BIONIC_SVC_MAGIC | BionicFuncId::Dlopen as u32, &mut cpu, &mut mem)
        .unwrap();
    assert_eq!(cpu.reg(Reg::R0), lib_handle);

    // 4. dlsym(lib_handle, "GameInit") -> 0x5000_1000
    let sym_addr = GuestAddr::new(0x1000_5020);
    mem.write_bytes(sym_addr, b"GameInit\0").unwrap();
    cpu.set_reg(Reg::R0, lib_handle);
    cpu.set_reg(Reg::R1, sym_addr.as_u32());
    bridge
        .handle_svc(BIONIC_SVC_MAGIC | BionicFuncId::Dlsym as u32, &mut cpu, &mut mem)
        .unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0x5000_1000);

    // 5. dlsym(RTLD_DEFAULT, "malloc") -> resolves Bionic malloc stub
    let malloc_name_addr = GuestAddr::new(0x1000_5040);
    mem.write_bytes(malloc_name_addr, b"malloc\0").unwrap();
    cpu.set_reg(Reg::R0, RTLD_DEFAULT);
    cpu.set_reg(Reg::R1, malloc_name_addr.as_u32());
    bridge
        .handle_svc(BIONIC_SVC_MAGIC | BionicFuncId::Dlsym as u32, &mut cpu, &mut mem)
        .unwrap();
    let malloc_addr = cpu.reg(Reg::R0);
    assert_eq!(malloc_addr, 0x1000_0000 + (BionicFuncId::Malloc as u32) * 8);

    // 6. dlsym(lib_handle, "NonExistent") -> 0 and sets dlerror
    let bogus_name_addr = GuestAddr::new(0x1000_5060);
    mem.write_bytes(bogus_name_addr, b"NonExistent\0").unwrap();
    cpu.set_reg(Reg::R0, lib_handle);
    cpu.set_reg(Reg::R1, bogus_name_addr.as_u32());
    bridge
        .handle_svc(BIONIC_SVC_MAGIC | BionicFuncId::Dlsym as u32, &mut cpu, &mut mem)
        .unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);

    // 7. dlerror() -> returns pointer to error string
    bridge
        .handle_svc(BIONIC_SVC_MAGIC | BionicFuncId::Dlerror as u32, &mut cpu, &mut mem)
        .unwrap();
    let err_ptr = cpu.reg(Reg::R0);
    assert_ne!(err_ptr, 0);

    let mut err_buf = vec![0u8; 32];
    mem.read_bytes(GuestAddr::new(err_ptr), &mut err_buf).unwrap();
    let err_str = String::from_utf8_lossy(&err_buf);
    assert!(err_str.contains("undefined symbol"));

    // 8. Second call to dlerror() returns NULL (cleared)
    bridge
        .handle_svc(BIONIC_SVC_MAGIC | BionicFuncId::Dlerror as u32, &mut cpu, &mut mem)
        .unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);

    // 9. dlclose(lib_handle) -> 0 (success)
    cpu.set_reg(Reg::R0, lib_handle);
    bridge
        .handle_svc(BIONIC_SVC_MAGIC | BionicFuncId::Dlclose as u32, &mut cpu, &mut mem)
        .unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);

    // 10. Test BionicBridge as SymbolResolver for dynamic linker
    assert_eq!(
        bridge.resolve("GameInit"),
        Some(GuestAddr::new(0x5000_1000))
    );
    assert_eq!(
        bridge.resolve("malloc"),
        Some(GuestAddr::new(0x1000_0000 + (BionicFuncId::Malloc as u32) * 8))
    );
    assert_eq!(bridge.resolve("NonExistent"), None);
}
