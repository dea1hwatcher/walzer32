use walzer32_bridge::{invoke_guest_full, BionicBridge, BionicFuncId, JniBridge};
use walzer32_core::{ArenaMemory, GuestAddr, Memory, PROT_READ};
use walzer32_rt::DbtEngine;

#[test]
fn test_bionic_mprotect_bridge_call() {
    let mut arena = ArenaMemory::new().expect("Failed to allocate 4GB virtual arena");
    let stub_base = GuestAddr::new(0x1000);
    let heap_base = GuestAddr::new(0x3000);
    let target_page = GuestAddr::new(0x7000);
    arena.commit_range(stub_base, 0x10000).unwrap();

    let mut bionic = BionicBridge::new(stub_base, heap_base, 0x2000);
    bionic.install_stubs(&mut arena).unwrap();

    let mut engine = DbtEngine::new(arena);

    // Call mprotect(target_page, 4096, PROT_READ) via bionic stub
    let mprotect_stub = bionic.stub_base.add((BionicFuncId::Mprotect as u32) * 8);
    let args = [target_page.as_u32(), 4096, PROT_READ];

    let mut jni = JniBridge::new(GuestAddr::new(0x9000));
    let res = invoke_guest_full(&mut engine, &mut bionic, &mut jni, None, mprotect_stub, &args).unwrap();
    assert_eq!(res, 0); // 0 = Success

    assert_eq!(engine.mem.get_protection(target_page), PROT_READ);
    assert!(engine.mem.write_u32(target_page, 0x42).is_err());
}
