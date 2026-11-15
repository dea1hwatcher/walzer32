use walzer32_android::Walzer32Session;
use walzer32_core::{GuestAddr, Memory, Reg};

fn get_test_lib(name: &str) -> Option<Vec<u8>> {
    let candidates = [
        format!("/data/local/tmp/test_libs/{}", name),
        format!("test_libs/{}", name),
        format!("../../test_libs/{}", name),
    ];
    for c in &candidates {
        if let Ok(bytes) = std::fs::read(c) {
            return Some(bytes);
        }
    }
    None
}

#[test]
fn test_repro_objc_alignof_and_sel_register() {
    let bytes = match get_test_lib("libobjc.so") {
        Some(b) => b,
        None => {
            eprintln!("Skipping test: test_libs/libobjc.so not found");
            return;
        }
    };
    let mut session = Walzer32Session::new(GuestAddr::new(0x7000_0000), 0x800_0000).expect("session new");
    let lib = session.load_library_bytes("libobjc.so", &bytes).expect("load libobjc");

    let align_sym = lib.find_symbol("objc_alignof_type").expect("find objc_alignof_type");
    let sel_reg_sym = lib.find_symbol("sel_register_typed_name").expect("find sel_register_typed_name");
    println!("objc_alignof_type at 0x{:08x}, sel_register_typed_name at 0x{:08x}", align_sym.as_u32(), sel_reg_sym.as_u32());

    let test_strings = [
        b"^{?=L^@^L[5L]}8^@12I16\0".as_slice(),
        b"{?=L^@^L[5L]}8^@12I16\0".as_slice(),
        b"I20@0:4^{?=L^@^L[5L]}8^@12I16\0".as_slice(),
    ];

    for s in test_strings {
        let str_addr = GuestAddr::new(0x7005_0000);
        session.engine.mem.write_bytes(str_addr, s).unwrap();

        let sp = GuestAddr::new(0x7004_f000);
        let lr = GuestAddr::new(0xdead_dead);
        session.engine.cpu.set_sp(sp.as_u32());
        session.engine.cpu.set_lr(lr.as_u32());
        session.engine.cpu.set_reg(Reg::R0, str_addr.as_u32());
        session.engine.cpu.set_reg(Reg::R1, 0);
        session.engine.cpu.set_reg(Reg::R2, 0);
        session.engine.cpu.set_reg(Reg::R3, 0);
        session.engine.cpu.set_reg(Reg::R4, 0);
        session.engine.cpu.set_reg(Reg::R5, 0);
        session.engine.cpu.set_reg(Reg::R6, 0);
        session.engine.cpu.set_reg(Reg::R7, 0);
        session.engine.cpu.set_reg(Reg::R8, 0);

        let entry_pc = GuestAddr::new(align_sym.as_u32() & !1);
        session.engine.cpu.set_pc(entry_pc);
        session.engine.cpu.set_thumb((align_sym.as_u32() & 1) != 0);

        println!("Testing objc_alignof_type on '{}'...", std::str::from_utf8(s).unwrap().trim_end_matches('\0'));
        let res = session.engine.run(100_000);
        println!("  Result: pc=0x{:08x} r0={}", session.engine.cpu.pc().as_u32(), session.engine.cpu.reg(Reg::R0));
    }

    // Now test sel_register_typed_name(name, type)
    let name_addr = GuestAddr::new(0x7006_0000);
    session.engine.mem.write_bytes(name_addr, b"countByEnumeratingWithState:objects:count:\0").unwrap();
    let type_addr = GuestAddr::new(0x7006_1000);
    session.engine.mem.write_bytes(type_addr, b"I20@0:4^{?=L^@^L[5L]}8^@12I16\0").unwrap();

    let sp = GuestAddr::new(0x7004_f000);
    let lr = GuestAddr::new(0xdead_dead);
    session.engine.cpu.set_sp(sp.as_u32());
    session.engine.cpu.set_lr(lr.as_u32());
    session.engine.cpu.set_reg(Reg::R0, name_addr.as_u32());
    session.engine.cpu.set_reg(Reg::R1, type_addr.as_u32());
    session.engine.cpu.set_reg(Reg::R2, 0);
    session.engine.cpu.set_reg(Reg::R3, 0);

    let entry_pc = GuestAddr::new(sel_reg_sym.as_u32() & !1);
    session.engine.cpu.set_pc(entry_pc);
    session.engine.cpu.set_thumb((sel_reg_sym.as_u32() & 1) != 0);

    println!("Testing sel_register_typed_name...");
    let res = session.engine.run(100_000);
    println!("  sel_register_typed_name Result: pc=0x{:08x} r0=0x{:08x} err={:?}",
        session.engine.cpu.pc().as_u32(), session.engine.cpu.reg(Reg::R0), res.err());
}

#[test]
fn test_inspect_block_c3d2c() {
    let bytes = match get_test_lib("libcocos2d.so") {
        Some(b) => b,
        None => {
            eprintln!("Skipping test: test_libs/libcocos2d.so not found");
            return;
        }
    };
    let base = GuestAddr::new(0x717f_0000);
    let mut mem = walzer32_core::FlatMemory::new(base, 0x100_0000);
    mem.write_bytes(base, &bytes).expect("write bytes");

    for &off in &[0xc3c6c, 0xc3d2c] {
        let target_pc = base.add(off);
        let block = walzer32_ir::Lifter::lift_block(&mem, target_pc, true).expect("lift block");
        println!("\n=== LIFTED BLOCK AT 0x{:08x} (offset 0x{:x}, {} insts, exit={:?}) ===",
            target_pc.as_u32(), off, block.insts.len(), block.exit);
        for (i, inst) in block.insts.iter().enumerate() {
            let pc = block.inst_pc(i);
            println!("  [{:02}] pc=0x{:08x} cond={:?} => {:?}", i, pc.as_u32(), inst.cond, inst.op);
        }
        let compiled = walzer32_emitter_a64::A64Compiler::compile(&block);
        println!("=== COMPILED AARCH64 CODE ({} bytes) ===", compiled.code_bytes.len());
        for (idx, chunk) in compiled.code_bytes.chunks(4).enumerate() {
            let w = u32::from_le_bytes(chunk.try_into().unwrap());
            println!("    +{:03x}: 0x{:08x}", idx * 4, w);
        }
    }

    let bad_pc = base.add(0xc3d32);
    let hw1 = mem.read_u16(bad_pc).unwrap();
    let hw2 = mem.read_u16(bad_pc.add(2)).ok();
    let (inst, sz) = walzer32_decoder::ThumbDecoder::decode(hw1, hw2);
    println!("Instruction at 0x{:08x}: hw1=0x{:04x}, hw2={:?}, sz={}, op={:?}",
        bad_pc.as_u32(), hw1, hw2, sz, inst.op);
}

#[test]
fn test_inspect_unloc_block_1e8562() {
    let bytes = match get_test_lib("libfoundation.so") {
        Some(b) => b,
        None => {
            eprintln!("Skipping test: test_libs/libfoundation.so not found");
            return;
        }
    };
    let base = GuestAddr::new(0x7100_0000);
    let mut mem = walzer32_core::FlatMemory::new(base, 0x100_0000);
    mem.write_bytes(base, &bytes).expect("write bytes");

    for &offset in &[0x15a796] {
        let target_pc = base.add(offset);
        if let Ok(block) = walzer32_ir::Lifter::lift_block(&mem, target_pc, true) {
            println!("\n=== LIFTED BLOCK AT 0x{:08x} (offset 0x{:x}, {} insts, exit={:?}) ===",
                target_pc.as_u32(), offset, block.insts.len(), block.exit);
            for (i, inst) in block.insts.iter().enumerate() {
                let pc = block.inst_pc(i);
                println!("  [{:02}] pc=0x{:08x} cond={:?} => {:?}", i, pc.as_u32(), inst.cond, inst.op);
            }
            let compiled = walzer32_emitter_a64::A64Compiler::compile(&block);
            println!("=== COMPILED AARCH64 CODE ({} bytes) ===", compiled.code_bytes.len());
            for (idx, chunk) in compiled.code_bytes.chunks(4).enumerate() {
                let w = u32::from_le_bytes(chunk.try_into().unwrap());
                println!("    +{:03x}: 0x{:08x}", idx * 4, w);
            }
        }
    }
}

#[test]
fn test_disasm_array() {
    let bytes = match get_test_lib("libfoundation.so") {
        Some(b) => b,
        None => {
            eprintln!("Skipping test: test_libs/libfoundation.so not found");
            return;
        }
    };
    let base = GuestAddr::new(0x7100_0000);
    let mut mem = walzer32_core::FlatMemory::new(base, 0x100_0000);
    mem.write_bytes(base, &bytes).expect("write bytes");

    let mut visited = std::collections::BTreeSet::new();
    let mut queue = std::collections::VecDeque::new();
    queue.push_back(base.add(0x129c00));

    while let Some(pc) = queue.pop_front() {
        let pc_val = pc.as_u32() & !1;
        if !visited.insert(pc_val) {
            continue;
        }
        let block_pc = GuestAddr::new(pc_val);
        match walzer32_ir::Lifter::lift_block(&mem, block_pc, true) {
            Ok(block) => {
                println!("\n=== BLOCK AT 0x{:08x} (offset 0x{:x}, {} insts, exit={:?}) ===",
                    pc_val, pc_val - base.as_u32(), block.insts.len(), block.exit);
                for (i, inst) in block.insts.iter().enumerate() {
                    let ipc = block.inst_pc(i);
                    println!("  pc=0x{:08x} cond={:?} => {:?}", ipc.as_u32(), inst.cond, inst.op);
                }
                // If block is a call (BL / BLX), enqueue return address (fallthrough)
                if block.is_call {
                    let ret_addr = block.entry.add(block.byte_size as u32);
                    let ret_val = ret_addr.as_u32() & !1;
                    if ret_val >= base.as_u32() + 0x129c00 && ret_val <= base.as_u32() + 0x129d40 {
                        queue.push_back(GuestAddr::new(ret_val));
                    }
                }
                match block.exit {
                    walzer32_ir::BlockExit::Direct(t) => {
                        let t_val = t.as_u32() & !1;
                        if t_val >= base.as_u32() + 0x129c00 && t_val <= base.as_u32() + 0x129d40 {
                            queue.push_back(GuestAddr::new(t_val));
                        }
                    }
                    walzer32_ir::BlockExit::BranchCond { target, fallthrough, .. }
                    | walzer32_ir::BlockExit::CompareBranch { target, fallthrough, .. } => {
                        let t_val = target.as_u32() & !1;
                        let f_val = fallthrough.as_u32() & !1;
                        if t_val >= base.as_u32() + 0x129c00 && t_val <= base.as_u32() + 0x129d40 {
                            queue.push_back(GuestAddr::new(t_val));
                        }
                        if f_val >= base.as_u32() + 0x129c00 && f_val <= base.as_u32() + 0x129d40 {
                            queue.push_back(GuestAddr::new(f_val));
                        }
                    }
                    _ => {}
                }
            }
            Err(e) => {
                println!("Lift err at 0x{:08x}: {:?}", pc_val, e);
            }
        }
    }
}

#[test]
fn test_inspect_array_chain() {
    let bytes = match get_test_lib("libfoundation.so") {
        Some(b) => b,
        None => {
            eprintln!("Skipping test: test_libs/libfoundation.so not found");
            return;
        }
    };
    let base = GuestAddr::new(0x7100_0000);
    let mut mem = walzer32_core::FlatMemory::new(base, 0x100_0000);
    mem.write_bytes(base, &bytes).expect("write bytes");

    for &offset in &[0x129cd6, 0x129ce2, 0x129cf4, 0x129d0e] {
        let target_pc = base.add(offset);
        let block = walzer32_ir::Lifter::lift_block(&mem, target_pc, true).expect("lift block");
        println!("\n=== LIFTED BLOCK AT 0x{:08x} (offset 0x{:x}, {} insts, exit={:?}) ===",
            target_pc.as_u32(), offset, block.insts.len(), block.exit);
        for (i, inst) in block.insts.iter().enumerate() {
            let pc = block.inst_pc(i);
            let pc_r = block.pc_read_val(i);
            let pc_m = block.pc_mem_read_val(i);
            println!("  [{:02}] pc=0x{:08x} (r=0x{:08x}, m=0x{:08x}) cond={:?} => {:?}", i, pc.as_u32(), pc_r, pc_m, inst.cond, inst.op);
        }

        let compiled = walzer32_emitter_a64::A64Compiler::compile(&block);
        println!("=== COMPILED AARCH64 CODE ({} bytes) ===", compiled.code_bytes.len());
        for (idx, chunk) in compiled.code_bytes.chunks(4).enumerate() {
            let w = u32::from_le_bytes(chunk.try_into().unwrap());
            println!("    +{:03x}: 0x{:08x}", idx * 4, w);
        }
    }
}

#[test]
fn test_inspect_129d16() {
    let bytes = match get_test_lib("libfoundation.so") {
        Some(b) => b,
        None => {
            eprintln!("Skipping test: test_libs/libfoundation.so not found");
            return;
        }
    };
    let base = GuestAddr::new(0x7100_0000);
    let mut mem = walzer32_core::FlatMemory::new(base, 0x100_0000);
    mem.write_bytes(base, &bytes).expect("write bytes");

    let target_pc = base.add(0x129d16);
    let block = walzer32_ir::Lifter::lift_block(&mem, target_pc, true).expect("lift 129d16");
    println!("=== LIFTED BLOCK AT 0x{:08x} ({} insts, exit={:?}) ===", target_pc.as_u32(), block.insts.len(), block.exit);
    for (i, inst) in block.insts.iter().enumerate() {
        let pc = block.inst_pc(i);
        let pc_r = block.pc_read_val(i);
        let pc_m = block.pc_mem_read_val(i);
        println!("  [{:02}] pc=0x{:08x} (r=0x{:08x}, m=0x{:08x}) cond={:?} => {:?}", i, pc.as_u32(), pc_r, pc_m, inst.cond, inst.op);
    }

    let compiled = walzer32_emitter_a64::A64Compiler::compile(&block);
    println!("=== COMPILED AARCH64 CODE ({} bytes) ===", compiled.code_bytes.len());
    for (idx, chunk) in compiled.code_bytes.chunks(4).enumerate() {
        let w = u32::from_le_bytes(chunk.try_into().unwrap());
        println!("    +{:03x}: 0x{:08x}", idx * 4, w);
    }
}


#[test]
fn test_inspect_placeholder_array() {
    let bytes = match get_test_lib("libfoundation.so") {
        Some(b) => b,
        None => {
            eprintln!("Skipping test: test_libs/libfoundation.so not found");
            return;
        }
    };
    let base = GuestAddr::new(0x7100_0000);
    let mut mem = walzer32_core::FlatMemory::new(base, 0x100_0000);
    mem.write_bytes(base, &bytes).expect("write bytes");

    let mut pc = base.add(0x1056f0);
    let end_pc = base.add(0x105750);
    while pc < end_pc {
        let block = walzer32_ir::Lifter::lift_block(&mem, pc, true).expect("lift block");
        println!("\n=== BLOCK AT 0x{:08x} (offset 0x{:x}, {} insts, exit={:?}) ===",
            pc.as_u32(), pc.as_u32() - base.as_u32(), block.insts.len(), block.exit);
        for (i, inst) in block.insts.iter().enumerate() {
            let ipc = block.inst_pc(i);
            println!("  pc=0x{:08x} cond={:?} => {:?}", ipc.as_u32(), inst.cond, inst.op);
        }
        let compiled = walzer32_emitter_a64::A64Compiler::compile(&block);
        println!("=== COMPILED AARCH64 ({} bytes) ===", compiled.code_bytes.len());
        for (idx, chunk) in compiled.code_bytes.chunks(4).enumerate() {
            let w = u32::from_le_bytes(chunk.try_into().unwrap());
            println!("    +{:03x}: 0x{:08x}", idx * 4, w);
        }
        pc = pc.add(block.byte_size as u32);
    }
}

#[test]
fn test_inspect_1030e6() {
    let bytes = match get_test_lib("libfoundation.so") {
        Some(b) => b,
        None => {
            eprintln!("Skipping test: test_libs/libfoundation.so not found");
            return;
        }
    };
    let base = GuestAddr::new(0x7100_0000);
    let mut mem = walzer32_core::FlatMemory::new(base, 0x100_0000);
    mem.write_bytes(base, &bytes).expect("write bytes");

    let target_pc = base.add(0x1030e6);
    let block = walzer32_ir::Lifter::lift_block(&mem, target_pc, true).expect("lift 1030e6");
    println!("=== LIFTED BLOCK AT 0x{:08x} ({} insts, exit={:?}) ===", target_pc.as_u32(), block.insts.len(), block.exit);
    for (i, inst) in block.insts.iter().enumerate() {
        let pc = block.inst_pc(i);
        let pc_r = block.pc_read_val(i);
        let pc_m = block.pc_mem_read_val(i);
        println!("  [{:02}] pc=0x{:08x} (r=0x{:08x}, m=0x{:08x}) cond={:?} => {:?}", i, pc.as_u32(), pc_r, pc_m, inst.cond, inst.op);
    }

    let compiled = walzer32_emitter_a64::A64Compiler::compile(&block);
    println!("=== COMPILED AARCH64 CODE ({} bytes) ===", compiled.code_bytes.len());
    for (idx, chunk) in compiled.code_bytes.chunks(4).enumerate() {
        let w = u32::from_le_bytes(chunk.try_into().unwrap());
        println!("    +{:03x}: 0x{:08x}", idx * 4, w);
    }
}

#[test]
#[ignore = "slow whole-game test; run on physical device or with -- --ignored"]
fn test_repro_native_init() {
    let libs_dir = if std::path::Path::new("/data/local/tmp/test_libs").exists() {
        "/data/local/tmp/test_libs"
    } else if std::path::Path::new("test_libs").exists() {
        "test_libs"
    } else if std::path::Path::new("../../test_libs").exists() {
        "../../test_libs"
    } else {
        eprintln!("Skipping test: test_libs not found");
        return;
    };

    let topo_libs = [
        "libgnustl_shared.so",
        "libbox2d.so",
        "libdispatch.so",
        "libobjc.so",
        "libfoundation.so",
        "libcoregraphics.so",
        "libogg.so",
        "libopenal.so",
        "libquartzcore.so",
        "libuikit.so",
        "libcocos2d.so",
        "libnoodle.so",
        "libgameservices.so",
        "libstorekit.so",
        "libvorbis.so",
        "libcocosdenshion_al.so",
        "libgame.so",
    ];

    let mut session = Walzer32Session::new(GuestAddr::new(0x7000_0000), 0x800_0000).expect("session new");

    println!("Loading 17 libraries in topological order...");
    for name in &topo_libs {
        let p = format!("{}/{}", libs_dir, name);
        let bytes = match std::fs::read(&p) {
            Ok(b) => b,
            Err(e) => {
                println!("Cannot read {}: {:?}", p, e);
                return;
            }
        };
        let lib = session.load_library_bytes(name, &bytes).expect(&format!("load {}", name));
        println!("Loaded {} at 0x{:08x} ({} symbols)", name, lib.load_base.as_u32(), lib.symbols.len());
        if *name == "libobjc.so" {
            let got_16eb8 = lib.load_base.add(0x16eb8);
            let got_16ebc = lib.load_base.add(0x16ebc);
            let val_16eb8 = session.engine.mem.read_u32(got_16eb8).unwrap_or(0xdead);
            let val_16ebc = session.engine.mem.read_u32(got_16ebc).unwrap_or(0xdead);
            println!("DEBUG libobjc: load_base=0x{:08x}", lib.load_base.as_u32());
            println!("DEBUG libobjc GOT: [0x16eb8]=0x{:08x}, [0x16ebc]=0x{:08x}", val_16eb8, val_16ebc);

            // Let's inspect the IrBlock at 0x711273fe
            let target_pc = lib.load_base.add(0x73fe);
            let block = walzer32_ir::Lifter::lift_block(&session.engine.mem, target_pc, true).expect("lift 73fe");
            println!("=== LIFTED BLOCK AT 0x{:08x} ({} insts, exit={:?}) ===", target_pc.as_u32(), block.insts.len(), block.exit);
            for (i, inst) in block.insts.iter().enumerate() {
                let pc = block.inst_pc(i);
                let pc_r = block.pc_read_val(i);
                let pc_m = block.pc_mem_read_val(i);
                println!("  [{:02}] pc=0x{:08x} (r=0x{:08x}, m=0x{:08x}) cond={:?} => {:?}", i, pc.as_u32(), pc_r, pc_m, inst.cond, inst.op);
            }

            // Also let's compile it
            let compiled = walzer32_emitter_a64::A64Compiler::compile(&block);
            println!("=== COMPILED AARCH64 CODE ({} bytes) ===", compiled.code_bytes.len());
            for (idx, chunk) in compiled.code_bytes.chunks(4).enumerate() {
                let w = u32::from_le_bytes(chunk.try_into().unwrap());
                println!("    +{:03x}: 0x{:08x}", idx * 4, w);
            }
        }
    }

    if let Some(lib) = session.loaded_libraries.get("libfoundation.so") {
        let target_pc = lib.load_base.add(0x129d16);
        let block = walzer32_ir::Lifter::lift_block(&session.engine.mem, target_pc, true).expect("lift 129d16");
        println!("=== LIFTED BLOCK AT 0x{:08x} ({} insts, exit={:?}) ===", target_pc.as_u32(), block.insts.len(), block.exit);
        for (i, inst) in block.insts.iter().enumerate() {
            let pc = block.inst_pc(i);
            let pc_r = block.pc_read_val(i);
            let pc_m = block.pc_mem_read_val(i);
            println!("  [{:02}] pc=0x{:08x} (r=0x{:08x}, m=0x{:08x}) cond={:?} => {:?}", i, pc.as_u32(), pc_r, pc_m, inst.cond, inst.op);
        }

        let compiled = walzer32_emitter_a64::A64Compiler::compile(&block);
        println!("=== COMPILED AARCH64 CODE FOR 0x129d16 ({} bytes) ===", compiled.code_bytes.len());
        for (idx, chunk) in compiled.code_bytes.chunks(4).enumerate() {
            let w = u32::from_le_bytes(chunk.try_into().unwrap());
            println!("    +{:03x}: 0x{:08x}", idx * 4, w);
        }
    }

    let init_sym = session.loaded_libraries.get("libgame.so").expect("find libgame.so")
        .find_symbol("Java_org_cocos2dx_lib_Cocos2dxRenderer_nativeInit")
        .expect("find nativeInit");
    println!("Found nativeInit at 0x{:08x}", init_sym.as_u32());

    let env_ptr = session.jni.env_ptr.as_u32();
    let thiz_obj = 0x7001_1000u32;
    let width = 2520u32;
    let height = 1080u32;

    let objc_lib = session.loaded_libraries.get("libobjc.so").expect("find libobjc.so");
    let lookup_class_sym = objc_lib.find_symbol("objc_lookup_class").unwrap();
    let lookup_sender_sym = objc_lib.find_symbol("objc_msg_lookup_sender").unwrap();
    let sel_get_name_sym = objc_lib.find_symbol("sel_getName").unwrap();
    let found_base = session.loaded_libraries.get("libfoundation.so").unwrap().load_base;
    let prior_str = found_base.add(0x36ee58);
    println!("PROBE: NXConstantString @'prior' at 0x{:08x}: isa=0x{:08x}, chars=0x{:08x}, len={}",
        prior_str.as_u32(),
        session.engine.mem.read_u32(prior_str).unwrap_or(0),
        session.engine.mem.read_u32(prior_str.add(4)).unwrap_or(0),
        session.engine.mem.read_u32(prior_str.add(8)).unwrap_or(0),
    );

    let nsarray_str_addr = GuestAddr::new(0x7001_2000);
    session.engine.mem.write_bytes(nsarray_str_addr, b"NSArray\0").unwrap();
    let nsarray_cls = session.call_native(lookup_class_sym, &[nsarray_str_addr.as_u32()]).expect("call lookup_class");
    println!("PROBE: objc_lookup_class('NSArray') = 0x{:08x}", nsarray_cls);

    let r4_sel = found_base.add(0x36eb80);
    let cls_ptr_addr = GuestAddr::new(0x7001_2010);
    session.engine.mem.write_u32(cls_ptr_addr, nsarray_cls).unwrap();
    let slot = session.call_native(lookup_sender_sym, &[cls_ptr_addr.as_u32(), r4_sel.as_u32(), 0]).expect("lookup_sender");
    let imp = session.engine.mem.read_u32(GuestAddr::new(slot + 0x10)).unwrap_or(0);
    println!("PROBE: slot=0x{:08x}, slot->method=0x{:08x} (offset=0x{:08x})", slot, imp, imp.wrapping_sub(found_base.as_u32()));

    let imp_addr = GuestAddr::new(imp);
    println!("PROBE: calling +[NSArray arrayWithObjects:] with 5 dummy items...");
    let arr_res = session.call_native(imp_addr, &[nsarray_cls, r4_sel.as_u32(), nsarray_cls, nsarray_cls, nsarray_cls, nsarray_cls, nsarray_cls, 0]);
    println!("PROBE: +[NSArray arrayWithObjects:] returned: {:?}", arr_res);

    println!("PROBE: calling +[NSArray arrayWithObjects:] with 4 prior items...");
    let arr_prior_res = session.call_native(imp_addr, &[nsarray_cls, r4_sel.as_u32(), prior_str.as_u32(), prior_str.as_u32(), prior_str.as_u32(), prior_str.as_u32(), 0]);
    println!("PROBE: +[NSArray arrayWithObjects:] with prior returned: {:?}", arr_prior_res);

    let nsuserdefaults_str_addr = GuestAddr::new(0x7001_2040);
    session.engine.mem.write_bytes(nsuserdefaults_str_addr, b"NSUserDefaults\0").unwrap();
    let nsuserdefaults_cls = session.call_native(lookup_class_sym, &[nsuserdefaults_str_addr.as_u32()]).expect("lookup NSUserDefaults");
    println!("PROBE: objc_lookup_class('NSUserDefaults') = 0x{:08x}", nsuserdefaults_cls);

    let name_ptr = session.call_native(sel_get_name_sym, &[r4_sel.as_u32()]).expect("call sel_getName");
    let mut sel_name = String::new();
    for off in 0..64 {
        if let Ok(b) = session.engine.mem.read_u8(GuestAddr::new(name_ptr + off)) {
            if b == 0 { break; }
            sel_name.push(b as char);
        }
    }
    println!("PROBE: sel_getName(r4_sel) = 0x{:08x} \"{}\"", name_ptr, sel_name);

    println!("Calling nativeInit({}, {})...", width, height);
    let res = session.call_native(init_sym, &[env_ptr, thiz_obj, width, height]);
    let err_str = format!("{:?}", res.as_ref().err());
    println!("nativeInit completed with: res={:?} pc=0x{:08x} err={}",
        res, session.engine.cpu.pc().as_u32(), err_str);
    let mut fault_host_pc = 0usize;
    if let Some(pos) = err_str.find("host_pc=0x") {
        let hex_str = &err_str[pos + 10..pos + 20];
        fault_host_pc = usize::from_str_radix(hex_str, 16).unwrap_or(0);
    }
    println!("Extracted fault_host_pc = 0x{:016x}", fault_host_pc);

    println!("Searching JitCache for faulting host_pc (0x{:016x}):", fault_host_pc);
    for (guest_addr, host_ptr) in &session.engine.cache.code_ptrs {
        let p = host_ptr.0 as usize;
        let is_sb = session.engine.cache.superblocks.contains_key(guest_addr);
        let block_size = if let Some(b) = session.engine.cache.blocks.get(guest_addr) {
            b.code_bytes.len()
        } else if let Some(sb) = session.engine.cache.superblocks.get(guest_addr) {
            sb.code_bytes.len()
        } else {
            1024
        };
        if fault_host_pc >= p && fault_host_pc < p + block_size {
            println!("===> MATCHED GUEST BLOCK: 0x{:08x} (host=0x{:016x}..0x{:016x}, is_superblock={}, offset=+0x{:x})",
                guest_addr.as_u32(), p, p + block_size, is_sb, fault_host_pc - p);
            if let Some(b) = session.engine.cache.blocks.get(guest_addr) {
                println!("  Block inst_count={}, guest_byte_size={}, is_thumb={}", b.inst_count, b.guest_byte_size, b.is_thumb);
            }
            if let Some(sb) = session.engine.cache.superblocks.get(guest_addr) {
                println!("  Superblock inst_count={}, guest_byte_size={}, is_thumb={}", sb.inst_count, sb.guest_byte_size, sb.is_thumb);
            }
        }
    }
    if let Ok(maps) = std::fs::read_to_string("/proc/self/maps") {
        for line in maps.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if let Some(range) = parts.first() {
                let addrs: Vec<&str> = range.split('-').collect();
                if addrs.len() == 2 {
                    if let (Ok(start), Ok(end)) = (usize::from_str_radix(addrs[0], 16), usize::from_str_radix(addrs[1], 16)) {
                        if fault_host_pc >= start && fault_host_pc < end {
                            println!("FOUND FAULT MAP: {}", line);
                            let host_ptr = fault_host_pc as *const u32;
                            println!("Instructions around fault_host_pc (0x{:016x}):", fault_host_pc);
                            for i in -8..=4 {
                                let p = unsafe { host_ptr.offset(i) };
                                let w = unsafe { *p };
                                println!("  [{:+03}] 0x{:016x}: 0x{:08x}", i * 4, p as usize, w);
                            }
                        }
                    }
                }
            }
        }
    }

    println!("Dumping stack from 0x7f7fe8b0..0x7f7feb00:");
    for addr in (0x7f7fe8b0u32..0x7f7feb00u32).step_by(4) {
        if let Ok(w) = session.engine.mem.read_u32(GuestAddr::new(addr)) {
            let b0 = (w & 0xff) as u8;
            let b1 = ((w >> 8) & 0xff) as u8;
            let b2 = ((w >> 16) & 0xff) as u8;
            let b3 = ((w >> 24) & 0xff) as u8;
            let chars: String = [b0, b1, b2, b3].iter().map(|&c| if c >= 32 && c < 127 { c as char } else { '.' }).collect();
            println!("  [0x{:08x}] 0x{:08x} \"{}\"", addr, w, chars);
        }
    }
    println!("Dumping R7 (0x70341828):");
    for addr in (0x70341820u32..0x70341850u32).step_by(4) {
        if let Ok(w) = session.engine.mem.read_u32(GuestAddr::new(addr)) {
            println!("  [0x{:08x}] 0x{:08x}", addr, w);
        }
    }
    println!("Dumping R4 (0x71471530):");
    for addr in (0x71471530u32..0x71471540u32).step_by(4) {
        if let Ok(w) = session.engine.mem.read_u32(GuestAddr::new(addr)) {
            println!("  [0x{:08x}] 0x{:08x}", addr, w);
            if let Ok(w2) = session.engine.mem.read_u32(GuestAddr::new(w)) {
                println!("    -> points to 0x{:08x}", w2);
            }
        }
    }
    println!("Dumping keys and objects:");
    for i in 0..15 {
        let obj_addr = session.engine.mem.read_u32(GuestAddr::new(0x7f7fe980 + i * 4)).unwrap_or(0);
        let key_addr = session.engine.mem.read_u32(GuestAddr::new(0x7f7fea80 + i * 4)).unwrap_or(0);
        let mut key_str = String::new();
        for b_off in 0..32 {
            if let Ok(b) = session.engine.mem.read_u8(GuestAddr::new(key_addr + 16 + b_off)) {
                if b >= 32 && b < 127 { key_str.push(b as char); }
            }
        }
        println!("  [{:02}] key=0x{:08x} (\"{}\"), obj=0x{:08x}", i, key_addr, key_str, obj_addr);
    }

    let found_base = session.loaded_libraries.get("libfoundation.so").unwrap().load_base;
    let prior_str = found_base.add(0x36ee58);
    println!("PROBE: NXConstantString @'prior' at 0x{:08x}: isa=0x{:08x}, chars=0x{:08x}, len={}",
        prior_str.as_u32(),
        session.engine.mem.read_u32(prior_str).unwrap_or(0),
        session.engine.mem.read_u32(prior_str.add(4)).unwrap_or(0),
        session.engine.mem.read_u32(prior_str.add(8)).unwrap_or(0),
    );
    let r4_addr = found_base.add(0x36eb80);
    println!("Dumping selector r4 at 0x{:08x}:", r4_addr.as_u32());
    for i in 0..8 {
        let w = session.engine.mem.read_u32(r4_addr.add(i * 4)).unwrap_or(0);
        println!("  [+0x{:02x}] 0x{:08x}", i * 4, w);
    }

    println!("Dumping stack from 0x7f7feb00..0x7f7fed00:");
    for addr in (0x7f7feb00u32..0x7f7fed00u32).step_by(4) {
        if let Ok(w) = session.engine.mem.read_u32(GuestAddr::new(addr)) {
            if w != 0 {
                let b0 = (w & 0xff) as u8;
                let b1 = ((w >> 8) & 0xff) as u8;
                let b2 = ((w >> 16) & 0xff) as u8;
                let b3 = ((w >> 24) & 0xff) as u8;
                let chars: String = [b0, b1, b2, b3].iter().map(|&c| if c >= 32 && c < 127 { c as char } else { '.' }).collect();
                println!("  [0x{:08x}] 0x{:08x} \"{}\"", addr, w, chars);
            }
        }
    }
    println!("Registers:");
    for r in 0..16 {
        let reg = Reg::from_u8(r).unwrap();
        println!("  {:?}: 0x{:08x}", reg, session.engine.cpu.reg(reg));
    }

    println!("Recent guest blocks executed (last 64):");
    let count = session.engine.recent_blocks_idx.min(64);
    let start = session.engine.recent_blocks_idx.saturating_sub(count);
    for i in start..session.engine.recent_blocks_idx {
        let b = session.engine.recent_blocks[i % 64];
        println!("  #{:02}: 0x{:08x}", i - start, b.as_u32());
    }

    assert!(res.is_ok(), "nativeInit failed: {:?}", res);

    println!("\n==========================================");
    println!("=== CALLING nativeSurfaceChanged({}, {}) ===", width, height);
    println!("==========================================");
    let surf_sym = session.loaded_libraries.get("libgame.so")
        .and_then(|lib| lib.find_symbol("Java_org_cocos2dx_lib_Cocos2dxRenderer_nativeSurfaceChanged"));
    session.on_surface_changed(width, height);
    if let Some(surf_sym) = surf_sym {
        println!("Found nativeSurfaceChanged at 0x{:08x}", surf_sym.as_u32());
        let surf_res = session.call_native(surf_sym, &[env_ptr, thiz_obj, width, height]);
        println!("nativeSurfaceChanged returned: {:?}", surf_res);
        assert!(surf_res.is_ok(), "nativeSurfaceChanged failed: {:?}", surf_res);
    }

    println!("\n==========================================");
    println!("=== CALLING on_draw_frame() ===");
    println!("==========================================");
    let draw_res = session.on_draw_frame();
    println!("on_draw_frame returned: {:?}", draw_res);

    println!("\n==========================================");
    println!("=== CALLING nativeRender(env, 1) ===");
    println!("==========================================");
    let uikit_lib = session.loaded_libraries.get("libuikit.so").expect("find libuikit.so");
    let uikit_base = uikit_lib.load_base;
    let hook_ptr = uikit_base.add(0xd8af4);
    let hook_val = session.engine.mem.read_u32(hook_ptr);
    println!("Main loop hook val in libuikit at 0x{:08x}: {:?}", hook_ptr.as_u32(), hook_val);
    if let Ok(hv) = hook_val {
        if hv != 0 {
            println!("Memory at hook 0x{:08x}:", hv);
            for off in (0..32).step_by(4) {
                let w = session.engine.mem.read_u32(GuestAddr::new(hv + off));
                println!("  +0x{:02x}: {:?}", off, w);
            }
            if let Ok(isa) = session.engine.mem.read_u32(GuestAddr::new(hv)) {
                if let Ok(name_ptr) = session.engine.mem.read_u32(GuestAddr::new(isa + 8)) {
                    let mut s = String::new();
                    for i in 0..64 {
                        if let Ok(b) = session.engine.mem.read_u8(GuestAddr::new(name_ptr + i)) {
                            if b == 0 { break; }
                            s.push(b as char);
                        }
                    }
                    println!("Hook object class name: {}", s);
                }
            }
        }
    }

    let render_sym = uikit_lib.find_symbol("Java_org_cocos2dx_lib_Cocos2dxRenderer_nativeRender")
        .expect("find nativeRender in libuikit.so");
    println!("Found nativeRender at 0x{:08x}", render_sym.as_u32());

    let render_res = session.call_native(render_sym, &[env_ptr, 1]);
    println!("nativeRender returned: {:?}", render_res);
    println!("GLES total draw calls: {}", session.gles.total_draw_calls);
    println!("GLES draw calls record: {:?}", session.gles.draw_calls);
    println!("GLES swap count: {}", session.gles.swap_count);

    if let Err(e) = &render_res {
        println!("ERROR in nativeRender: {:?}", e);
        println!("Registers at trap:");
        for r in 0..16 {
            let reg = Reg::from_u8(r).unwrap();
            println!("  {:?}: 0x{:08x}", reg, session.engine.cpu.reg(reg));
        }
        println!("Recent guest blocks executed (last 64):");
        let count = session.engine.recent_blocks_idx.min(64);
        let start = session.engine.recent_blocks_idx.saturating_sub(count);
        for i in start..session.engine.recent_blocks_idx {
            let b = session.engine.recent_blocks[i % 64];
            println!("  #{:02}: 0x{:08x}", i - start, b.as_u32());
        }

        println!("Dumping stack from SP-32 to SP+64:");
        let sp = session.engine.cpu.sp();
        for addr in (sp.saturating_sub(32)..sp.saturating_add(64)).step_by(4) {
            if let Ok(w) = session.engine.mem.read_u32(GuestAddr::new(addr)) {
                println!("  [0x{:08x}] 0x{:08x}", addr, w);
            }
        }
    }

    assert!(render_res.is_ok(), "nativeRender failed: {:?}", render_res);
}
