use transd_core::{FlatMemory, GuestAddr, Memory};
use transd_rt::DbtEngine;
use transd_bridge::{
    invoke_guest_full, BionicBridge, GlesBridge, JniBridge,
    GL_TRIANGLES, GL_VERSION,
};

#[test]
fn test_gles_get_string() {
    let mut mem = FlatMemory::new(GuestAddr::new(0x7000_0000), 0x200_000);

    let mut bionic = BionicBridge::new(
        GuestAddr::new(0x7000_0000),
        GuestAddr::new(0x7010_0000),
        0x100_000,
    );
    bionic.install_stubs(&mut mem).unwrap();

    let mut jni = JniBridge::new(GuestAddr::new(0x7005_0000));
    jni.install(&mut mem).unwrap();

    let mut gles = GlesBridge::new(
        GuestAddr::new(0x7008_0000),
        GuestAddr::new(0x7009_0000),
    );
    gles.install_stubs(&mut mem).unwrap();

    let mut engine = DbtEngine::new(mem);

    // Write ARM32 code at 0x7002_0000:
    // PUSH {lr}
    // LDR r0, =0x1F02 (GL_VERSION)
    // LDR r1, =glGetString_stub
    // BLX r1
    // POP {lr}
    // BX lr
    let code_addr = GuestAddr::new(0x7002_0000);
    let gl_get_string_addr = gles.stub_base.add((transd_bridge::GlesFuncId::GlGetString as u32) * 8);

    let insts = [
        0xE52DE004, // STR lr, [sp, #-4]! (PUSH {lr})
        0xE59F000C, // LDR r0, [pc, #12] -> GL_VERSION
        0xE59F100C, // LDR r1, [pc, #12] -> gl_get_string_addr
        0xE12FFF31, // BLX r1
        0xE49DE004, // LDR lr, [sp], #4  (POP {lr})
        0xE12FFF1E, // BX lr
        // Literals at pc+8:
        GL_VERSION,
        gl_get_string_addr.as_u32(),
    ];

    for (i, &word) in insts.iter().enumerate() {
        engine.mem.write_u32(code_addr.add((i * 4) as u32), word).unwrap();
    }

    engine.cpu.set_sp(0x701F_F000);

    let str_ptr = invoke_guest_full(
        &mut engine,
        &mut bionic,
        &mut jni,
        Some(&mut gles),
        code_addr,
        &[],
    ).unwrap();

    assert_ne!(str_ptr, 0);

    // Read string from returned guest address
    let mut str_bytes = Vec::new();
    let mut offset = 0;
    loop {
        let b = engine.mem.read_u8(GuestAddr::new(str_ptr + offset)).unwrap();
        if b == 0 {
            break;
        }
        str_bytes.push(b);
        offset += 1;
    }

    let version_str = String::from_utf8(str_bytes).unwrap();
    assert_eq!(version_str, "OpenGL ES 3.2 Transd");
}

#[test]
fn test_gles_draw_calls_and_state() {
    let mut mem = FlatMemory::new(GuestAddr::new(0x7000_0000), 0x200_000);

    let mut bionic = BionicBridge::new(
        GuestAddr::new(0x7000_0000),
        GuestAddr::new(0x7010_0000),
        0x100_000,
    );
    bionic.install_stubs(&mut mem).unwrap();

    let mut jni = JniBridge::new(GuestAddr::new(0x7005_0000));
    jni.install(&mut mem).unwrap();

    let mut gles = GlesBridge::new(
        GuestAddr::new(0x7008_0000),
        GuestAddr::new(0x7009_0000),
    );
    gles.install_stubs(&mut mem).unwrap();

    let mut engine = DbtEngine::new(mem);

    // Test glClearColor(0.2, 0.4, 0.6, 1.0)
    // and glViewport(0, 0, 1920, 1080)
    // and glDrawArrays(GL_TRIANGLES, 0, 3)
    // and eglSwapBuffers(0x1000, 0x2000)
    let code_addr = GuestAddr::new(0x7002_0000);
    let clear_color_addr = gles.stub_base.add((transd_bridge::GlesFuncId::GlClearColor as u32) * 8);
    let viewport_addr = gles.stub_base.add((transd_bridge::GlesFuncId::GlViewport as u32) * 8);
    let draw_arrays_addr = gles.stub_base.add((transd_bridge::GlesFuncId::GlDrawArrays as u32) * 8);
    let swap_buffers_addr = gles.stub_base.add((transd_bridge::GlesFuncId::EglSwapBuffers as u32) * 8);

    let r_bits = 0.2f32.to_bits();
    let g_bits = 0.4f32.to_bits();
    let b_bits = 0.6f32.to_bits();
    let a_bits = 1.0f32.to_bits();

    // Assembly:
    // PUSH {lr}
    // 1. glClearColor
    // LDR r0, =r_bits
    // LDR r1, =g_bits
    // LDR r2, =b_bits
    // LDR r3, =a_bits
    // LDR r4, =clear_color_addr
    // BLX r4
    //
    // 2. glViewport(0, 0, 1920, 1080)
    // MOV r0, #0
    // MOV r1, #0
    // LDR r2, =1920
    // LDR r3, =1080
    // LDR r4, =viewport_addr
    // BLX r4
    //
    // 3. glDrawArrays(GL_TRIANGLES, 0, 3)
    // MOV r0, #4 (GL_TRIANGLES)
    // MOV r1, #0
    // MOV r2, #3
    // LDR r4, =draw_arrays_addr
    // BLX r4
    //
    // 4. eglSwapBuffers(0x1000, 0x2000)
    // LDR r0, =0x1000
    // LDR r1, =0x2000
    // LDR r4, =swap_buffers_addr
    // BLX r4
    //
    // POP {lr}
    // BX lr
    let insts = [
        0xE52DE004, // STR lr, [sp, #-4]!
        // 1. glClearColor
        0xE59F0054, // LDR r0, [pc, #84] -> r_bits
        0xE59F1054, // LDR r1, [pc, #84] -> g_bits
        0xE59F2054, // LDR r2, [pc, #84] -> b_bits
        0xE59F3054, // LDR r3, [pc, #84] -> a_bits
        0xE59F4054, // LDR r4, [pc, #84] -> clear_color_addr
        0xE12FFF34, // BLX r4
        // 2. glViewport
        0xE3A00000, // MOV r0, #0
        0xE3A01000, // MOV r1, #0
        0xE59F2048, // LDR r2, [pc, #72] -> 1920
        0xE59F3048, // LDR r3, [pc, #72] -> 1080
        0xE59F4048, // LDR r4, [pc, #72] -> viewport_addr
        0xE12FFF34, // BLX r4
        // 3. glDrawArrays
        0xE3A00004, // MOV r0, #4
        0xE3A01000, // MOV r1, #0
        0xE3A02003, // MOV r2, #3
        0xE59F4038, // LDR r4, [pc, #56] -> draw_arrays_addr
        0xE12FFF34, // BLX r4
        // 4. eglSwapBuffers
        0xE59F0034, // LDR r0, [pc, #52] -> 0x1000
        0xE59F1034, // LDR r1, [pc, #52] -> 0x2000
        0xE59F4034, // LDR r4, [pc, #52] -> swap_buffers_addr
        0xE12FFF34, // BLX r4
        // Return
        0xE49DE004, // LDR lr, [sp], #4
        0xE12FFF1E, // BX lr
        // Literals pool:
        r_bits,
        g_bits,
        b_bits,
        a_bits,
        clear_color_addr.as_u32(),
        1920,
        1080,
        viewport_addr.as_u32(),
        draw_arrays_addr.as_u32(),
        0x1000,
        0x2000,
        swap_buffers_addr.as_u32(),
    ];

    for (i, &word) in insts.iter().enumerate() {
        engine.mem.write_u32(code_addr.add((i * 4) as u32), word).unwrap();
    }

    engine.cpu.set_sp(0x701F_F000);

    let res = invoke_guest_full(
        &mut engine,
        &mut bionic,
        &mut jni,
        Some(&mut gles),
        code_addr,
        &[],
    ).unwrap();

    assert_eq!(res, 1); // eglSwapBuffers returns 1 (EGL_TRUE)
    assert_eq!(gles.clear_color, [0.2, 0.4, 0.6, 1.0]);
    assert_eq!(gles.viewport, [0, 0, 1920, 1080]);
    assert_eq!(gles.draw_calls.len(), 1);
    assert_eq!(gles.draw_calls[0].mode, GL_TRIANGLES);
    assert_eq!(gles.draw_calls[0].first, 0);
    assert_eq!(gles.draw_calls[0].count, 3);
    assert_eq!(gles.swap_count, 1);
}
