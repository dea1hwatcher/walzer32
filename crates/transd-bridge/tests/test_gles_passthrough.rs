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

#[test]
fn test_egl_surface_and_context_lifecycle() {
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

    // Assembly sequence to test full EGL lifecycle:
    // 1. eglGetDisplay(0) -> dpy
    // 2. eglInitialize(dpy, 0, 0)
    // 3. eglCreateWindowSurface(dpy, config, 0x3000_0001, 0) -> surface
    // 4. eglCreateContext(dpy, config, 0, 0) -> context
    // 5. eglMakeCurrent(dpy, surface, surface, context)
    // 6. eglQueryString(dpy, 0x3054) -> version string
    let code_addr = GuestAddr::new(0x7002_0000);
    let get_display_addr = gles.stub_base.add((transd_bridge::GlesFuncId::EglGetDisplay as u32) * 8);
    let initialize_addr = gles.stub_base.add((transd_bridge::GlesFuncId::EglInitialize as u32) * 8);
    let create_surface_addr = gles.stub_base.add((transd_bridge::GlesFuncId::EglCreateWindowSurface as u32) * 8);
    let create_context_addr = gles.stub_base.add((transd_bridge::GlesFuncId::EglCreateContext as u32) * 8);
    let make_current_addr = gles.stub_base.add((transd_bridge::GlesFuncId::EglMakeCurrent as u32) * 8);
    let query_string_addr = gles.stub_base.add((transd_bridge::GlesFuncId::EglQueryString as u32) * 8);

    let insts = [
        0xE52DE004, // index 0: PUSH {lr}
        // 1. eglGetDisplay(0)
        0xE3A00000, // index 1: MOV r0, #0
        0xE59F407C, // index 2: LDR r4, [pc, #124] -> get_display_addr (idx 35)
        0xE12FFF34, // index 3: BLX r4
        0xE1A05000, // index 4: MOV r5, r0 (save dpy in r5)
        // 2. eglInitialize(dpy, 0, 0)
        0xE1A00005, // index 5: MOV r0, r5
        0xE3A01000, // index 6: MOV r1, #0
        0xE3A02000, // index 7: MOV r2, #0
        0xE59F4068, // index 8: LDR r4, [pc, #104] -> initialize_addr (idx 36)
        0xE12FFF34, // index 9: BLX r4
        // 3. eglCreateWindowSurface(dpy, config, 0x3000_0001)
        0xE1A00005, // index 10: MOV r0, r5
        0xE3A01000, // index 11: MOV r1, #0
        0xE59F205C, // index 12: LDR r2, [pc, #92] -> 0x3000_0001 (idx 37)
        0xE59F405C, // index 13: LDR r4, [pc, #92] -> create_surface_addr (idx 38)
        0xE12FFF34, // index 14: BLX r4
        0xE1A06000, // index 15: MOV r6, r0 (save surface in r6)
        // 4. eglCreateContext(dpy, config, 0, 0)
        0xE1A00005, // index 16: MOV r0, r5
        0xE3A01000, // index 17: MOV r1, #0
        0xE3A02000, // index 18: MOV r2, #0
        0xE3A03000, // index 19: MOV r3, #0
        0xE59F4044, // index 20: LDR r4, [pc, #68] -> create_context_addr (idx 39)
        0xE12FFF34, // index 21: BLX r4
        0xE1A07000, // index 22: MOV r7, r0 (save context in r7)
        // 5. eglMakeCurrent(dpy, surface, surface, context)
        0xE1A00005, // index 23: MOV r0, r5
        0xE1A01006, // index 24: MOV r1, r6
        0xE1A02006, // index 25: MOV r2, r6
        0xE1A03007, // index 26: MOV r3, r7
        0xE59F402C, // index 27: LDR r4, [pc, #44] -> make_current_addr (idx 40)
        0xE12FFF34, // index 28: BLX r4
        // 6. eglQueryString(dpy, 0x3054)
        0xE1A00005, // index 29: MOV r0, r5
        0xE59F1024, // index 30: LDR r1, [pc, #36] -> 0x3054 (EGL_VERSION, idx 41)
        0xE59F4024, // index 31: LDR r4, [pc, #36] -> query_string_addr (idx 42)
        0xE12FFF34, // index 32: BLX r4
        // Return
        0xE49DE004, // index 33: POP {lr}
        0xE12FFF1E, // index 34: BX lr
        // Literals pool (starting at index 35 = offset 140):
        get_display_addr.as_u32(),      // idx 35
        initialize_addr.as_u32(),       // idx 36
        0x3000_0001,                    // idx 37
        create_surface_addr.as_u32(),   // idx 38
        create_context_addr.as_u32(),   // idx 39
        make_current_addr.as_u32(),     // idx 40
        0x3054,                         // idx 41
        query_string_addr.as_u32(),     // idx 42
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
    assert_eq!(gles.bound_native_window, 0x3000_0001);
    assert!(gles.active_draw_surface >= 1);
    assert!(gles.active_context >= 1);
}
