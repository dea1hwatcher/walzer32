package com.walzer32.loader

import android.util.Log

/**
 * Walzer32 DBT Engine Host Interface
 *
 * Bridges 64-bit Android ART to 32-bit ARM guest libraries running inside
 * the Walzer32 In-Process DBT engine.
 */
object Walzer32Engine {
    private const val TAG = "Walzer32Engine"

    init {
        try {
            System.loadLibrary("walzer32")
            Log.i(TAG, "libwalzer32.so successfully loaded into 64-bit ART process")
        } catch (e: UnsatisfiedLinkError) {
            Log.e(TAG, "Failed to load libwalzer32.so", e)
        }
    }

    /**
     * Initialize the DBT environment, memory arena, and Bionic/GLES/JNI bridges.
     */
    external fun nativeInit(apkPath: String): Int

    /**
     * Load a 32-bit ELF library from raw bytes.
     */
    external fun nativeLoadLibraryBytes(
        name: String,
        elfBytes: ByteArray
    ): Int

    /**
     * Call an exported 32-bit native guest function by virtual address.
     */
    external fun nativeCallMethod(
        fnAddr: Long,
        arg0: Int,
        arg1: Int,
        arg2: Int,
        arg3: Int
    ): Int

    /**
     * Query count of loaded 32-bit libraries.
     */
    external fun nativeGetStatus(): Int

    /**
     * Reset the DBT execution session.
     */
    external fun nativeReset()

    /**
     * Notify DBT of SurfaceView creation and establish 32-bit native window mapping.
     */
    external fun nativeSurfaceCreated(surface: Any, width: Int, height: Int): Int

    /**
     * Notify DBT of SurfaceView dimension changes.
     */
    external fun nativeSurfaceChanged(width: Int, height: Int): Int

    /**
     * Notify DBT of SurfaceView destruction.
     */
    external fun nativeSurfaceDestroyed(): Int

    /**
     * Execute a single frame render tick in guest DBT.
     */
    external fun nativeDrawFrame(): Int

    /**
     * Forward touch input events to guest touch queue.
     */
    external fun nativeTouchEvent(action: Int, x: Float, y: Float, pointerId: Int): Int

    /**
     * Forward key input events to guest key queue.
     */
    external fun nativeKeyEvent(action: Int, keyCode: Int): Int

    /**
     * High-level loader helper: loads a 32-bit .so from assets or file and resolves entry point.
     */
    fun loadLibraryFromBytes(name: String, bytes: ByteArray): Boolean {
        val res = nativeLoadLibraryBytes(name, bytes)
        if (res == 0) {
            Log.i(TAG, "Successfully loaded 32-bit library: $name (status: ${nativeGetStatus()})")
            return true
        } else {
            Log.e(TAG, "Failed to load 32-bit library: $name (err: $res)")
            return false
        }
    }
}
