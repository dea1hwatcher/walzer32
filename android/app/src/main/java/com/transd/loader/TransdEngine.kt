package com.transd.loader

import android.util.Log

/**
 * Transd DBT Engine Host Interface
 *
 * Bridges 64-bit Android ART to 32-bit ARM guest libraries running inside
 * the Transd In-Process DBT engine.
 */
object TransdEngine {
    private const val TAG = "TransdEngine"

    init {
        try {
            System.loadLibrary("transd")
            Log.i(TAG, "libtransd.so successfully loaded into 64-bit ART process")
        } catch (e: UnsatisfiedLinkError) {
            Log.e(TAG, "Failed to load libtransd.so", e)
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
