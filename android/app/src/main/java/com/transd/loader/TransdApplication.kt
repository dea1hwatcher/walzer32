package com.transd.loader

import android.app.Application
import android.content.Context
import android.util.Log
import java.io.File

/**
 * TransdApplication — Base Android application for TransdLoader
 *
 * Prepares the 64-bit runtime, extracts bundled 32-bit assets, and initializes
 * the In-Process Dynamic Binary Translator.
 */
class TransdApplication : Application() {
    companion object {
        private const val TAG = "TransdApplication"
        lateinit var appContext: Context
            private set
    }

    override fun onCreate() {
        super.onCreate()
        appContext = applicationContext
        Log.i(TAG, "TransdApplication starting on ABI: ${android.os.Build.SUPPORTED_ABIS.joinToString()}")

        // Initialize Transd DBT
        val packageCodePath = applicationInfo.sourceDir
        val initResult = TransdEngine.nativeInit(packageCodePath)
        Log.i(TAG, "TransdEngine.nativeInit returned: $initResult")
    }
}
