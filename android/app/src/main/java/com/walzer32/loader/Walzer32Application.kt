package com.walzer32.loader

import android.app.Application
import android.content.Context
import android.util.Log
import java.io.File

/**
 * Walzer32Application — Base Android application for Walzer32Loader
 *
 * Prepares the 64-bit runtime, extracts bundled 32-bit assets, and initializes
 * the In-Process Dynamic Binary Translator.
 */
class Walzer32Application : Application() {
    companion object {
        private const val TAG = "Walzer32Application"
        lateinit var appContext: Context
            private set
    }

    override fun onCreate() {
        super.onCreate()
        appContext = applicationContext
        Log.i(TAG, "Walzer32Application starting on ABI: ${android.os.Build.SUPPORTED_ABIS.joinToString()}")

        // Initialize Walzer32 DBT
        val packageCodePath = applicationInfo.sourceDir
        val initResult = Walzer32Engine.nativeInit(packageCodePath)
        Log.i(TAG, "Walzer32Engine.nativeInit returned: $initResult")
    }
}
