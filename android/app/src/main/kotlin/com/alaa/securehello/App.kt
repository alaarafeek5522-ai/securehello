package com.alaa.securehello

import android.app.Application
import android.os.Process

class App : Application() {
    override fun onCreate() {
        // مكان 7 — أول حاجة بتتنفذ في التطبيق كله
        performEarlyCheck()
        super.onCreate()
    }

    private fun performEarlyCheck() {
        try {
            val pm = packageManager
            val info = pm.getPackageInfo(packageName, 0)
            if (info.packageName != "com.alaa.securehello") {
                Process.killProcess(Process.myPid())
                System.exit(0)
            }
        } catch (e: Exception) {
            Process.killProcess(Process.myPid())
            System.exit(0)
        }
    }
}
