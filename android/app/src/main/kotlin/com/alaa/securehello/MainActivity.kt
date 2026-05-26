package com.alaa.securehello

import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import io.flutter.embedding.android.FlutterActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.MethodChannel
import java.security.MessageDigest

class SecurityHelper {
    external fun checkDebug(): String
    external fun checkEmulator(): String
    external fun checkFrida(): String
    external fun checkRoot(): String

    companion object {
        init { System.loadLibrary("security") }
    }
}

class MainActivity : FlutterActivity() {
    private val CHANNEL = "com.alaa.securehello/security"
    private val VALID_SIGNATURE = "318d4d9d730459aacd7f93df42a7f3fefc2ab8395e525189335fd48fbb26023b"

    override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)
        MethodChannel(flutterEngine.dartExecutor.binaryMessenger, CHANNEL)
            .setMethodCallHandler { call, result ->
                if (call.method == "runSecurityChecks") {
                    result.success(runAllChecks())
                } else {
                    result.notImplemented()
                }
            }
    }

    private fun getApkSignature(): String {
        return try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                val info = packageManager.getPackageInfo(packageName, PackageManager.GET_SIGNING_CERTIFICATES)
                val cert = info.signingInfo?.apkContentsSigners?.firstOrNull()?.toByteArray() ?: return "error"
                MessageDigest.getInstance("SHA-256").digest(cert).joinToString("") { "%02x".format(it) }
            } else {
                @Suppress("DEPRECATION")
                val info = packageManager.getPackageInfo(packageName, PackageManager.GET_SIGNATURES)
                val cert = info.signatures?.firstOrNull()?.toByteArray() ?: return "error"
                MessageDigest.getInstance("SHA-256").digest(cert).joinToString("") { "%02x".format(it) }
            }
        } catch (e: Exception) { "error" }
    }

    private fun runAllChecks(): Map<String, Any> {
        val helper = SecurityHelper()
        val reasons = mutableListOf<String>()

        if (helper.checkDebug() != "OK") reasons.add("DEBUG_DETECTED")
        if (helper.checkEmulator() != "OK") reasons.add("EMULATOR_DETECTED")
        if (helper.checkFrida() != "OK") reasons.add("FRIDA_DETECTED")
        if (helper.checkRoot() != "OK") reasons.add("ROOT_DETECTED")

        val sig = getApkSignature()
        if (sig != VALID_SIGNATURE) reasons.add("SIGNATURE_MISMATCH")

        return mapOf("passed" to reasons.isEmpty(), "reason" to reasons.joinToString(", "))
    }
}
