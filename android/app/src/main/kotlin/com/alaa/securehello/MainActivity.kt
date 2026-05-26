package com.alaa.securehello

import android.content.pm.PackageManager
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

    // ✅ ضع هنا SHA-256 الخاص بـ keystore بعد أول build
    private val VALID_SIGNATURE = "REPLACE_WITH_YOUR_SHA256"

    override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)

        MethodChannel(flutterEngine.dartExecutor.binaryMessenger, CHANNEL)
            .setMethodCallHandler { call, result ->
                if (call.method == "runSecurityChecks") {
                    val check = runAllChecks()
                    result.success(check)
                } else {
                    result.notImplemented()
                }
            }
    }

    private fun getApkSignature(): String {
        return try {
            val pm = packageManager
            val info = pm.getPackageInfo(packageName, PackageManager.GET_SIGNATURES)
            val cert = info.signatures[0].toByteArray()
            val md = MessageDigest.getInstance("SHA-256")
            val digest = md.digest(cert)
            digest.joinToString("") { "%02x".format(it) }
        } catch (e: Exception) {
            "error"
        }
    }

    private fun runAllChecks(): Map<String, Any> {
        val helper = SecurityHelper()

        // Native checks
        val debugCheck = helper.checkDebug()
        val emuCheck = helper.checkEmulator()
        val fridaCheck = helper.checkFrida()
        val rootCheck = helper.checkRoot()

        // Signature check
        val sig = getApkSignature()
        val sigOk = VALID_SIGNATURE == "REPLACE_WITH_YOUR_SHA256" || sig == VALID_SIGNATURE

        val reasons = mutableListOf<String>()
        if (debugCheck != "OK") reasons.add(debugCheck)
        if (emuCheck != "OK") reasons.add(emuCheck)
        if (fridaCheck != "OK") reasons.add(fridaCheck)
        if (rootCheck != "OK") reasons.add(rootCheck)
        if (!sigOk) reasons.add("SIGNATURE_MISMATCH")

        return mapOf(
            "passed" to reasons.isEmpty(),
            "reason" to reasons.joinToString(", ")
        )
    }
}
