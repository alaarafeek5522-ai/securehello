package com.alaa.securehello

import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.os.Process
import io.flutter.embedding.android.FlutterActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.MethodChannel
import java.security.MessageDigest

class SecurityHelper {
    external fun checkDebug(): String
    external fun checkEmulator(): String
    external fun checkFrida(): String
    external fun checkRoot(): String
    external fun checkXposed(): String
    external fun checkPackageName(context: android.content.Context): Boolean
    external fun killIfTampered()
    companion object { init { System.loadLibrary("security") } }
}

class MainActivity : FlutterActivity() {
    private val CHANNEL = "com.alaa.securehello/security"

    private val encSig = byteArrayOf(
        0x69,0x6b,0x62,0x3e,0x6e,0x3e,0x63,0x3e,0x6d,0x69,0x6a,0x6e,
        0x6f,0x63,0x3b,0x3b,0x39,0x3e,0x6d,0x3c,0x63,0x69,0x3e,0x3c,
        0x6e,0x68,0x3b,0x6d,0x3c,0x69,0x3c,0x3f,0x3c,0x39,0x68,0x3b,
        0x38,0x62,0x69,0x63,0x6f,0x3f,0x6f,0x68,0x6f,0x6b,0x62,0x63,
        0x69,0x69,0x6f,0x3c,0x3e,0x6e,0x62,0x3c,0x38,0x38,0x68,0x6c,
        0x6a,0x68,0x69,0x38
    )
    private val xorKey: Byte = 0x5A

    private fun decryptSig(): String =
        encSig.map { (it.toInt() xor xorKey.toInt()).toChar() }.joinToString("")

    private fun killNow() {
        Process.killProcess(Process.myPid())
        System.exit(0)
    }

    private fun getSignatureV1(): String {
        return try {
            @Suppress("DEPRECATION")
            val info = packageManager.getPackageInfo(packageName, PackageManager.GET_SIGNATURES)
            val cert = info.signatures?.firstOrNull()?.toByteArray() ?: return "error"
            MessageDigest.getInstance("SHA-256").digest(cert).joinToString("") { "%02x".format(it) }
        } catch (e: Exception) { "error" }
    }

    private fun getSignatureV2(): String {
        return try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                val info = packageManager.getPackageInfo(packageName, PackageManager.GET_SIGNING_CERTIFICATES)
                val cert = info.signingInfo?.apkContentsSigners?.firstOrNull()?.toByteArray() ?: return "error"
                MessageDigest.getInstance("SHA-256").digest(cert).joinToString("") { "%02x".format(it) }
            } else getSignatureV1()
        } catch (e: Exception) { "error" }
    }

    private fun checkSignatureOrKill() {
        val valid = decryptSig()
        val s1 = getSignatureV1()
        val s2 = getSignatureV2()
        if (s1 == "error" || s2 == "error") killNow()
        if (s1 != s2) killNow()
        if (s1 != valid) killNow()
    }

    private fun hardCheck() {
        val helper = SecurityHelper()
        if (!helper.checkPackageName(applicationContext)) killNow()
        if (helper.checkFrida() != "OK") killNow()
        if (helper.checkDebug() != "OK") killNow()
        if (helper.checkXposed() != "OK") killNow()
        checkSignatureOrKill()
    }

    // مكان 1
    override fun onCreate(savedInstanceState: Bundle?) {
        hardCheck()
        super.onCreate(savedInstanceState)
    }

    // مكان 2
    override fun onStart() {
        super.onStart()
        checkSignatureOrKill()
    }

    // مكان 3
    override fun onResume() {
        super.onResume()
        hardCheck()
    }

    // مكان 4
    override fun onWindowFocusChanged(hasFocus: Boolean) {
        super.onWindowFocusChanged(hasFocus)
        if (hasFocus) checkSignatureOrKill()
    }

    override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)
        MethodChannel(flutterEngine.dartExecutor.binaryMessenger, CHANNEL)
            .setMethodCallHandler { call, result ->
                if (call.method == "runSecurityChecks") {
                    // مكان 5
                    result.success(runAllChecks())
                } else result.notImplemented()
            }
    }

    private fun runAllChecks(): Map<String, Any> {
        val helper = SecurityHelper()
        val reasons = mutableListOf<String>()
        if (helper.checkDebug() != "OK") { killNow(); reasons.add("DEBUG") }
        if (helper.checkEmulator() != "OK") reasons.add("EMULATOR")
        if (helper.checkFrida() != "OK") { killNow(); reasons.add("FRIDA") }
        if (helper.checkRoot() != "OK") reasons.add("ROOT")
        if (helper.checkXposed() != "OK") { killNow(); reasons.add("XPOSED") }
        checkSignatureOrKill()
        return mapOf("passed" to reasons.isEmpty(), "reason" to reasons.joinToString(", "))
    }
}
