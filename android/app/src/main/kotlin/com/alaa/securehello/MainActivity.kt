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
    external fun checkPackageName(context: android.content.Context): Boolean
    external fun killIfTampered()
    companion object { init { System.loadLibrary("security") } }
}

class MainActivity : FlutterActivity() {
    private val CHANNEL = "com.alaa.securehello/security"
    private val S1 = "318d4d9d730459aa"
    private val S2 = "cd7f93df42a7f3fe"
    private val S3 = "fc2ab8395e525189"
    private val S4 = "335fd48fbb26023b"
    private val VALID_SIG get() = S1 + S2 + S3 + S4

    // مكان 1 — onCreate قبل Flutter
    override fun onCreate(savedInstanceState: Bundle?) {
        checkSignatureOrKill()
        checkPackageOrKill()
        super.onCreate(savedInstanceState)
    }

    // مكان 2 — onStart
    override fun onStart() {
        super.onStart()
        checkSignatureOrKill()
    }

    // مكان 3 — onResume كل ما يرجع للفور
    override fun onResume() {
        super.onResume()
        checkSignatureOrKill()
        checkPackageOrKill()
        val helper = SecurityHelper()
        if (helper.checkFrida() != "OK") killNow()
        if (helper.checkDebug() != "OK") killNow()
    }

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
        val sig1 = getSignatureV1()
        val sig2 = getSignatureV2()
        if (sig1 != sig2) killNow()
        if (sig1 != VALID_SIG) killNow()
    }

    private fun checkPackageOrKill() {
        val helper = SecurityHelper()
        if (!helper.checkPackageName(applicationContext)) killNow()
    }

    override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)
        MethodChannel(flutterEngine.dartExecutor.binaryMessenger, CHANNEL)
            .setMethodCallHandler { call, result ->
                if (call.method == "runSecurityChecks") {
                    // مكان 6 — MethodChannel runtime
                    result.success(runAllChecks())
                } else {
                    result.notImplemented()
                }
            }
    }

    private fun runAllChecks(): Map<String, Any> {
        val helper = SecurityHelper()
        val reasons = mutableListOf<String>()

        val debugCheck = helper.checkDebug()
        val emuCheck = helper.checkEmulator()
        val fridaCheck = helper.checkFrida()
        val rootCheck = helper.checkRoot()

        if (debugCheck != "OK") { killNow(); reasons.add(debugCheck) }
        if (emuCheck != "OK") reasons.add(emuCheck)
        if (fridaCheck != "OK") { killNow(); reasons.add(fridaCheck) }
        if (rootCheck != "OK") reasons.add(rootCheck)

        // مكان 6 — فحص التوقيع مرة تانية في الـ runtime
        checkSignatureOrKill()
        checkPackageOrKill()

        return mapOf("passed" to reasons.isEmpty(), "reason" to reasons.joinToString(", "))
    }
}
