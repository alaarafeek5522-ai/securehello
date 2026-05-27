#include <jni.h>
#include <string>
#include <fstream>
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>
#include <android/log.h>
#include <signal.h>
#include <dlfcn.h>
#include <pthread.h>
#include <stdlib.h>
#include <sys/system_properties.h>
#include <sys/mman.h>
#include <elf.h>

static void killApp() { kill(getpid(), SIGKILL); }

// package name مشفر compile-time بـ XOR
static const uint8_t ENC_PKG[] = {
    0x19,0x13,0x18,0x2e,0x1f,0x18,0x1f,0x2e,
    0x39,0x1b,0x13,0x1e,0x28,0x1b,0x18,0x18,
    0x1d,0x2e,0x39,0x1b,0x13,0x1e,0x28,0x1b,
    0x18,0x18,0x1d
};
static const uint8_t PKG_KEY = 0x7A;

static std::string decryptPkg() {
    std::string result;
    for (size_t i = 0; i < sizeof(ENC_PKG); i++)
        result += (char)(ENC_PKG[i] ^ PKG_KEY);
    return result;
}

// ======= DEBUG =======
static bool isBeingDebugged() {
    std::ifstream status("/proc/self/status");
    std::string line;
    while (std::getline(status, line)) {
        if (line.find("TracerPid:") != std::string::npos) {
            int pid = std::stoi(line.substr(line.find(':') + 1));
            if (pid != 0) return true;
        }
    }
    std::ifstream wchan("/proc/self/wchan");
    std::string wc; wchan >> wc;
    if (wc == "ptrace_stop") return true;
    return false;
}

// ======= FRIDA =======
static bool isFridaPresent() {
    std::ifstream maps("/proc/self/maps");
    std::string line;
    while (std::getline(maps, line)) {
        if (line.find("frida") != std::string::npos) return true;
        if (line.find("gadget") != std::string::npos) return true;
        if (line.find("linjector") != std::string::npos) return true;
    }
    const char* tcpFiles[] = {"/proc/net/tcp", "/proc/net/tcp6"};
    for (auto f : tcpFiles) {
        std::ifstream tcp(f);
        while (std::getline(tcp, line)) {
            if (line.find("699A") != std::string::npos) return true;
        }
    }
    const char* fridaLibs[] = {
        "libfrida-agent.so", "libfrida-gadget.so", "libfrida.so"
    };
    for (auto lib : fridaLibs) {
        void* h = dlopen(lib, RTLD_LAZY | RTLD_NOLOAD);
        if (h) { dlclose(h); return true; }
    }
    DIR* dir = opendir("/proc/self/fd");
    if (dir) {
        struct dirent* entry;
        while ((entry = readdir(dir)) != nullptr) {
            char path[256], resolved[256];
            snprintf(path, sizeof(path), "/proc/self/fd/%s", entry->d_name);
            ssize_t len = readlink(path, resolved, sizeof(resolved)-1);
            if (len > 0) {
                resolved[len] = 0;
                if (std::string(resolved).find("frida") != std::string::npos) {
                    closedir(dir); return true;
                }
            }
        }
        closedir(dir);
    }
    return false;
}

// ======= ROOT =======
static bool isRooted() {
    const char* paths[] = {
        "/system/app/Superuser.apk", "/sbin/su",
        "/system/bin/su", "/system/xbin/su",
        "/data/local/xbin/su", "/data/local/bin/su",
        "/system/sd/xbin/su", "/data/local/su",
        "/system/bin/.ext/.su", "/system/xbin/mu",
        "/system/app/SuperSU.apk", "/system/xbin/daemonsu"
    };
    for (auto p : paths) {
        struct stat st;
        if (stat(p, &st) == 0) return true;
    }
    return false;
}

// ======= EMULATOR =======
static bool isEmulator() {
    char val[PROP_VALUE_MAX];
    __system_property_get("ro.kernel.qemu", val);
    if (std::string(val) == "1") return true;
    __system_property_get("ro.product.model", val);
    if (std::string(val).find("Android SDK") != std::string::npos) return true;
    __system_property_get("ro.hardware", val);
    std::string hw(val);
    if (hw.find("goldfish") != std::string::npos) return true;
    if (hw.find("ranchu") != std::string::npos) return true;
    const char* emuFiles[] = {
        "/dev/socket/qemud", "/dev/qemu_pipe", "/sys/qemu_trace"
    };
    for (auto f : emuFiles) {
        struct stat st;
        if (stat(f, &st) == 0) return true;
    }
    return false;
}

// ======= XPOSED =======
static bool isXposedPresent() {
    std::ifstream maps("/proc/self/maps");
    std::string line;
    while (std::getline(maps, line)) {
        if (line.find("XposedBridge") != std::string::npos) return true;
        if (line.find("xposed") != std::string::npos) return true;
        if (line.find("edxposed") != std::string::npos) return true;
        if (line.find("lsposed") != std::string::npos) return true;
    }
    struct stat st;
    if (stat("/system/framework/XposedBridge.jar", &st) == 0) return true;
    return false;
}

// ======= APK CRC =======
static uint32_t computeCRC32(const std::string& path) {
    std::ifstream file(path, std::ios::binary);
    if (!file) return 0;
    uint32_t crc = 0xFFFFFFFF;
    char buf[4096];
    while (file.read(buf, sizeof(buf)) || file.gcount() > 0) {
        for (int i = 0; i < file.gcount(); i++) {
            crc ^= (uint8_t)buf[i];
            for (int j = 0; j < 8; j++)
                crc = (crc >> 1) ^ (0xEDB88320 & -(crc & 1));
        }
    }
    return crc ^ 0xFFFFFFFF;
}

static uint32_t storedCRC = 0;

static void initApkCRC(JNIEnv* env, jobject context) {
    jclass ctxClass = env->GetObjectClass(context);
    jmethodID getPkgCodePath = env->GetMethodID(
        env->FindClass("android/content/pm/ApplicationInfo"),
        "sourceDir", nullptr);
    // جيب الـ sourceDir
    jmethodID getAppInfo = env->GetMethodID(ctxClass, "getApplicationInfo",
        "()Landroid/content/pm/ApplicationInfo;");
    jobject appInfo = env->CallObjectMethod(context, getAppInfo);
    jclass aiClass = env->GetObjectClass(appInfo);
    jfieldID sourceDirField = env->GetFieldID(aiClass, "sourceDir", "Ljava/lang/String;");
    jstring sourceDir = (jstring)env->GetObjectField(appInfo, sourceDirField);
    const char* apkPath = env->GetStringUTFChars(sourceDir, nullptr);
    storedCRC = computeCRC32(std::string(apkPath));
    env->ReleaseStringUTFChars(sourceDir, apkPath);
}

static bool isApkModified(JNIEnv* env, jobject context) {
    if (storedCRC == 0) return false;
    jclass ctxClass = env->GetObjectClass(context);
    jmethodID getAppInfo = env->GetMethodID(ctxClass, "getApplicationInfo",
        "()Landroid/content/pm/ApplicationInfo;");
    jobject appInfo = env->CallObjectMethod(context, getAppInfo);
    jclass aiClass = env->GetObjectClass(appInfo);
    jfieldID sourceDirField = env->GetFieldID(aiClass, "sourceDir", "Ljava/lang/String;");
    jstring sourceDir = (jstring)env->GetObjectField(appInfo, sourceDirField);
    const char* apkPath = env->GetStringUTFChars(sourceDir, nullptr);
    uint32_t currentCRC = computeCRC32(std::string(apkPath));
    env->ReleaseStringUTFChars(sourceDir, apkPath);
    return currentCRC != storedCRC;
}

// ======= THREADS =======
static void* securityThread(void*) {
    while (true) {
        sleep(10 + rand() % 20);
        if (isBeingDebugged()) killApp();
        if (isFridaPresent()) killApp();
        if (isXposedPresent()) killApp();
    }
    return nullptr;
}

static void* securityThread2(void*) {
    while (true) {
        sleep(7 + rand() % 13);
        if (isBeingDebugged()) killApp();
        if (isFridaPresent()) killApp();
    }
    return nullptr;
}

// ======= CONSTRUCTOR =======
__attribute__((constructor))
static void onLibraryLoad() {
    if (isBeingDebugged()) killApp();
    if (isFridaPresent()) killApp();
    if (isXposedPresent()) killApp();
    pthread_t t1, t2;
    pthread_create(&t1, nullptr, securityThread, nullptr);
    pthread_detach(t1);
    pthread_create(&t2, nullptr, securityThread2, nullptr);
    pthread_detach(t2);
}

// ======= JNI =======
extern "C" JNIEXPORT jstring JNICALL
Java_com_alaa_securehello_SecurityHelper_checkDebug(JNIEnv* env, jobject) {
    if (isBeingDebugged()) { killApp(); return env->NewStringUTF("NOK"); }
    return env->NewStringUTF("OK");
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_alaa_securehello_SecurityHelper_checkEmulator(JNIEnv* env, jobject) {
    if (isEmulator()) { killApp(); return env->NewStringUTF("NOK"); }
    return env->NewStringUTF("OK");
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_alaa_securehello_SecurityHelper_checkFrida(JNIEnv* env, jobject) {
    if (isFridaPresent()) { killApp(); return env->NewStringUTF("NOK"); }
    return env->NewStringUTF("OK");
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_alaa_securehello_SecurityHelper_checkRoot(JNIEnv* env, jobject) {
    if (isRooted()) { killApp(); return env->NewStringUTF("NOK"); }
    return env->NewStringUTF("OK");
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_alaa_securehello_SecurityHelper_checkXposed(JNIEnv* env, jobject) {
    if (isXposedPresent()) { killApp(); return env->NewStringUTF("NOK"); }
    return env->NewStringUTF("OK");
}

extern "C" JNIEXPORT jboolean JNICALL
Java_com_alaa_securehello_SecurityHelper_checkPackageName(JNIEnv* env, jobject, jobject context) {
    jclass ctxClass = env->GetObjectClass(context);
    jmethodID getPkg = env->GetMethodID(ctxClass, "getPackageName", "()Ljava/lang/String;");
    jstring pkgName = (jstring)env->CallObjectMethod(context, getPkg);
    const char* pkg = env->GetStringUTFChars(pkgName, nullptr);
    bool valid = (decryptPkg() == pkg);
    env->ReleaseStringUTFChars(pkgName, pkg);
    if (!valid) killApp();
    return valid ? JNI_TRUE : JNI_FALSE;
}

extern "C" JNIEXPORT void JNICALL
Java_com_alaa_securehello_SecurityHelper_initCRC(JNIEnv* env, jobject, jobject context) {
    initApkCRC(env, context);
}

extern "C" JNIEXPORT jboolean JNICALL
Java_com_alaa_securehello_SecurityHelper_checkApkIntegrity(JNIEnv* env, jobject, jobject context) {
    if (isApkModified(env, context)) { killApp(); return JNI_FALSE; }
    return JNI_TRUE;
}

extern "C" JNIEXPORT void JNICALL
Java_com_alaa_securehello_SecurityHelper_killIfTampered(JNIEnv*, jobject) {
    killApp();
}
