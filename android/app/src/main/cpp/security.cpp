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
#include <link.h>

static void killApp() { kill(getpid(), SIGKILL); }

// package name مشفر compile-time
static const uint8_t ENC_PKG[] = {
    0x19,0x13,0x18,0x2e,0x1f,0x18,0x1f,0x2e,
    0x39,0x1b,0x13,0x1e,0x28,0x1b,0x18,0x18,
    0x1d,0x2e,0x39,0x1b,0x13,0x1e,0x28,0x1b,
    0x18,0x18,0x1d
};
static const uint8_t PKG_KEY = 0x7A;

static std::string decryptPkg() {
    std::string r;
    for (size_t i = 0; i < sizeof(ENC_PKG); i++)
        r += (char)(ENC_PKG[i] ^ PKG_KEY);
    return r;
}

// ======= DEBUG =======
static bool isBeingDebugged() {
    // فحص TracerPid
    std::ifstream status("/proc/self/status");
    std::string line;
    while (std::getline(status, line)) {
        if (line.find("TracerPid:") != std::string::npos) {
            int pid = std::stoi(line.substr(line.find(':') + 1));
            if (pid != 0) return true;
        }
    }
    // فحص wchan
    std::ifstream wchan("/proc/self/wchan");
    std::string wc; wchan >> wc;
    if (wc == "ptrace_stop") return true;
    // فحص status flags
    std::ifstream statf("/proc/self/stat");
    std::string stat_content;
    std::getline(statf, stat_content);
    // لو فيه debugger هيبان في الـ flags
    return false;
}

static bool isFridaPresent() {
    std::ifstream maps("/proc/self/maps");
    std::string line;
    while (std::getline(maps, line)) {
        if (line.find("frida") != std::string::npos) return true;
        if (line.find("gadget") != std::string::npos) return true;
        if (line.find("linjector") != std::string::npos) return true;
        if (line.find("re.frida") != std::string::npos) return true;
    }
    const char* tcpFiles[] = {"/proc/net/tcp", "/proc/net/tcp6"};
    for (auto f : tcpFiles) {
        std::ifstream tcp(f);
        while (std::getline(tcp, line)) {
            if (line.find("699A") != std::string::npos) return true;
            if (line.find("6B68") != std::string::npos) return true;
        }
    }
    const char* fridaLibs[] = {
        "libfrida-agent.so", "libfrida-gadget.so",
        "libfrida.so", "libgadget.so"
    };
    for (auto lib : fridaLibs) {
        void* h = dlopen(lib, RTLD_LAZY | RTLD_NOLOAD);
        if (h) { dlclose(h); return true; }
    }
    // فحص /proc/self/fd
    DIR* dir = opendir("/proc/self/fd");
    if (dir) {
        struct dirent* entry;
        while ((entry = readdir(dir)) != nullptr) {
            char path[256], resolved[256];
            snprintf(path, sizeof(path), "/proc/self/fd/%s", entry->d_name);
            ssize_t len = readlink(path, resolved, sizeof(resolved)-1);
            if (len > 0) {
                resolved[len] = 0;
                std::string r(resolved);
                if (r.find("frida") != std::string::npos ||
                    r.find("gadget") != std::string::npos) {
                    closedir(dir); return true;
                }
            }
        }
        closedir(dir);
    }
    // فحص environment variables
    const char* envVars[] = {"FRIDA_AGENT", "FRIDA_SERVER", "LD_PRELOAD"};
    for (auto v : envVars) {
        char* val = getenv(v);
        if (val != nullptr) return true;
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
        "/system/app/SuperSU.apk", "/system/xbin/daemonsu",
        "/system/etc/init.d/99SuperSUDaemon"
    };
    for (auto p : paths) {
        struct stat st;
        if (stat(p, &st) == 0) return true;
    }
    // فحص ro.build.tags
    char val[PROP_VALUE_MAX];
    __system_property_get("ro.build.tags", val);
    if (std::string(val).find("test-keys") != std::string::npos) return true;
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
    __system_property_get("ro.product.manufacturer", val);
    if (std::string(val) == "Genymotion") return true;
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
    const char* xFiles[] = {
        "/system/framework/XposedBridge.jar",
        "/system/lib/libxposed_art.so",
        "/system/lib64/libxposed_art.so",
        "/data/app/de.robv.android.xposed.installer",
        "/data/app/org.meowcat.edxposed.manager"
    };
    for (auto f : xFiles) {
        struct stat st;
        if (stat(f, &st) == 0) return true;
    }
    return false;
}

// ======= APK CRC =======
static uint32_t storedCRC = 0;

static uint32_t computeCRC32(const std::string& path) {
    std::ifstream file(path, std::ios::binary);
    if (!file) return 0;
    uint32_t crc = 0xFFFFFFFF;
    char buf[8192];
    while (file.read(buf, sizeof(buf)) || file.gcount() > 0) {
        for (int i = 0; i < (int)file.gcount(); i++) {
            crc ^= (uint8_t)buf[i];
            for (int j = 0; j < 8; j++)
                crc = (crc >> 1) ^ (0xEDB88320 & -(crc & 1));
        }
    }
    return crc ^ 0xFFFFFFFF;
}

static std::string getApkPath(JNIEnv* env, jobject context) {
    jclass ctxClass = env->GetObjectClass(context);
    jmethodID getAppInfo = env->GetMethodID(ctxClass, "getApplicationInfo",
        "()Landroid/content/pm/ApplicationInfo;");
    jobject appInfo = env->CallObjectMethod(context, getAppInfo);
    jclass aiClass = env->GetObjectClass(appInfo);
    jfieldID sourceDirField = env->GetFieldID(aiClass, "sourceDir", "Ljava/lang/String;");
    jstring sourceDir = (jstring)env->GetObjectField(appInfo, sourceDirField);
    const char* path = env->GetStringUTFChars(sourceDir, nullptr);
    std::string result(path);
    env->ReleaseStringUTFChars(sourceDir, path);
    return result;
}

// ======= THREADS =======
static void* securityThread(void*) {
    srand(time(nullptr));
    while (true) {
        sleep(8 + rand() % 15);
        if (isBeingDebugged()) killApp();
        if (isFridaPresent()) killApp();
        if (isXposedPresent()) killApp();
    }
    return nullptr;
}

static void* securityThread2(void*) {
    while (true) {
        sleep(5 + rand() % 10);
        if (isBeingDebugged()) killApp();
        if (isFridaPresent()) killApp();
    }
    return nullptr;
}

static void* securityThread3(void*) {
    while (true) {
        sleep(20 + rand() % 25);
        if (isRooted()) killApp();
        if (isEmulator()) killApp();
    }
    return nullptr;
}

// ======= CONSTRUCTOR =======
__attribute__((constructor))
static void onLibraryLoad() {
    if (isBeingDebugged()) killApp();
    if (isFridaPresent()) killApp();
    if (isXposedPresent()) killApp();
    // 3 threads بفترات مختلفة
    pthread_t t1, t2, t3;
    pthread_create(&t1, nullptr, securityThread, nullptr);
    pthread_detach(t1);
    pthread_create(&t2, nullptr, securityThread2, nullptr);
    pthread_detach(t2);
    pthread_create(&t3, nullptr, securityThread3, nullptr);
    pthread_detach(t3);
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
    std::string path = getApkPath(env, context);
    storedCRC = computeCRC32(path);
}

extern "C" JNIEXPORT jboolean JNICALL
Java_com_alaa_securehello_SecurityHelper_checkApkIntegrity(JNIEnv* env, jobject, jobject context) {
    if (storedCRC == 0) return JNI_TRUE;
    std::string path = getApkPath(env, context);
    uint32_t current = computeCRC32(path);
    if (current != storedCRC) { killApp(); return JNI_FALSE; }
    return JNI_TRUE;
}

extern "C" JNIEXPORT jboolean JNICALL
extern "C" JNIEXPORT jboolean JNICALL
Java_com_alaa_securehello_SecurityHelper_checkHooks(JNIEnv*, jobject) {
    char* preload = getenv("LD_PRELOAD");
    if (preload != nullptr) { killApp(); return JNI_FALSE; }
    return JNI_TRUE;
}
