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

static void killApp() { kill(getpid(), SIGKILL); }

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
    // فحص wchan
    std::ifstream wchan("/proc/self/wchan");
    std::string wc;
    wchan >> wc;
    if (wc == "ptrace_stop") return true;
    return false;
}

// ======= FRIDA =======
static bool isFridaPresent() {
    // فحص maps
    std::ifstream maps("/proc/self/maps");
    std::string line;
    while (std::getline(maps, line)) {
        if (line.find("frida") != std::string::npos) return true;
        if (line.find("gadget") != std::string::npos) return true;
        if (line.find("linjector") != std::string::npos) return true;
    }
    // فحص ports
    const char* tcpFiles[] = {"/proc/net/tcp", "/proc/net/tcp6"};
    for (auto f : tcpFiles) {
        std::ifstream tcp(f);
        while (std::getline(tcp, line)) {
            if (line.find("699A") != std::string::npos) return true;
            if (line.find("6B68") != std::string::npos) return true; // 27496
        }
    }
    // فحص dlopen
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
                if (r.find("frida") != std::string::npos) { closedir(dir); return true; }
            }
        }
        closedir(dir);
    }
    return false;
}

// ======= ROOT =======
static bool isRooted() {
    const char* rootPaths[] = {
        "/system/app/Superuser.apk", "/sbin/su",
        "/system/bin/su", "/system/xbin/su",
        "/data/local/xbin/su", "/data/local/bin/su",
        "/system/sd/xbin/su", "/data/local/su",
        "/system/bin/.ext/.su", "/system/xbin/mu",
        "/system/app/SuperSU.apk", "/system/xbin/daemonsu"
    };
    for (auto p : rootPaths) {
        struct stat st;
        if (stat(p, &st) == 0) return true;
    }
    return false;
}

// ======= EMULATOR =======
static bool isEmulator() {
    char val[PROP_VALUE_MAX];
    __system_property_get("ro.hardware", val);
    if (std::string(val).find("goldfish") != std::string::npos) return true;
    if (std::string(val).find("ranchu") != std::string::npos) return true;
    __system_property_get("ro.product.model", val);
    if (std::string(val).find("Android SDK") != std::string::npos) return true;
    __system_property_get("ro.kernel.qemu", val);
    if (std::string(val) == "1") return true;
    const char* emuFiles[] = {
        "/dev/socket/qemud", "/dev/qemu_pipe",
        "/sys/qemu_trace", "/system/bin/qemu-props"
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

// ======= MEMORY PATCH =======
static bool isMemoryPatched() {
    std::ifstream maps("/proc/self/maps");
    std::string line;
    while (std::getline(maps, line)) {
        // لو في منطقة rwx (مكتوبة وقابلة للتنفيذ) — خطر
        if (line.find("rwxp") != std::string::npos) return true;
    }
    return false;
}

// ======= THREAD بفترات عشوائية =======
static void* securityThread(void*) {
    while (true) {
        // فترة عشوائية بين 10 و 40 ثانية
        int delay = 10 + (rand() % 30);
        sleep(delay);
        if (isBeingDebugged()) killApp();
        if (isFridaPresent()) killApp();
        if (isXposedPresent()) killApp();
        if (isMemoryPatched()) killApp();
    }
    return nullptr;
}

// ======= THREAD تاني بفترة مختلفة =======
static void* securityThread2(void*) {
    while (true) {
        sleep(17);
        if (isBeingDebugged()) killApp();
        if (isFridaPresent()) killApp();
    }
    return nullptr;
}

// ======= CONSTRUCTOR — بيشتغل عند تحميل الـ .so =======
__attribute__((constructor))
static void onLibraryLoad() {
    if (isBeingDebugged()) killApp();
    if (isFridaPresent()) killApp();
    if (isXposedPresent()) killApp();
    // شغّل اتنين threads
    pthread_t t1, t2;
    pthread_create(&t1, nullptr, securityThread, nullptr);
    pthread_detach(t1);
    pthread_create(&t2, nullptr, securityThread2, nullptr);
    pthread_detach(t2);
}

// ======= JNI FUNCTIONS =======
extern "C" JNIEXPORT jstring JNICALL
Java_com_alaa_securehello_SecurityHelper_checkDebug(JNIEnv* env, jobject) {
    if (isBeingDebugged()) { killApp(); return env->NewStringUTF("DEBUG_DETECTED"); }
    return env->NewStringUTF("OK");
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_alaa_securehello_SecurityHelper_checkEmulator(JNIEnv* env, jobject) {
    if (isEmulator()) { killApp(); return env->NewStringUTF("EMULATOR_DETECTED"); }
    return env->NewStringUTF("OK");
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_alaa_securehello_SecurityHelper_checkFrida(JNIEnv* env, jobject) {
    if (isFridaPresent()) { killApp(); return env->NewStringUTF("FRIDA_DETECTED"); }
    return env->NewStringUTF("OK");
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_alaa_securehello_SecurityHelper_checkRoot(JNIEnv* env, jobject) {
    if (isRooted()) { killApp(); return env->NewStringUTF("ROOT_DETECTED"); }
    return env->NewStringUTF("OK");
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_alaa_securehello_SecurityHelper_checkXposed(JNIEnv* env, jobject) {
    if (isXposedPresent()) { killApp(); return env->NewStringUTF("XPOSED_DETECTED"); }
    return env->NewStringUTF("OK");
}

extern "C" JNIEXPORT jboolean JNICALL
Java_com_alaa_securehello_SecurityHelper_checkPackageName(JNIEnv* env, jobject, jobject context) {
    jclass ctxClass = env->GetObjectClass(context);
    jmethodID getPkg = env->GetMethodID(ctxClass, "getPackageName", "()Ljava/lang/String;");
    jstring pkgName = (jstring)env->CallObjectMethod(context, getPkg);
    const char* pkg = env->GetStringUTFChars(pkgName, nullptr);
    bool valid = (std::string("com.alaa.securehello") == pkg);
    env->ReleaseStringUTFChars(pkgName, pkg);
    if (!valid) killApp();
    return valid ? JNI_TRUE : JNI_FALSE;
}

extern "C" JNIEXPORT void JNICALL
Java_com_alaa_securehello_SecurityHelper_killIfTampered(JNIEnv*, jobject) {
    killApp();
}
