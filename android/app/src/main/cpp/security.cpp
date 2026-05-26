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

static void killApp() {
    kill(getpid(), SIGKILL);
}

static bool isBeingDebugged() {
    std::ifstream status("/proc/self/status");
    std::string line;
    while (std::getline(status, line)) {
        if (line.find("TracerPid:") != std::string::npos) {
            int pid = std::stoi(line.substr(line.find(':') + 1));
            if (pid != 0) return true;
        }
    }
    return false;
}

static bool isEmulator() {
    std::ifstream cpuinfo("/proc/cpuinfo");
    std::string content((std::istreambuf_iterator<char>(cpuinfo)),
                         std::istreambuf_iterator<char>());
    if (content.find("Goldfish") != std::string::npos) return true;
    if (content.find("ranchu") != std::string::npos) return true;
    const char* emuFiles[] = {
        "/dev/socket/qemud", "/dev/qemu_pipe",
        "/system/lib/libc_malloc_debug_qemu.so",
        "/sys/qemu_trace", "/system/bin/qemu-props"
    };
    for (auto f : emuFiles) {
        struct stat st;
        if (stat(f, &st) == 0) return true;
    }
    return false;
}

static bool isFridaPresent() {
    std::ifstream maps("/proc/self/maps");
    std::string line;
    while (std::getline(maps, line)) {
        if (line.find("frida") != std::string::npos) return true;
        if (line.find("gadget") != std::string::npos) return true;
    }
    std::ifstream tcp("/proc/net/tcp");
    while (std::getline(tcp, line)) {
        if (line.find("699A") != std::string::npos) return true;
    }
    void* frida = dlopen("libfrida-agent.so", RTLD_LAZY | RTLD_NOLOAD);
    if (frida != nullptr) { dlclose(frida); return true; }
    return false;
}

static bool isRooted() {
    const char* rootPaths[] = {
        "/system/app/Superuser.apk", "/sbin/su",
        "/system/bin/su", "/system/xbin/su",
        "/data/local/xbin/su", "/data/local/bin/su",
        "/system/sd/xbin/su", "/data/local/su",
        "/system/bin/.ext/.su", "/system/xbin/mu"
    };
    for (auto p : rootPaths) {
        struct stat st;
        if (stat(p, &st) == 0) return true;
    }
    return false;
}

static void* securityThread(void*) {
    while (true) {
        sleep(30);
        if (isBeingDebugged()) killApp();
        if (isFridaPresent()) killApp();
    }
    return nullptr;
}

__attribute__((constructor))
static void onLibraryLoad() {
    // بدون ptrace — بس فحص Frida والـ debug
    if (isBeingDebugged()) killApp();
    if (isFridaPresent()) killApp();
    pthread_t thread;
    pthread_create(&thread, nullptr, securityThread, nullptr);
    pthread_detach(thread);
}

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
