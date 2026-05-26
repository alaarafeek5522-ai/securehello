#include <jni.h>
#include <string>
#include <fstream>
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>
#include <android/log.h>

#define TAG "SecureHello"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)

// Anti-debug: detect TracerPid
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

// Anti-emulator: check CPU info
static bool isEmulator() {
    std::ifstream cpuinfo("/proc/cpuinfo");
    std::string content((std::istreambuf_iterator<char>(cpuinfo)),
                         std::istreambuf_iterator<char>());
    if (content.find("Goldfish") != std::string::npos) return true;
    if (content.find("ranchu") != std::string::npos) return true;

    // Check for emulator files
    const char* emuFiles[] = {
        "/dev/socket/qemud",
        "/dev/qemu_pipe",
        "/system/lib/libc_malloc_debug_qemu.so",
        "/sys/qemu_trace",
        "/system/bin/qemu-props"
    };
    for (auto f : emuFiles) {
        struct stat st;
        if (stat(f, &st) == 0) return true;
    }
    return false;
}

// Anti-Frida: check maps and ports
static bool isFridaPresent() {
    std::ifstream maps("/proc/self/maps");
    std::string line;
    while (std::getline(maps, line)) {
        if (line.find("frida") != std::string::npos) return true;
        if (line.find("gadget") != std::string::npos) return true;
    }

    // Check /proc/net/tcp for Frida port 27042
    std::ifstream tcp("/proc/net/tcp");
    while (std::getline(tcp, line)) {
        if (line.find("699A") != std::string::npos) return true; // 27042 hex
    }
    return false;
}

// Root detection
static bool isRooted() {
    const char* rootPaths[] = {
        "/system/app/Superuser.apk",
        "/sbin/su",
        "/system/bin/su",
        "/system/xbin/su",
        "/data/local/xbin/su",
        "/data/local/bin/su",
        "/system/sd/xbin/su",
        "/system/bin/failsafe/su",
        "/data/local/su"
    };
    for (auto p : rootPaths) {
        struct stat st;
        if (stat(p, &st) == 0) return true;
    }
    return false;
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_alaa_securehello_SecurityHelper_checkDebug(JNIEnv* env, jobject) {
    if (isBeingDebugged()) return env->NewStringUTF("DEBUG_DETECTED");
    return env->NewStringUTF("OK");
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_alaa_securehello_SecurityHelper_checkEmulator(JNIEnv* env, jobject) {
    if (isEmulator()) return env->NewStringUTF("EMULATOR_DETECTED");
    return env->NewStringUTF("OK");
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_alaa_securehello_SecurityHelper_checkFrida(JNIEnv* env, jobject) {
    if (isFridaPresent()) return env->NewStringUTF("FRIDA_DETECTED");
    return env->NewStringUTF("OK");
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_alaa_securehello_SecurityHelper_checkRoot(JNIEnv* env, jobject) {
    if (isRooted()) return env->NewStringUTF("ROOT_DETECTED");
    return env->NewStringUTF("OK");
}
