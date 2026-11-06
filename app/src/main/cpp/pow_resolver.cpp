#include <jni.h>
#include <cstdio>
#include <cstring>
#include <cstdint>
#include <cstdlib>
#include <string>
#include <vector>
#include <dlfcn.h>
#include <link.h>
#include <elf.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <poll.h>
#include <android/log.h>

#define TAG "PowResolver"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

#define ANCHOR_SYM "Java_com_deepseek_crypto_PowCalculator_nativeCalculateDeepSeekHashV1Pow"

typedef jlong (*JniCalcSig)(JNIEnv*, jclass, jstring, jstring, jlong);
typedef long long (*PowFunc)(const char*, int, const char*, int, long long);

static void* g_handle = nullptr;
static std::string g_soPath;
static uintptr_t g_runtimeBase = 0;
static long long g_delta = -1;
static JniCalcSig g_jniCalc = nullptr;
static PowFunc g_pow = nullptr;

struct ElfView {
    uint8_t* data = nullptr;
    size_t size = 0;
    int fd = -1;
    Elf64_Ehdr* eh = nullptr;
    Elf64_Shdr* sh = nullptr;
    const char* shstr = nullptr;
    int shnum = 0;
};

static bool mapElf(const char* path, ElfView& v) {
    v.fd = open(path, O_RDONLY);
    if (v.fd < 0) return false;
    struct stat st;
    if (fstat(v.fd, &st) != 0 || st.st_size < (off_t)sizeof(Elf64_Ehdr)) { close(v.fd); v.fd = -1; return false; }
    v.size = (size_t)st.st_size;
    v.data = (uint8_t*)mmap(nullptr, v.size, PROT_READ, MAP_PRIVATE, v.fd, 0);
    if (v.data == MAP_FAILED) { v.data = nullptr; close(v.fd); v.fd = -1; return false; }
    v.eh = (Elf64_Ehdr*)v.data;
    if (memcmp(v.eh->e_ident, ELFMAG, SELFMAG) != 0 || v.eh->e_ident[EI_CLASS] != ELFCLASS64) {
        munmap(v.data, v.size); v.data = nullptr; close(v.fd); v.fd = -1; return false;
    }
    v.sh = (Elf64_Shdr*)(v.data + v.eh->e_shoff);
    v.shnum = (int)v.eh->e_shnum;
    if (v.eh->e_shstrndx < v.eh->e_shnum) v.shstr = (const char*)(v.data + v.sh[v.eh->e_shstrndx].sh_offset);
    return true;
}

static void unmapElf(ElfView& v) {
    if (v.data) munmap(v.data, v.size);
    if (v.fd >= 0) close(v.fd);
    v.data = nullptr; v.fd = -1;
}

static Elf64_Shdr* findSection(ElfView& v, const char* name) {
    if (!v.shstr) return nullptr;
    for (int i = 0; i < v.shnum; i++)
        if (strcmp(v.shstr + v.sh[i].sh_name, name) == 0) return &v.sh[i];
    return nullptr;
}

static uint64_t findSymbolVaddr(ElfView& v, const char* sym) {
    uint64_t found = 0;
    for (int i = 0; i < v.shnum && found == 0; i++) {
        Elf64_Shdr& s = v.sh[i];
        if (s.sh_type != SHT_DYNSYM && s.sh_type != SHT_SYMTAB) continue;
        Elf64_Sym* syms = (Elf64_Sym*)(v.data + s.sh_offset);
        size_t n = s.sh_size / sizeof(Elf64_Sym);
        if (s.sh_link >= (uint64_t)v.shnum) continue;
        const char* strtab = (const char*)(v.data + v.sh[s.sh_link].sh_offset);
        for (size_t k = 1; k < n; k++) {
            if (syms[k].st_name == 0 || syms[k].st_value == 0) continue;
            if (strcmp(strtab + syms[k].st_name, sym) == 0) { found = syms[k].st_value; break; }
        }
    }
    return found;
}

static uint64_t computeLoadBias(ElfView& v) {
    if (!v.eh->e_phoff) return 0;
    Elf64_Phdr* ph = (Elf64_Phdr*)(v.data + v.eh->e_phoff);
    uint64_t lo = UINT64_MAX;
    for (int i = 0; i < v.eh->e_phnum; i++)
        if (ph[i].p_type == PT_LOAD && ph[i].p_vaddr < lo) lo = ph[i].p_vaddr;
    return lo == UINT64_MAX ? 0 : lo;
}

static bool fileVaddrToOff(ElfView& v, uint64_t vaddr, uint64_t& off) {
    if (!v.eh->e_phoff) return false;
    Elf64_Phdr* ph = (Elf64_Phdr*)(v.data + v.eh->e_phoff);
    for (int i = 0; i < v.eh->e_phnum; i++) {
        if (ph[i].p_type != PT_LOAD) continue;
        if (vaddr >= ph[i].p_vaddr && vaddr < ph[i].p_vaddr + ph[i].p_filesz) {
            off = vaddr - ph[i].p_vaddr + ph[i].p_offset;
            return true;
        }
    }
    return false;
}

static void collectCallTargets(const uint8_t* code, size_t len, uint64_t pcVaddr,
                               uint64_t textLo, uint64_t textHi, std::vector<uint64_t>& out) {
    for (size_t i = 0; i + 4 <= len; i += 4) {
        uint32_t w; memcpy(&w, code + i, 4);
        uint32_t op = (w >> 26) & 0x3F;
        if (op != 0x25 && op != 0x05) continue;
        int32_t imm = (int32_t)(w & 0x03FFFFFF);
        if (imm & 0x02000000) imm |= (int32_t)0xFC000000;
        int64_t tgt = (int64_t)(pcVaddr + i) + (int64_t)imm * 4;
        if (tgt <= 0) continue;
        uint64_t t = (uint64_t)tgt;
        if (t < textLo || t >= textHi) continue;
        if (t % 4 != 0) continue;
        bool dup = false;
        for (uint64_t x : out) if (x == t) { dup = true; break; }
        if (!dup) out.push_back(t);
    }
}

static bool ensureLoaded(const char* path) {
    if (g_handle && g_soPath == path && g_jniCalc) return true;
    if (g_handle) { dlclose(g_handle); g_handle = nullptr; }
    g_handle = dlopen(path, RTLD_NOW | RTLD_LOCAL);
    if (!g_handle) { LOGE("dlopen fail: %s", dlerror()); return false; }
    void* fn = dlsym(g_handle, ANCHOR_SYM);
    if (!fn) { LOGE("dlsym fail"); dlclose(g_handle); g_handle = nullptr; return false; }
    Dl_info info;
    if (!dladdr(fn, &info) || !info.dli_fbase) { dlclose(g_handle); g_handle = nullptr; return false; }
    g_runtimeBase = (uintptr_t)info.dli_fbase;
    g_jniCalc = (JniCalcSig)fn;
    g_soPath = path;
    g_pow = nullptr;
    return true;
}

static jlong jniCalc(JNIEnv* env, jstring challenge, jstring base, jlong difficulty) {
    if (!g_jniCalc) return -1;
    return g_jniCalc(env, nullptr, challenge, base, difficulty);
}

static bool testOffsetAt(JNIEnv* env, long long delta, jstring challenge, jstring base,
                         jlong difficulty, jlong expected, long long* actual) {
    if (!g_runtimeBase) return false;
    const char* c = env->GetStringUTFChars(challenge, nullptr);
    const char* b = env->GetStringUTFChars(base, nullptr);
    int cl = (int)strlen(c), bl = (int)strlen(b);
    int fds[2];
    if (pipe(fds) != 0) { env->ReleaseStringUTFChars(challenge, c); env->ReleaseStringUTFChars(base, b); return false; }
    pid_t pid = fork();
    if (pid < 0) { close(fds[0]); close(fds[1]); env->ReleaseStringUTFChars(challenge, c); env->ReleaseStringUTFChars(base, b); return false; }
    if (pid == 0) {
        close(fds[0]);
        prctl(PR_SET_DUMPABLE, 0);
        alarm(2);
        PowFunc f = (PowFunc)(g_runtimeBase + (uintptr_t)delta);
        long long r = f(c, cl, b, bl, (long long)difficulty);
        if (write(fds[1], &r, sizeof(r)) != (ssize_t)sizeof(r)) _exit(1);
        _exit(0);
    }
    close(fds[1]);
    struct pollfd pfd; pfd.fd = fds[0]; pfd.events = POLLIN;
    long long r = -1; bool got = false;
    if (poll(&pfd, 1, 2500) > 0) {
        ssize_t n = read(fds[0], &r, sizeof(r));
        if (n == (ssize_t)sizeof(r)) got = true;
    }
    close(fds[0]);
    int st = 0; waitpid(pid, &st, 0);
    env->ReleaseStringUTFChars(challenge, c);
    env->ReleaseStringUTFChars(base, b);
    if (actual) *actual = r;
    return got && r == (long long)expected;
}

extern "C" JNIEXPORT jlong JNICALL
Java_com_powrouter_app_PowResolver_nativeResolve(
        JNIEnv* env, jclass, jstring soPath, jstring challenge, jstring base, jlong difficulty) {
    const char* path = env->GetStringUTFChars(soPath, nullptr);
    long long delta = -1;
    if (!ensureLoaded(path)) {
        env->ReleaseStringUTFChars(soPath, path);
        return -1;
    }
    jlong truth = jniCalc(env, challenge, base, difficulty);
    if (truth < 0) {
        LOGE("JNI truth failed %lld", (long long)truth);
        env->ReleaseStringUTFChars(soPath, path);
        return -1;
    }
    LOGI("JNI truth=%lld", (long long)truth);

    ElfView v;
    if (!mapElf(path, v)) { env->ReleaseStringUTFChars(soPath, path); return -2; }
    uint64_t anchorVaddr = findSymbolVaddr(v, ANCHOR_SYM);
    uint64_t bias = computeLoadBias(v);
    Elf64_Shdr* text = findSection(v, ".text");
    if (anchorVaddr == 0 || !text) {
        unmapElf(v);
        env->ReleaseStringUTFChars(soPath, path);
        return -2;
    }
    uint64_t textLo = text->sh_addr, textHi = text->sh_addr + text->sh_size;
    uint64_t anchorOff = 0;
    if (!fileVaddrToOff(v, anchorVaddr, anchorOff)) {
        unmapElf(v);
        env->ReleaseStringUTFChars(soPath, path);
        return -2;
    }
    std::vector<uint64_t> targets;
    size_t scanLen = 0x4000;
    if (anchorOff + scanLen > v.size) scanLen = v.size - anchorOff;
    collectCallTargets(v.data + anchorOff, scanLen, anchorVaddr, textLo, textHi, targets);
    LOGI("anchor=%llx bias=%llx candidates=%zu", (unsigned long long)anchorVaddr, (unsigned long long)bias, targets.size());
    unmapElf(v);

    for (uint64_t t : targets) {
        if (t == anchorVaddr) continue;
        long long d = (long long)(t - bias);
        long long actual = 0;
        if (testOffsetAt(env, d, challenge, base, difficulty, truth, &actual)) {
            delta = d;
            LOGI("MATCH delta=0x%llx result=%lld", delta, actual);
            break;
        }
    }
    env->ReleaseStringUTFChars(soPath, path);
    if (delta < 0) { g_delta = -1; g_pow = nullptr; return -2; }
    g_delta = delta;
    g_pow = (PowFunc)(g_runtimeBase + (uintptr_t)delta);
    return delta;
}

extern "C" JNIEXPORT jlong JNICALL
Java_com_powrouter_app_PowResolver_nativeCalculate(
        JNIEnv* env, jclass, jstring soPath, jstring challenge, jstring base,
        jlong difficulty, jlong delta) {
    const char* path = env->GetStringUTFChars(soPath, nullptr);
    bool ok = ensureLoaded(path);
    env->ReleaseStringUTFChars(soPath, path);
    if (!ok) return -1;
    jlong r = jniCalc(env, challenge, base, difficulty);
    if (r >= 0) return r;
    if (delta >= 0 && g_runtimeBase) {
        PowFunc f = (PowFunc)(g_runtimeBase + (uintptr_t)delta);
        const char* c = env->GetStringUTFChars(challenge, nullptr);
        const char* b = env->GetStringUTFChars(base, nullptr);
        r = f(c, (int)strlen(c), b, (int)strlen(b), (long long)difficulty);
        env->ReleaseStringUTFChars(challenge, c);
        env->ReleaseStringUTFChars(base, b);
    }
    return r;
}

extern "C" JNIEXPORT jlong JNICALL
Java_com_powrouter_app_PowResolver_nativeCalculateViaJni(
        JNIEnv* env, jclass, jstring soPath, jstring challenge, jstring base, jlong difficulty) {
    const char* path = env->GetStringUTFChars(soPath, nullptr);
    bool ok = ensureLoaded(path);
    env->ReleaseStringUTFChars(soPath, path);
    if (!ok) return -1;
    return jniCalc(env, challenge, base, difficulty);
}

extern "C" JNIEXPORT jboolean JNICALL
Java_com_powrouter_app_PowResolver_nativeSelfTest(
        JNIEnv* env, jclass, jstring soPath, jlong delta,
        jstring challenge, jstring base, jlong difficulty) {
    const char* path = env->GetStringUTFChars(soPath, nullptr);
    bool ok = ensureLoaded(path);
    env->ReleaseStringUTFChars(soPath, path);
    if (!ok) return JNI_FALSE;
    jlong truth = jniCalc(env, challenge, base, difficulty);
    if (truth < 0) return JNI_FALSE;
    jlong t2 = jniCalc(env, challenge, base, difficulty);
    if (t2 != truth) return JNI_FALSE;
    if (delta >= 0) {
        long long actual = 0;
        if (!testOffsetAt(env, delta, challenge, base, difficulty, truth, &actual)) return JNI_FALSE;
    }
    return JNI_TRUE;
}

extern "C" JNIEXPORT jboolean JNICALL
Java_com_powrouter_app_PowResolver_nativeQualityCheck(
        JNIEnv* env, jclass, jstring soPath, jstring challenge, jstring base,
        jlong difficulty, jlong delta) {
    const char* path = env->GetStringUTFChars(soPath, nullptr);
    bool ok = ensureLoaded(path);
    env->ReleaseStringUTFChars(soPath, path);
    if (!ok) return JNI_FALSE;
    jlong truth = jniCalc(env, challenge, base, difficulty);
    if (truth < 0) { LOGE("QC: jni truth failed"); return JNI_FALSE; }
    jlong t2 = jniCalc(env, challenge, base, difficulty);
    if (t2 != truth) { LOGE("QC: jni not deterministic %lld vs %lld", (long long)truth, (long long)t2); return JNI_FALSE; }
    if (delta >= 0) {
        long long actual = 0;
        if (!testOffsetAt(env, delta, challenge, base, difficulty, truth, &actual)) {
            LOGE("QC: offset mismatch actual=%lld truth=%lld", actual, (long long)truth);
            return JNI_FALSE;
        }
    }
    LOGI("QC OK");
    return JNI_TRUE;
}