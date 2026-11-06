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

typedef long long (*PowFunc)(const char*, int, const char*, int, long long);

static void* g_handle = nullptr;
static std::string g_soPath;
static uintptr_t g_runtimeBase = 0;
static long long g_delta = -1;
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
    if (g_handle && g_soPath == path) return true;
    if (g_handle) { dlclose(g_handle); g_handle = nullptr; }
    g_handle = dlopen(path, RTLD_NOW | RTLD_LOCAL);
    if (!g_handle) { LOGE("dlopen fail: %s", dlerror()); return false; }
    void* fn = dlsym(g_handle, ANCHOR_SYM);
    if (!fn) { LOGE("dlsym anchor fail"); dlclose(g_handle); g_handle = nullptr; return false; }
    Dl_info info;
    if (!dladdr(fn, &info) || !info.dli_fbase) { dlclose(g_handle); g_handle = nullptr; return false; }
    g_runtimeBase = (uintptr_t)info.dli_fbase;
    g_soPath = path;
    g_pow = nullptr;
    return true;
}

// 用真实 challenge 测试偏移函数。判断标准：非负、两次调用一致。
// difficulty 建议传一个低值（如 1），使真实 PoW 快速返回。
static bool testOffsetAt(JNIEnv* env, long long delta, jstring challenge, jstring base,
                         jlong difficulty, long long* actual) {
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
        alarm(5);
        PowFunc f = (PowFunc)(g_runtimeBase + (uintptr_t)delta);
        long long r1 = f(c, cl, b, bl, (long long)difficulty);
        if (r1 < 0) _exit(3);
        if (r1 > 1000000000LL) _exit(5);  // 真 PoW nonce 不会超过 1e9
        long long r2 = f(c, cl, b, bl, (long long)difficulty);
        if (r2 != r1) _exit(4);
        if (write(fds[1], &r1, sizeof(r1)) != (ssize_t)sizeof(r1)) _exit(1);
        _exit(0);
    }
    close(fds[1]);
    struct pollfd pfd; pfd.fd = fds[0]; pfd.events = POLLIN;
    long long r = -1; bool got = false;
    if (poll(&pfd, 1, 6000) > 0) {
        ssize_t n = read(fds[0], &r, sizeof(r));
        if (n == (ssize_t)sizeof(r)) got = true;
    }
    close(fds[0]);
    int st = 0; waitpid(pid, &st, 0);
    env->ReleaseStringUTFChars(challenge, c);
    env->ReleaseStringUTFChars(base, b);
    if (actual) *actual = r;
    return got && r >= 0;
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
    LOGI("anchor=%llx bias=%llx", (unsigned long long)anchorVaddr, (unsigned long long)bias);
    std::vector<uint64_t> targets;
    size_t scanLen = 0x4000;
    if (anchorOff + scanLen > v.size) scanLen = v.size - anchorOff;
    collectCallTargets(v.data + anchorOff, scanLen, anchorVaddr, textLo, textHi, targets);
    LOGI("candidates=%zu", targets.size());
    unmapElf(v);

    // 优先测试已知历史偏移（0x19bc0 是 SuperRouter 验证过的正确偏移）
    static const long long legacy[] = { 0x19bc0, 0x19c00, 0x19b80, 0x19c40, 0x1a000, 0x1a100, 0x1a200, 0x19e00, 0x19800 };
    for (long long d : legacy) {
        long long actual = 0;
        if (testOffsetAt(env, d, challenge, base, difficulty, &actual)) {
            delta = d;
            LOGI("LEGACY MATCH delta=0x%llx result=%lld", delta, actual);
            break;
        }
    }

    // 再扫描调用目标
    if (delta < 0) {
        for (uint64_t t : targets) {
            if (t == anchorVaddr) continue;
            long long d = (long long)(t - bias);
            long long actual = 0;
            if (testOffsetAt(env, d, challenge, base, difficulty, &actual)) {
                delta = d;
                LOGI("MATCH delta=0x%llx result=%lld", delta, actual);
                break;
            }
        }
    }

    env->ReleaseStringUTFChars(soPath, path);
    if (delta < 0) { g_delta = -1; g_pow = nullptr; return -3; }
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
    if (delta < 0 || !g_runtimeBase) return -1;
    PowFunc f = (PowFunc)(g_runtimeBase + (uintptr_t)delta);
    const char* c = env->GetStringUTFChars(challenge, nullptr);
    const char* b = env->GetStringUTFChars(base, nullptr);
    long long r = f(c, (int)strlen(c), b, (int)strlen(b), (long long)difficulty);
    env->ReleaseStringUTFChars(challenge, c);
    env->ReleaseStringUTFChars(base, b);
    return r;
}

extern "C" JNIEXPORT jlong JNICALL
Java_com_powrouter_app_PowResolver_nativeCalculateViaJni(
        JNIEnv* env, jclass, jstring soPath, jstring challenge, jstring base, jlong difficulty) {
    // 保留兼容：等价于 nativeCalculate（需先解析 delta，否则返回 -1）
    return Java_com_powrouter_app_PowResolver_nativeCalculate(
        env, nullptr, soPath, challenge, base, difficulty, g_delta);
}

extern "C" JNIEXPORT jboolean JNICALL
Java_com_powrouter_app_PowResolver_nativeSelfTest(
        JNIEnv* env, jclass, jstring soPath, jlong delta,
        jstring challenge, jstring base, jlong difficulty) {
    const char* path = env->GetStringUTFChars(soPath, nullptr);
    bool ok = ensureLoaded(path);
    env->ReleaseStringUTFChars(soPath, path);
    if (!ok) return JNI_FALSE;
    if (delta < 0) return JNI_FALSE;
    long long actual = 0;
    bool pass = testOffsetAt(env, delta, challenge, base, difficulty, &actual);
    LOGI("selfTest delta=0x%llx pass=%d actual=%lld", (long long)delta, pass ? 1 : 0, actual);
    return pass ? JNI_TRUE : JNI_FALSE;
}

extern "C" JNIEXPORT jboolean JNICALL
Java_com_powrouter_app_PowResolver_nativeQualityCheck(
        JNIEnv* env, jclass, jstring soPath, jstring challenge, jstring base,
        jlong difficulty, jlong delta) {
    const char* path = env->GetStringUTFChars(soPath, nullptr);
    bool ok = ensureLoaded(path);
    env->ReleaseStringUTFChars(soPath, path);
    if (!ok) { LOGE("QC: ensureLoaded fail"); return JNI_FALSE; }
    if (delta < 0) { LOGE("QC: delta<0"); return JNI_FALSE; }
    long long a1 = 0, a2 = 0;
    if (!testOffsetAt(env, delta, challenge, base, difficulty, &a1)) { LOGE("QC: round1 fail"); return JNI_FALSE; }
    if (!testOffsetAt(env, delta, challenge, base, difficulty, &a2)) { LOGE("QC: round2 fail"); return JNI_FALSE; }
    if (a1 != a2) { LOGE("QC: inconsistent %lld vs %lld", a1, a2); return JNI_FALSE; }
    LOGI("QC OK delta=0x%llx result=%lld", (long long)delta, a1);
    return JNI_TRUE;
}