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
#include <poll.h>
#include <android/log.h>

#define TAG "PowResolver"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)
#define ANCHOR_SYM_C "Java_com_deepseek_crypto_PowCalculator_nativeCalculateDeepSeekHashV1Pow"

typedef long long (*PowFunc)(const char*, int, const char*, int, long long);

static std::string g_soPath;
static void* g_handle = nullptr;
static uintptr_t g_loadBias = 0;
static PowFunc g_pow = nullptr;
static long long g_delta = -1;

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
    if (v.fd < 0) { LOGE("open fail %s", path); return false; }
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
        uint32_t w;
        memcpy(&w, code + i, 4);
        uint32_t op = (w >> 26) & 0x3F;
        if (op != 0x25 && op != 0x05) continue;  // BL / B
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

static bool testCandidate(uintptr_t addr, long long* resultOut) {
    int fds[2];
    if (pipe(fds) != 0) return false;
    pid_t pid = fork();
    if (pid < 0) { close(fds[0]); close(fds[1]); return false; }
    if (pid == 0) {
        close(fds[0]);
        alarm(3);
        PowFunc f = (PowFunc)addr;
        const char* ch = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        const char* base = "1700000000_1800000000_";
        // 依次用低难度验证，任一成功且稳定即认为命中
        long long diffs[3] = {1LL, 2LL, 0LL};
        long long good = -1;
        for (int di = 0; di < 3 && good < 0; di++) {
            long long r = f(ch, (int)strlen(ch), base, (int)strlen(base), diffs[di]);
            if (r < 0) continue;
            long long r2 = f(ch, (int)strlen(ch), base, (int)strlen(base), diffs[di]);
            if (r != r2) continue;
            good = r;
        }
        if (good < 0) _exit(9);
        if (write(fds[1], &good, sizeof(good)) != (ssize_t)sizeof(good)) _exit(8);
        _exit(0);
    }
    close(fds[1]);
    struct pollfd pfd; pfd.fd = fds[0]; pfd.events = POLLIN;
    bool ok = false;
    long long val = 0;
    if (poll(&pfd, 1, 4000) > 0) {
        ssize_t n = read(fds[0], &val, sizeof(val));
        if (n == (ssize_t)sizeof(val)) ok = true;
    }
    close(fds[0]);
    int status = 0;
    waitpid(pid, &status, 0);
    if (!ok || !WIFEXITED(status) || WEXITSTATUS(status) != 0) return false;
    *resultOut = val;
    return true;
}

extern "C" JNIEXPORT jlong JNICALL
Java_com_powrouter_app_PowResolver_nativeResolve(JNIEnv* env, jclass, jstring soPath, jstring anchorSym) {
    const char* path = env->GetStringUTFChars(soPath, nullptr);
    const char* anchor = env->GetStringUTFChars(anchorSym, nullptr);
    long long delta = -1;
    ElfView v;
    if (!mapElf(path, v)) { env->ReleaseStringUTFChars(soPath, path); env->ReleaseStringUTFChars(anchorSym, anchor); return -1; }

    uint64_t anchorVaddr = findSymbolVaddr(v, anchor);
    uint64_t bias = computeLoadBias(v);
    Elf64_Shdr* text = findSection(v, ".text");
    if (anchorVaddr == 0 || !text) {
        LOGE("anchor symbol not found: %s", anchor);
        unmapElf(v);
        env->ReleaseStringUTFChars(soPath, path);
        env->ReleaseStringUTFChars(anchorSym, anchor);
        return -1;
    }

    uint64_t textLo = text->sh_addr, textHi = text->sh_addr + text->sh_size;
    uint64_t anchorOff = 0;
    if (!fileVaddrToOff(v, anchorVaddr, anchorOff)) {
        unmapElf(v);
        env->ReleaseStringUTFChars(soPath, path);
        env->ReleaseStringUTFChars(anchorSym, anchor);
        return -1;
    }

    std::vector<uint64_t> targets;
    size_t scanLen = 0x4000;
    if (anchorOff + scanLen > v.size) scanLen = v.size - anchorOff;
    collectCallTargets(v.data + anchorOff, scanLen, anchorVaddr, textLo, textHi, targets);
    LOGI("anchor=%llx bias=%llx candidates=%zu", (unsigned long long)anchorVaddr,
         (unsigned long long)bias, targets.size());

    if (g_handle == nullptr) {
        g_handle = dlopen(path, RTLD_NOW | RTLD_LOCAL);
        if (!g_handle) { LOGE("dlopen fail: %s", dlerror()); }
    }
    if (g_handle) {
        void* anchorRuntime = dlsym(g_handle, anchor);
        if (anchorRuntime) {
            g_loadBias = (uintptr_t)anchorRuntime - (uintptr_t)(anchorVaddr - bias);
            for (uint64_t t : targets) {
                if (t == anchorVaddr) continue;
                long long r = 0;
                if (testCandidate(g_loadBias + (uintptr_t)(t - bias), &r)) {
                    delta = (long long)(t - bias);
                    LOGI("candidate OK delta=0x%llx result=%lld", delta, r);
                    break;
                }
            }
        }
    }

    if (delta < 0) {
        // 兜底：历史偏移候选，逐个 fork 验证
        static const long long legacy[] = { 0x19bc0, 0x19c00, 0x19b80, 0x19c40, 0x1a000, 0x1a100 };
        if (g_handle && g_loadBias) {
            for (long long d : legacy) {
                long long r = 0;
                if (testCandidate(g_loadBias + (uintptr_t)d, &r)) { delta = d; LOGI("legacy hit 0x%llx", d); break; }
            }
        }
    }

    g_soPath = path;
    g_delta = delta;
    g_pow = nullptr;
    unmapElf(v);
    env->ReleaseStringUTFChars(soPath, path);
    env->ReleaseStringUTFChars(anchorSym, anchor);
    return (jlong)delta;
}

extern "C" JNIEXPORT jlong JNICALL
Java_com_powrouter_app_PowResolver_nativeCalculate(JNIEnv* env, jclass, jstring soPath, jstring challenge,
                                                   jstring base, jlong difficulty, jlong delta) {
    const char* path = env->GetStringUTFChars(soPath, nullptr);
    if (g_handle == nullptr || g_soPath != path || g_delta != delta) {
        if (g_handle) { dlclose(g_handle); g_handle = nullptr; }
        g_handle = dlopen(path, RTLD_NOW | RTLD_LOCAL);
        g_soPath = path;
        g_delta = delta;
        g_pow = nullptr;
        if (g_handle) {
            Dl_info info;
            void* any = dlsym(g_handle, "Java_com_deepseek_crypto_PowCalculator_nativeCalculateDeepSeekHashV1Pow");
            if (!any) {
                // 用任意导出符号取基址
                ElfView v;
                if (mapElf(path, v)) {
                    uint64_t bias = computeLoadBias(v);
                    uint64_t a = findSymbolVaddr(v, "Java_com_deepseek_crypto_PowCalculator_nativeCalculateDeepSeekHashV1Pow");
                    unmapElf(v);
                    if (a) any = dlsym(g_handle, "JNI_OnLoad");
                    (void)bias;
                }
            }
            if (any && dladdr(any, &info)) {
                g_loadBias = (uintptr_t)info.dli_fbase;
                g_pow = (PowFunc)(g_loadBias + (uintptr_t)delta);
            } else {
                Dl_info bi;
                void* ip = dlsym(g_handle, ANCHOR_SYM_C);
                if (ip && dladdr(ip, &bi) && bi.dli_fbase) {
                    g_loadBias = (uintptr_t)bi.dli_fbase;
                    g_pow = (PowFunc)(g_loadBias + (uintptr_t)delta);
                }
            }
        }
    }
    env->ReleaseStringUTFChars(soPath, path);
    if (!g_pow) return -1;
    const char* c = env->GetStringUTFChars(challenge, nullptr);
    const char* b = env->GetStringUTFChars(base, nullptr);
    long long r = g_pow(c, (int)strlen(c), b, (int)strlen(b), (long long)difficulty);
    env->ReleaseStringUTFChars(challenge, c);
    env->ReleaseStringUTFChars(base, b);
    return (jlong)r;
}

extern "C" JNIEXPORT jboolean JNICALL
Java_com_powrouter_app_PowResolver_nativeSelfTest(JNIEnv* env, jclass, jstring soPath, jlong delta) {
    const char* path = env->GetStringUTFChars(soPath, nullptr);
    void* h = dlopen(path, RTLD_NOW | RTLD_LOCAL);
    env->ReleaseStringUTFChars(soPath, path);
    if (!h) return JNI_FALSE;
    void* ip = dlsym(h, ANCHOR_SYM_C);
    Dl_info bi;
    if (!ip || !dladdr(ip, &bi) || !bi.dli_fbase) { dlclose(h); return JNI_FALSE; }
    long long r = 0;
    bool ok = testCandidate((uintptr_t)bi.dli_fbase + (uintptr_t)delta, &r);
    dlclose(h);
    return ok ? JNI_TRUE : JNI_FALSE;
}
