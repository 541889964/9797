package com.powrouter.app

object PowResolver {
    init {
        System.loadLibrary("powresolver")
    }

    @JvmStatic
    external fun nativeResolve(soPath: String, anchorSym: String, challenge: String, base: String, difficulty: Long): Long

    @JvmStatic
    external fun nativeCalculate(soPath: String, challenge: String, base: String, difficulty: Long, delta: Long): Long

    @JvmStatic
    external fun nativeCalculateViaJni(soPath: String, challenge: String, base: String, difficulty: Long): Long

    @JvmStatic
    external fun nativeSelfTest(soPath: String, delta: Long, challenge: String, base: String, difficulty: Long): Boolean

    const val ANCHOR = "Java_com_deepseek_crypto_PowCalculator_nativeCalculateDeepSeekHashV1Pow"

    data class ResolveResult(val ok: Boolean, val delta: Long, val soPath: String, val msg: String)

    fun resolveCurrent(challenge: String = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", base: String = "1700000000_1800000000_", difficulty: Long = 1L): ResolveResult {
        val so = RootHelper.findLibrscrypto()
        if (so.isBlank()) return ResolveResult(false, -1, "", "未找到 librscrypto.so")
        val delta = nativeResolve(so, ANCHOR, challenge, base, difficulty)
        if (delta < 0) return ResolveResult(false, delta, so, "动态偏移解析失败（JNI 真值异常或候选未命中）")
        val pass = nativeSelfTest(so, delta, challenge, base, difficulty)
        return ResolveResult(true, delta, so, if (pass) "解析成功并通过自检" else "解析成功但自检未通过")
    }

    fun calculateViaJni(so: String, challenge: String, base: String, difficulty: Long): Long =
        nativeCalculateViaJni(so, challenge, base, difficulty)

    fun calculate(so: String, challenge: String, base: String, difficulty: Long, delta: Long): Long =
        nativeCalculate(so, challenge, base, difficulty, delta)
}
