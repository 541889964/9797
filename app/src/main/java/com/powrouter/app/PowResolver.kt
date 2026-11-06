package com.powrouter.app

object PowResolver {
    init { System.loadLibrary("powresolver") }

    @JvmStatic external fun nativeResolve(soPath: String, challenge: String, base: String, difficulty: Long): Long
    @JvmStatic external fun nativeCalculate(soPath: String, challenge: String, base: String, difficulty: Long, delta: Long): Long
    @JvmStatic external fun nativeCalculateViaJni(soPath: String, challenge: String, base: String, difficulty: Long): Long
    @JvmStatic external fun nativeSelfTest(soPath: String, delta: Long, challenge: String, base: String, difficulty: Long): Boolean
    @JvmStatic external fun nativeQualityCheck(soPath: String, challenge: String, base: String, difficulty: Long, delta: Long): Boolean

    data class ResolveResult(val ok: Boolean, val delta: Long, val soPath: String, val msg: String)

    const val PROBE_CHALLENGE = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    const val PROBE_BASE = "1700000000_1800000000_"
    const val PROBE_DIFFICULTY = 1L

    fun resolveCurrent(): ResolveResult {
        val so = RootHelper.findLibrscrypto()
        if (so.isBlank()) return ResolveResult(false, -1, "", "未找到 librscrypto.so")
        val delta = nativeResolve(so, PROBE_CHALLENGE, PROBE_BASE, PROBE_DIFFICULTY)
        if (delta < 0) return ResolveResult(false, delta, so, "动态偏移解析失败（JNI 真值异常或候选未命中）")
        val pass = nativeQualityCheck(so, PROBE_CHALLENGE, PROBE_BASE, PROBE_DIFFICULTY, delta)
        return ResolveResult(true, delta, so, if (pass) "解析成功并通过质检" else "解析成功但质检未通过")
    }

    fun qualityCheck(so: String, delta: Long): Boolean =
        nativeQualityCheck(so, PROBE_CHALLENGE, PROBE_BASE, PROBE_DIFFICULTY, delta)

    fun calculate(so: String, challenge: String, base: String, difficulty: Long, delta: Long): Long =
        nativeCalculate(so, challenge, base, difficulty, delta)
}
