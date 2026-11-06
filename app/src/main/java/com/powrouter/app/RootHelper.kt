package com.powrouter.app

import java.util.UUID

object RootHelper {
    data class Creds(val token: String, val smid: String)

    private const val APP_FILES = "/data/data/com.powrouter.app/files"
    private const val LOCAL_SO = "$APP_FILES/librscrypto.so"

    fun shell(cmd: String): String = try {
        val p = ProcessBuilder("su", "-c", cmd).redirectErrorStream(true).start()
        val out = p.inputStream.bufferedReader().readText()
        p.waitFor()
        out
    } catch (e: Exception) { "" }

    fun extractCredentials(): Creds {
        var token = ""
        var smid = ""
        val text = shell("cat /data/data/com.deepseek.chat/files/mmkv/mmkv.default 2>/dev/null")
        if (text.isNotBlank()) {
            val iso = String(text.toByteArray(Charsets.ISO_8859_1), Charsets.ISO_8859_1)
            Regex("\\b[a-zA-Z0-9+/=]{64}\\b").find(iso)?.let { token = it.value }
            Regex("\\b[a-zA-Z0-9_\\-+/=]{70,120}\\b").find(iso)?.let { smid = it.value }
        }
        if (token.isBlank()) {
            val t2 = shell("find /data/data/com.deepseek.chat -name '*.default' 2>/dev/null | head -5")
            if (t2.isNotBlank()) Regex("\\b[a-zA-Z0-9+/=]{64}\\b").find(t2)?.let { token = it.value }
        }
        if (smid.isBlank()) smid = UUID.randomUUID().toString().replace("-", "")
        return Creds(token, smid)
    }

    fun findLibrscrypto(): String {
        val pmOut = shell("pm path com.deepseek.chat 2>/dev/null")
        val apk = pmOut.lines().firstOrNull { it.startsWith("package:") }?.removePrefix("package:")?.trim()
        if (!apk.isNullOrBlank()) {
            val cand = apk.substringBeforeLast('/') + "/lib/arm64/librscrypto.so"
            if (shell("ls '$cand' 2>/dev/null").isNotBlank()) return cand
        }
        val f = shell("find /data/app -name librscrypto.so 2>/dev/null | head -n 1").trim()
        return f
    }

    // 关键：把 so 复制到本应用私有目录，解决 dlopen "Permission denied"
    fun ensureAccessible(srcSo: String): String {
        if (srcSo.isBlank()) return ""
        val cmd = "mkdir -p '$APP_FILES' && " +
                "cp -f '$srcSo' '$LOCAL_SO' && " +
                "chmod 755 '$LOCAL_SO' && " +
                "(chcon u:object_r:app_data_file:s0 '$LOCAL_SO' 2>/dev/null || true) && " +
                "ls -la '$LOCAL_SO'"
        val out = shell(cmd)
        return if (out.contains(LOCAL_SO)) LOCAL_SO else ""
    }

    fun deepseekInstalled(): Boolean = shell("pm path com.deepseek.chat 2>/dev/null").contains("package:")
    fun deepseekVersion(): String =
        shell("dumpsys package com.deepseek.chat 2>/dev/null | grep versionName | head -1")
            .substringAfter("versionName=", "").trim()
    fun rootAvailable(): Boolean = shell("id").contains("uid=0")
}
