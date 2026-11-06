package com.powrouter.app

import java.util.UUID

object RootHelper {
    data class Creds(val token: String, val smid: String)

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
            val t2 = shell("find /data/data/com.deepseek.chat -name '*.default' -o -name '*prefs*' 2>/dev/null | head -5")
            if (t2.isNotBlank()) {
                Regex("\\b[a-zA-Z0-9+/=]{64}\\b").find(t2)?.let { token = it.value }
            }
        }
        if (smid.isBlank()) smid = UUID.randomUUID().toString().replace("-", "")
        return Creds(token, smid)
    }

    fun findLibrscrypto(): String {
        val pmOut = shell("pm path com.deepseek.chat 2>/dev/null")
        val apk = pmOut.lines().firstOrNull { it.startsWith("package:") }?.removePrefix("package:")?.trim()
        if (!apk.isNullOrBlank()) {
            val cand = apk.substringBeforeLast('/') + "/lib/arm64/librscrypto.so"
            val chk = shell("ls '$cand' 2>/dev/null")
            if (chk.isNotBlank()) return cand
        }
        val f = shell("find /data/app -name librscrypto.so 2>/dev/null | head -n 1").trim()
        if (f.isNotEmpty()) return f
        return ""
    }

    fun deepseekInstalled(): Boolean = shell("pm path com.deepseek.chat 2>/dev/null").contains("package:")
    fun deepseekVersion(): String {
        val o = shell("dumpsys package com.deepseek.chat 2>/dev/null | grep versionName | head -1")
        return o.substringAfter("versionName=", "").trim()
    }
    fun rootAvailable(): Boolean = shell("id").contains("uid=0")
}
