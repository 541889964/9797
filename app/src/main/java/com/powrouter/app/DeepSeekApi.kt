package com.powrouter.app

import okhttp3.*
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.RequestBody.Companion.asRequestBody
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.util.concurrent.TimeUnit

object DeepSeekApi {
    private const val BASE = "https://chat.deepseek.com"
    private val client = OkHttpClient.Builder()
        .connectTimeout(15, TimeUnit.SECONDS).readTimeout(90, TimeUnit.SECONDS).build()
    private val jsonMedia = "application/json".toMediaType()

    enum class ErrorType { NONE, NETWORK, POW, SESSION_INVALID, AUTH, OTHER }

    @Volatile var lastDelta: Long = -1L
    @Volatile var lastSoPath: String = ""

    private fun headers(token: String, smid: String) = mutableMapOf(
        "Authorization" to "Bearer $token",
        "x-client-platform" to "android",
        "x-client-version" to "2.7.1",
        "x-client-bundle-id" to "com.deepseek.chat",
        "User-Agent" to "DeepSeek/2.7.1 Android/33",
        "x-device-id" to smid, "x-rangers-id" to smid,
        "Accept" to "text/event-stream", "Content-Type" to "application/json"
    )

    fun createSession(token: String, smid: String): String? = try {
        val h = headers(token, smid)
        val req = Request.Builder().url("$BASE/api/v0/chat_session/create")
            .apply { h.forEach { (k, v) -> header(k, v) } }
            .post("{}".toRequestBody(jsonMedia)).build()
        client.newCall(req).execute().use {
            JSONObject(it.body?.string() ?: "{}").getJSONObject("data")
                .getJSONObject("biz_data").getJSONObject("chat_session").getString("id")
        }
    } catch (e: Exception) { null }

    fun deleteSession(token: String, smid: String, sid: String) {
        try {
            val h = headers(token, smid)
            val req = Request.Builder().url("$BASE/api/v0/chat_session/delete")
                .apply { h.forEach { (k, v) -> header(k, v) } }
                .post(JSONObject().put("chat_session_id", sid).toString().toRequestBody(jsonMedia)).build()
            client.newCall(req).execute().close()
        } catch (_: Exception) {}
    }

    fun solvePow(token: String, smid: String): String? {
        return try {
        val h = headers(token, smid)
        val req = Request.Builder().url("$BASE/api/v0/chat/create_pow_challenge")
            .apply { h.forEach { (k, v) -> header(k, v) } }
            .post("{\"target_path\":\"/api/v0/chat/completion\"}".toRequestBody(jsonMedia)).build()
        val ch = client.newCall(req).execute().use {
            JSONObject(it.body?.string() ?: "{}").getJSONObject("data")
                .getJSONObject("biz_data").getJSONObject("challenge")
        }
        val base = "${ch.getString("salt")}_${ch.getLong("expire_at")}_"
        var delta = lastDelta
        var so = lastSoPath
        if (delta < 0 || so.isBlank()) {
            val r = PowResolver.resolveCurrent()
            if (!r.ok) return null
            delta = r.delta; so = r.soPath; lastDelta = delta; lastSoPath = so
        }
        var answer = PowResolver.calculate(so, ch.getString("challenge"), base, ch.getLong("difficulty"), delta)
        if (answer < 0) {
            val r = PowResolver.resolveCurrent()
            if (r.ok) {
                delta = r.delta; so = r.soPath; lastDelta = delta; lastSoPath = so
                answer = PowResolver.calculate(so, ch.getString("challenge"), base, ch.getLong("difficulty"), delta)
            }
        }
        if (answer < 0) return null
        val payload = JSONObject().apply {
            put("algorithm", "DeepSeekHashV1")
            put("challenge", ch.getString("challenge"))
            put("salt", ch.getString("salt"))
            put("answer", answer)
            put("signature", ch.getString("signature"))
            put("target_path", "/api/v0/chat/completion")
        }.toString()
        java.util.Base64.getEncoder().encodeToString(payload.toByteArray())
    } catch (e: Exception) { null }
    }

    fun uploadImage(token: String, smid: String, filePath: String): String? {
        return try {
        val f = File(filePath); if (!f.exists()) return null
        val h = headers(token, smid).filterKeys { it != "Content-Type" }
        val body = MultipartBody.Builder().setType(MultipartBody.FORM)
            .addFormDataPart("file", f.name, f.asRequestBody("image/png".toMediaType())).build()
        val req = Request.Builder().url("$BASE/api/v0/file/upload_file")
            .apply { h.forEach { (k, v) -> header(k, v) } }.post(body).build()
        client.newCall(req).execute().use {
            val o = JSONObject(it.body?.string() ?: "{}")
            if (o.has("data")) o.getJSONObject("data").getString("file_id") else null
        }
    } catch (e: Exception) { null }
    }

    data class Result(val success: Boolean, val newPid: String?, val error: String, val usage: Long = 0L, val errorType: ErrorType = ErrorType.NONE)

    fun streamChat(token: String, smid: String, sid: String, prompt: String, parentId: String?,
                   refFileIds: List<String> = emptyList(),
                   onThink: (String) -> Unit, onContent: (String) -> Unit): Result {
        val pow = solvePow(token, smid) ?: return Result(false, parentId, "PoW失败", 0L, ErrorType.POW)
        val h = headers(token, smid)
        h["X-DS-PoW-Response"] = pow
        val files = JSONArray(); refFileIds.forEach { files.put(it) }
        val body = JSONObject().apply {
            put("chat_session_id", sid); put("prompt", prompt); put("ref_file_ids", files)
            if (parentId != null) parentId.toLongOrNull()?.let { put("parent_message_id", it) } ?: put("parent_message_id", parentId)
        }.toString().toRequestBody(jsonMedia)
        val req = Request.Builder().url("$BASE/api/v0/chat/completion")
            .apply { h.forEach { (k, v) -> header(k, v) } }.post(body).build()

        var newPid = parentId; var fragIdx = 0; var phase = "content"
        var usage = 0L; var hasData = false
        try {
            client.newCall(req).execute().use { resp ->
                if (resp.code == 401) return Result(false, parentId, "Token失效", 0L, ErrorType.AUTH)
                if (!resp.isSuccessful) { android.util.Log.w("DS", "HTTP ${resp.code}: " + (resp.body?.string()?.take(300) ?: "")); return Result(false, parentId, "HTTP ${resp.code}", 0L, ErrorType.NETWORK) }
                val src = resp.body?.source() ?: return Result(false, parentId, "流为空", 0L, ErrorType.NETWORK)
                // Peek at raw body: if it looks like JSON error, parse it
                val firstLine = try { src.peek().readUtf8Line() ?: "" } catch (e: Exception) { "" }
                if (firstLine.startsWith("{") && firstLine.contains(""code"") && !firstLine.contains("data:")) {
                    val errMsg = try { JSONObject(firstLine).optString("msg", firstLine) } catch (e: Exception) { firstLine }
                    android.util.Log.w("DS", "API error: $errMsg")
                    return Result(false, parentId, "API错误: $errMsg", 0L, ErrorType.OTHER)
                }
                while (true) {
                    val line = src.readUtf8Line() ?: break
                    if (!line.startsWith("data:")) continue
                    val raw = line.removePrefix("data:").trim()
                    if (raw == "[DONE]") break
                    if (!line.startsWith("data:")) { android.util.Log.w("DS", "RAW: " + line.take(300)); continue }
                    try {
                        val o = JSONObject(raw)
                        if (o.has("response_message_id")) { newPid = o.getString("response_message_id"); hasData = true }
                        val p = o.optString("p", ""); val v = o.optString("v", "")
                        if (p == "accumulated_token_usage") { usage = v.toLongOrNull() ?: usage; continue }
                        if (p == "quasi_status" || p == "status" || p == "finish") continue
                        if (p.startsWith("response/fragments/") && p.endsWith("/content")) {
                            fragIdx++; phase = if (fragIdx == 1) "thinking" else "content"
                            if (v.isNotEmpty()) { hasData = true; if (phase == "thinking") onThink(v) else onContent(v) }
                            continue
                        }
                        if (v.isNotEmpty() && v != "FINISHED" && v != "WIP" && v != "DONE") {
                            hasData = true
                            if (phase == "thinking") onThink(v) else onContent(v)
                        }
                    } catch (_: Exception) {}
                }
            }
        } catch (e: Exception) {
            return Result(false, parentId, e.message ?: "网络异常", usage, ErrorType.NETWORK)
        }
        if (!hasData) return Result(false, parentId, "空响应", usage, ErrorType.SESSION_INVALID)
        return Result(true, newPid, "", usage, ErrorType.NONE)
    }
}
