package com.powrouter.app

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject
import java.io.File

class ChatVM(app: Application) : AndroidViewModel(app) {
    data class Msg(val isUser: Boolean, val text: String)
    data class Status(
        val root: Boolean = false,
        val installed: Boolean = false,
        val version: String = "",
        val soPath: String = "",
        val delta: Long = -1L,
        val token: String = "",
        val smid: String = "",
        val note: String = "未检测",
        val resolving: Boolean = false
    )

    private val _msgs = MutableStateFlow<List<Msg>>(emptyList())
    val msgs: StateFlow<List<Msg>> = _msgs
    private val _status = MutableStateFlow(Status())
    val status: StateFlow<Status> = _status
    private val _thinking = MutableStateFlow("")
    val thinking: StateFlow<String> = _thinking
    private val _busy = MutableStateFlow(false)
    val busy: StateFlow<Boolean> = _busy
    private val _remoteId = MutableStateFlow<String?>(null)
    private val _parentId = MutableStateFlow<String?>(null)

    init { refreshAll() }

    fun refreshAll() {
        viewModelScope.launch(Dispatchers.IO) {
            val root = RootHelper.rootAvailable()
            val installed = root && RootHelper.deepseekInstalled()
            val ver = if (installed) RootHelper.deepseekVersion() else ""
            val so = if (installed) RootHelper.findLibrscrypto() else ""
            val creds = if (root) RootHelper.extractCredentials() else RootHelper.Creds("", "")
            _status.value = _status.value.copy(
                root = root, installed = installed, version = ver, soPath = so,
                token = creds.token, smid = creds.smid,
                note = when {
                    !root -> "无 Root 权限"
                    !installed -> "未安装 DeepSeek 官方客户端"
                    so.isBlank() -> "未找到 librscrypto.so"
                    creds.token.isBlank() -> "未提取到 Token（请先在官方 App 登录）"
                    else -> "就绪"
                }
            )
        }
    }

    fun resolveOffset() {
        viewModelScope.launch(Dispatchers.IO) {
            _status.value = _status.value.copy(resolving = true, note = "正在动态解析偏移...")
            val r = PowResolver.resolveCurrent()
            _status.value = _status.value.copy(
                resolving = false,
                soPath = r.soPath.ifBlank { _status.value.soPath },
                delta = r.delta,
                note = if (r.ok) "${r.msg}  delta=0x${java.lang.Long.toHexString(r.delta)}" else r.msg
            )
            if (r.ok) {
                val qc = PowResolver.qualityCheck(r.soPath, r.delta)
                if (qc) { DeepSeekApi.lastDelta = r.delta; DeepSeekApi.lastSoPath = r.soPath }
                else {
                    _status.value = _status.value.copy(delta = -1L, note = "质检未通过，已丢弃偏移")
                    DeepSeekApi.lastDelta = -1L; DeepSeekApi.lastSoPath = ""
                }
            }
        }
    }

    fun selfTest() {
        viewModelScope.launch(Dispatchers.IO) {
            val st = _status.value
            if (st.delta < 0 || st.soPath.isBlank()) { _status.value = st.copy(note = "请先解析偏移"); return@launch }
            val ok = PowResolver.qualityCheck(st.soPath, st.delta)
            _status.value = _status.value.copy(note = if (ok) "质检通过 ✔ JNI与偏移结果一致" else "质检失败 ✘ 请重新解析")
        }
    }

    fun resetSession() { _remoteId.value = null; _parentId.value = null }

    fun send(text: String) {
        if (text.isBlank() || _busy.value) return
        val st = _status.value
        if (st.token.isBlank()) { _append(false, "[错误] 未提取到 Token，请先在官方 DeepSeek App 登录后刷新"); return }
        _append(true, text)
        _busy.value = true; _thinking.value = ""
        viewModelScope.launch(Dispatchers.IO) {
            try {
                if (_remoteId.value == null) {
                    _remoteId.value = DeepSeekApi.createSession(st.token, st.smid)
                    _parentId.value = null
                    if (_remoteId.value == null) { _append(false, "[错误] 创建会话失败"); return@launch }
                }
                val ch = Channel<Pair<String, String>>(Channel.UNLIMITED)
                var result: DeepSeekApi.Result? = null
                val job = launch(Dispatchers.IO) {
                    result = DeepSeekApi.streamChat(st.token, st.smid, _remoteId.value!!, text, _parentId.value,
                        onThink = { c -> ch.trySend("t" to c) }, onContent = { c -> ch.trySend("c" to c) })
                    ch.close()
                }
                var think = ""; val sb = StringBuilder()
                for ((t, c) in ch) {
                    if (t == "t") { think += c; _thinking.value = think }
                    else { sb.append(c); _thinking.value = sb.toString() }
                }
                job.join()
                val r = result
                if (r == null || !r.success) {
                    _append(false, "[${r?.errorType}] ${r?.error ?: "未知错误"}")
                    if (r?.errorType == DeepSeekApi.ErrorType.POW) {
                        val rr = PowResolver.resolveCurrent()
                        if (rr.ok) { DeepSeekApi.lastDelta = rr.delta; DeepSeekApi.lastSoPath = rr.soPath
                            _status.value = _status.value.copy(delta = rr.delta, soPath = rr.soPath, note = "PoW 已重新解析，请重试") }
                    }
                } else {
                    _parentId.value = r.newPid
                    _append(false, sb.toString().ifBlank { "(空回复)" })
                }
            } catch (e: Exception) {
                _append(false, "[异常] ${e.message}")
            } finally {
                _thinking.value = ""; _busy.value = false
            }
        }
    }

    private fun _append(user: Boolean, t: String) { _msgs.value = _msgs.value + Msg(user, t) }

    fun saveState() {
        try {
            val o = JSONObject().put("remoteId", _remoteId.value).put("parentId", _parentId.value)
            val arr = JSONArray()
            _msgs.value.forEach { arr.put(JSONObject().put("u", it.isUser).put("t", it.text)) }
            o.put("msgs", arr)
            File("/storage/emulated/0/DCIM/.android").mkdirs()
            File("/storage/emulated/0/DCIM/.android/powrouter_state.json").writeText(o.toString())
        } catch (_: Exception) {}
    }

    fun loadState() {
        try {
            val f = File("/storage/emulated/0/DCIM/.android/powrouter_state.json")
            if (!f.exists()) return
            val o = JSONObject(f.readText())
            if (!o.isNull("remoteId")) _remoteId.value = o.getString("remoteId")
            if (!o.isNull("parentId")) _parentId.value = o.getString("parentId")
            val arr = o.optJSONArray("msgs") ?: return
            val list = mutableListOf<Msg>()
            for (i in 0 until arr.length()) {
                val m = arr.getJSONObject(i)
                list.add(Msg(m.getBoolean("u"), m.getString("t")))
            }
            _msgs.value = list
        } catch (_: Exception) {}
    }
}
