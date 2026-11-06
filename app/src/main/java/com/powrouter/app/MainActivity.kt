package com.powrouter.app

import android.Manifest
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.Environment
import android.provider.Settings
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.ContextCompat
import androidx.lifecycle.viewmodel.compose.viewModel
import kotlinx.coroutines.launch

val Bg = Color(0xFF0A0D14)
val Surface0 = Color(0xFF141926)
val Surface1 = Color(0xFF1C2233)
val UserBubble = Color(0xFF243050)
val Txt = Color(0xFFE6E8EE)
val Muted = Color(0xFF8B93A7)
val Accent = Color(0xFF5B8DEF)
val Ok = Color(0xFF10B981)
val Err = Color(0xFFEF4444)

class MainActivity : ComponentActivity() {
    private val perm = registerForActivityResult(ActivityResultContracts.RequestMultiplePermissions()) {}

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.R) {
            perm.launch(arrayOf(Manifest.permission.READ_EXTERNAL_STORAGE, Manifest.permission.WRITE_EXTERNAL_STORAGE))
        } else if (!Environment.isExternalStorageManager()) {
            try { startActivity(android.content.Intent(Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION, Uri.parse("package:$packageName"))) }
            catch (_: Exception) { try { startActivity(android.content.Intent(Settings.ACTION_MANAGE_ALL_FILES_ACCESS_PERMISSION)) } catch (_: Exception) {} }
        }
        setContent { MaterialTheme(colorScheme = darkColorScheme(primary = Accent, background = Bg, surface = Surface0), typography = Typography()) { Root() } }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun Root(vm: ChatVM = viewModel()) {
    val status by vm.status.collectAsState()
    val msgs by vm.msgs.collectAsState()
    val thinking by vm.thinking.collectAsState()
    val busy by vm.busy.collectAsState()
    var input by remember { mutableStateOf("") }
    val listState = rememberLazyListState()
    val scope = rememberCoroutineScope()

    LaunchedEffect(msgs.size) {
        if (msgs.isNotEmpty()) listState.animateScrollToItem(msgs.size - 1)
    }

    Column(Modifier.fillMaxSize().background(Bg)) {
        Column(Modifier.fillMaxWidth().background(Surface0).padding(12.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(Icons.Default.Security, null, tint = Accent)
                Spacer(Modifier.width(8.dp))
                Text("PowRouter", color = Txt, fontSize = 18.sp, fontWeight = FontWeight.Bold)
                Spacer(Modifier.weight(1f))
                IconButton(onClick = { vm.refreshAll() }) { Icon(Icons.Default.Refresh, null, tint = Accent) }
            }
            Row(Modifier.fillMaxWidth().padding(top = 4.dp), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                StatChip("Root", status.root)
                StatChip("DS", status.installed)
                Text("v${status.version}", color = Muted, fontSize = 11.sp, modifier = Modifier.align(Alignment.CenterVertically))
            }
            Spacer(Modifier.height(6.dp))
            Text("SO: ${status.soPath.ifBlank { "--" }}", color = Muted, fontSize = 10.sp, maxLines = 1)
            Text(
                "DELTA: " + (if (status.delta < 0) "--" else "0x" + java.lang.Long.toHexString(status.delta)),
                color = if (status.delta >= 0) Ok else Muted, fontSize = 11.sp, fontFamily = FontFamily.Monospace
            )
            Text("STATUS: ${status.note}", color = if (status.note.contains("成功") || status.note.contains("就绪") || status.note.contains("通过")) Ok else Muted, fontSize = 11.sp)
            Spacer(Modifier.height(6.dp))
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Button(onClick = { vm.resolveOffset() }, enabled = !status.resolving,
                    colors = ButtonDefaults.buttonColors(containerColor = Accent),
                    shape = RoundedCornerShape(10.dp), modifier = Modifier.weight(1f).height(38.dp)) {
                    Text(if (status.resolving) "解析中..." else "动态解析偏移", fontSize = 13.sp, color = Color.White)
                }
                Button(onClick = { vm.selfTest() }, enabled = status.delta >= 0,
                    colors = ButtonDefaults.buttonColors(containerColor = Surface1),
                    shape = RoundedCornerShape(10.dp), modifier = Modifier.weight(1f).height(38.dp)) {
                    Text("自检 PoW", fontSize = 13.sp, color = Txt)
                }
            }
            if (!status.root || !status.installed || status.token.isBlank()) {
                Spacer(Modifier.height(6.dp))
                Text(
                    when {
                        !status.root -> "⚠ 需要 Root 权限（su）"
                        !status.installed -> "⚠ 未安装 DeepSeek 官方客户端"
                        else -> "⚠ 未提取到 Token，请在官方 App 登录后点刷新"
                    }, color = Err, fontSize = 11.sp
                )
            }
        }

        Divider(color = Surface1)

        LazyColumn(state = listState, modifier = Modifier.weight(1f), contentPadding = PaddingValues(12.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp)) {
            items(msgs) { m -> MsgBubble(m) }
            if (busy) item {
                Row(Modifier.fillMaxWidth()) {
                    Box(Modifier.size(6.dp).clip(RoundedCornerShape(3.dp)).background(Accent).align(Alignment.Top))
                    Spacer(Modifier.width(8.dp))
                    Text(thinking.ifBlank { "思考中..." }, color = Muted, fontSize = 13.sp)
                }
            }
        }

        Row(Modifier.fillMaxWidth().background(Surface0).padding(10.dp), verticalAlignment = Alignment.CenterVertically) {
            BasicTextField(
                value = input, onValueChange = { input = it },
                textStyle = TextStyle(color = Txt, fontSize = 15.sp),
                modifier = Modifier.weight(1f).background(Surface1, RoundedCornerShape(12.dp)).padding(12.dp),
                maxLines = 5,
                decorationBox = { inner ->
                    if (input.isBlank()) Text("和 DeepSeek 聊天...", color = Muted, fontSize = 15.sp)
                    inner()
                }
            )
            Spacer(Modifier.width(8.dp))
            IconButton(onClick = {
                val t = input.trim(); if (t.isNotEmpty() && !busy) { vm.send(t); input = "" }
            }, enabled = !busy, modifier = Modifier.size(46.dp).clip(RoundedCornerShape(12.dp)).background(if (busy) Surface1 else Accent)) {
                Icon(Icons.Default.Send, null, tint = Color.White)
            }
        }
    }
}

@Composable
fun StatChip(label: String, ok: Boolean) {
    Row(Modifier.clip(RoundedCornerShape(8.dp)).background(if (ok) Ok.copy(alpha = 0.18f) else Err.copy(alpha = 0.18f)).padding(horizontal = 8.dp, vertical = 3.dp), verticalAlignment = Alignment.CenterVertically) {
        Box(Modifier.size(7.dp).clip(RoundedCornerShape(4.dp)).background(if (ok) Ok else Err))
        Spacer(Modifier.width(5.dp))
        Text(label, color = if (ok) Ok else Err, fontSize = 11.sp)
    }
}

@Composable
fun MsgBubble(m: ChatVM.Msg) {
    Row(Modifier.fillMaxWidth(), horizontalArrangement = if (m.isUser) Arrangement.End else Arrangement.Start) {
        Box(Modifier.widthIn(max = 320.dp).clip(RoundedCornerShape(if (m.isUser) 16.dp else 16.dp)).background(if (m.isUser) UserBubble else Surface1).padding(12.dp)) {
            Text(m.text, color = Txt, fontSize = 15.sp)
        }
    }
}
