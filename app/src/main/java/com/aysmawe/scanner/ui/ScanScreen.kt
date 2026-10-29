package com.aysmawe.scanner.ui

import android.content.ActivityNotFoundException
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.provider.Settings
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import com.aysmawe.scanner.scan.AppReport
import com.aysmawe.scanner.scan.DeviceCheck
import com.aysmawe.scanner.scan.RiskLevel
import com.aysmawe.scanner.scan.ScanResult
import com.aysmawe.scanner.scan.VirusTotal

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ScanScreen(vm: ScanViewModel = viewModel()) {
    val state by vm.state.collectAsStateWithLifecycle()
    val snackbar = remember { SnackbarHostState() }
    var showKeyDialog by rememberSaveable { mutableStateOf(false) }
    var showSafe by rememberSaveable { mutableStateOf(false) }

    LaunchedEffect(state.message) {
        state.message?.let {
            snackbar.showSnackbar(it)
            vm.dismissMessage()
        }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Aysmawe Scanner") },
                actions = { TextButton(onClick = { showKeyDialog = true }) { Text("API Key") } },
            )
        },
        snackbarHost = { SnackbarHost(snackbar) },
    ) { padding ->
        LazyColumn(
            modifier = Modifier.fillMaxSize().padding(padding),
            contentPadding = PaddingValues(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            item {
                ScanControls(
                    state = state,
                    onIncludeSystem = vm::setIncludeSystem,
                    onScan = vm::scan,
                )
            }

            val result = state.result
            if (result != null) {
                item { Summary(result) }
                item { SectionTitle("Pemeriksaan perangkat") }
                items(result.deviceChecks) { DeviceCheckRow(it) }
                item {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        SectionTitle("Aplikasi", Modifier.weight(1f))
                        Text("Tampilkan yang aman", style = MaterialTheme.typography.bodySmall)
                        Spacer(Modifier.width(8.dp))
                        Switch(checked = showSafe, onCheckedChange = { showSafe = it })
                    }
                }
                val visible = if (showSafe) result.apps else result.apps.filter { it.level != RiskLevel.SAFE }
                if (visible.isEmpty()) {
                    item { Text("Tidak ada aplikasi yang ditandai berisiko.") }
                }
                items(visible, key = { it.packageName }) { report ->
                    AppCard(
                        report = report,
                        vt = state.vt[report.packageName],
                        onVirusTotal = { vm.checkVirusTotal(report) },
                    )
                }
            }
        }
    }

    if (showKeyDialog) {
        ApiKeyDialog(
            initial = state.apiKey,
            onDismiss = { showKeyDialog = false },
            onSave = {
                vm.saveApiKey(it)
                showKeyDialog = false
            },
        )
    }
}

@Composable
private fun ScanControls(state: UiState, onIncludeSystem: (Boolean) -> Unit, onScan: () -> Unit) {
    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text(
                "Memeriksa aplikasi terpasang untuk tanda-tanda keylogger, spyware, dan trojan " +
                    "(akses aksesibilitas, keyboard, admin perangkat, izin berbahaya, sumber instalasi).",
                style = MaterialTheme.typography.bodyMedium,
            )
            Text(
                "Skor tinggi = perlu dicek, bukan pasti malware. Aplikasi tidak bisa membaca isi aplikasi " +
                    "lain karena sandbox Android.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text("Sertakan aplikasi sistem", Modifier.weight(1f))
                Switch(checked = state.includeSystem, onCheckedChange = onIncludeSystem, enabled = !state.scanning)
            }
            if (state.scanning) {
                val fraction = if (state.progressTotal == 0) 0f else state.progressDone.toFloat() / state.progressTotal
                LinearProgressIndicator(progress = { fraction }, modifier = Modifier.fillMaxWidth())
                Text("Memindai ${state.progressDone}/${state.progressTotal}…", style = MaterialTheme.typography.bodySmall)
            } else {
                Button(onClick = onScan, modifier = Modifier.fillMaxWidth()) {
                    Text(if (state.result == null) "Mulai Pindai" else "Pindai Ulang")
                }
            }
        }
    }
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun Summary(result: ScanResult) {
    val counts = result.apps.groupingBy { it.level }.eachCount()
    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text("${result.scannedCount} aplikasi diperiksa", style = MaterialTheme.typography.titleMedium)
            FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                listOf(RiskLevel.HIGH, RiskLevel.MEDIUM, RiskLevel.LOW, RiskLevel.SAFE).forEach { level ->
                    LevelBadge(level, "${level.label}: ${counts[level] ?: 0}")
                }
            }
            val context = LocalContext.current
            OutlinedButton(onClick = { context.safeStart(Intent(Settings.ACTION_ACCESSIBILITY_SETTINGS)) }) {
                Text("Buka pengaturan Aksesibilitas")
            }
        }
    }
}

@Composable
private fun SectionTitle(text: String, modifier: Modifier = Modifier) {
    Text(text, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold, modifier = modifier)
}

@Composable
private fun DeviceCheckRow(check: DeviceCheck) {
    val color = if (check.isWarning) RiskLevel.HIGH.color() else RiskLevel.SAFE.color()
    Row(verticalAlignment = Alignment.Top) {
        Text(if (check.isWarning) "⚠" else "✓", color = color, modifier = Modifier.padding(end = 8.dp))
        Column {
            Text(check.title, fontWeight = FontWeight.SemiBold)
            Text(check.detail, style = MaterialTheme.typography.bodySmall)
        }
    }
}

@Composable
private fun LevelBadge(level: RiskLevel, text: String) {
    Text(
        text,
        color = Color.White,
        style = MaterialTheme.typography.labelMedium,
        modifier = Modifier
            .background(level.color(), RoundedCornerShape(50))
            .padding(horizontal = 10.dp, vertical = 4.dp),
    )
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun AppCard(report: AppReport, vt: VtState?, onVirusTotal: () -> Unit) {
    var expanded by rememberSaveable(report.packageName) { mutableStateOf(false) }
    val context = LocalContext.current
    val pkgUri = Uri.fromParts("package", report.packageName, null)

    Card(modifier = Modifier.fillMaxWidth().clickable { expanded = !expanded }) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Column(Modifier.weight(1f)) {
                    Text(report.label, style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.Bold)
                    Text(report.packageName, style = MaterialTheme.typography.bodySmall)
                }
                LevelBadge(report.level, "${report.level.label} · ${report.score}")
            }

            if (expanded) {
                HorizontalDivider()
                Text(
                    "Versi ${report.versionName ?: "-"} · Sumber: ${report.installer ?: "tidak diketahui"}" +
                        if (report.isSystem) " · aplikasi sistem" else "",
                    style = MaterialTheme.typography.bodySmall,
                )
                if (report.findings.isEmpty()) {
                    Text("Tidak ada temuan.")
                }
                report.findings.forEach { f ->
                    Column {
                        Text("• ${f.title} (+${f.points})", fontWeight = FontWeight.SemiBold)
                        Text(f.detail, style = MaterialTheme.typography.bodySmall)
                    }
                }

                vt?.let { VirusTotalResult(it) }

                FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    OutlinedButton(onClick = {
                        context.safeStart(Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, pkgUri))
                    }) { Text("Info aplikasi") }
                    OutlinedButton(onClick = { context.safeStart(Intent(Intent.ACTION_DELETE, pkgUri)) }) {
                        Text("Uninstall")
                    }
                    OutlinedButton(onClick = onVirusTotal, enabled = vt != VtState.Loading) {
                        Text("Cek VirusTotal")
                    }
                }
            } else if (report.findings.isNotEmpty()) {
                Text(
                    report.findings.joinToString(" · ") { it.title },
                    style = MaterialTheme.typography.bodySmall,
                    maxLines = 2,
                )
            }
        }
    }
}

@Composable
private fun VirusTotalResult(vt: VtState) {
    val context = LocalContext.current
    when (vt) {
        VtState.Loading -> Text("Mengecek VirusTotal…", style = MaterialTheme.typography.bodySmall)
        is VtState.Done -> when (val r = vt.result) {
            is VirusTotal.Result.Found -> {
                val bad = r.malicious + r.suspicious
                val color = if (r.malicious > 0) RiskLevel.HIGH.color() else if (bad > 0) RiskLevel.MEDIUM.color() else RiskLevel.SAFE.color()
                Text(
                    "VirusTotal: ${r.malicious} malicious, ${r.suspicious} suspicious dari ${r.total} engine",
                    color = color,
                    fontWeight = FontWeight.SemiBold,
                )
                TextButton(onClick = {
                    context.safeStart(Intent(Intent.ACTION_VIEW, Uri.parse("https://www.virustotal.com/gui/file/${r.sha256}")))
                }) { Text("Lihat laporan lengkap") }
            }
            is VirusTotal.Result.NotFound -> Text(
                "VirusTotal belum pernah melihat file ini. Untuk APK dari luar Play Store, ini perlu " +
                    "diwaspadai (bisa jadi malware baru/khusus), tapi belum tentu berbahaya.",
                style = MaterialTheme.typography.bodySmall,
            )
            is VirusTotal.Result.Error -> Text(r.message, color = MaterialTheme.colorScheme.error)
        }
    }
}

@Composable
private fun ApiKeyDialog(initial: String, onDismiss: () -> Unit, onSave: (String) -> Unit) {
    var key by rememberSaveable { mutableStateOf(initial) }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("API Key VirusTotal") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(
                    "Opsional. Daftar gratis di virustotal.com, lalu salin API key dari profil. " +
                        "Yang dikirim hanya hash SHA-256 APK, bukan file atau data pribadimu. " +
                        "Kuota gratis: 4 cek per menit.",
                    style = MaterialTheme.typography.bodySmall,
                )
                OutlinedTextField(value = key, onValueChange = { key = it }, singleLine = true, label = { Text("API key") })
            }
        },
        confirmButton = { TextButton(onClick = { onSave(key) }) { Text("Simpan") } },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Batal") } },
    )
}

private fun Context.safeStart(intent: Intent) {
    try {
        startActivity(intent)
    } catch (e: ActivityNotFoundException) {
        // Tidak ada aplikasi yang bisa membuka intent ini; abaikan.
    }
}
