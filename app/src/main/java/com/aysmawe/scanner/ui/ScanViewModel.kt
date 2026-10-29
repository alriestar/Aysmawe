package com.aysmawe.scanner.ui

import android.app.Application
import android.content.Context
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.aysmawe.scanner.scan.AppReport
import com.aysmawe.scanner.scan.ScanResult
import com.aysmawe.scanner.scan.Scanner
import com.aysmawe.scanner.scan.VirusTotal
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

sealed interface VtState {
    data object Loading : VtState
    data class Done(val result: VirusTotal.Result) : VtState
}

data class UiState(
    val scanning: Boolean = false,
    val progressDone: Int = 0,
    val progressTotal: Int = 0,
    val includeSystem: Boolean = false,
    val result: ScanResult? = null,
    val apiKey: String = "",
    val vt: Map<String, VtState> = emptyMap(),
    val message: String? = null,
)

class ScanViewModel(app: Application) : AndroidViewModel(app) {

    private val prefs = app.getSharedPreferences("settings", Context.MODE_PRIVATE)

    private val _state = MutableStateFlow(UiState(apiKey = prefs.getString(KEY_API, "").orEmpty()))
    val state: StateFlow<UiState> = _state.asStateFlow()

    fun setIncludeSystem(value: Boolean) = _state.update { it.copy(includeSystem = value) }

    fun saveApiKey(key: String) {
        prefs.edit().putString(KEY_API, key.trim()).apply()
        _state.update { it.copy(apiKey = key.trim()) }
    }

    fun dismissMessage() = _state.update { it.copy(message = null) }

    fun scan() {
        if (_state.value.scanning) return
        val includeSystem = _state.value.includeSystem
        _state.update { it.copy(scanning = true, progressDone = 0, progressTotal = 0, vt = emptyMap()) }
        viewModelScope.launch {
            val result = runCatching {
                withContext(Dispatchers.Default) {
                    Scanner(getApplication()).scan(includeSystem) { done, total ->
                        _state.update { it.copy(progressDone = done, progressTotal = total) }
                    }
                }
            }
            _state.update {
                it.copy(
                    scanning = false,
                    result = result.getOrNull() ?: it.result,
                    message = result.exceptionOrNull()?.let { e -> "Scan gagal: ${e.message}" },
                )
            }
        }
    }

    fun checkVirusTotal(report: AppReport) {
        val key = _state.value.apiKey
        if (key.isBlank()) {
            _state.update { it.copy(message = "Isi API key VirusTotal dulu (tombol \"API Key\" di atas).") }
            return
        }
        _state.update { it.copy(vt = it.vt + (report.packageName to VtState.Loading)) }
        viewModelScope.launch {
            val result = withContext(Dispatchers.IO) { VirusTotal.check(report.apkPath, key) }
            _state.update { it.copy(vt = it.vt + (report.packageName to VtState.Done(result))) }
        }
    }

    private companion object {
        const val KEY_API = "vt_api_key"
    }
}
