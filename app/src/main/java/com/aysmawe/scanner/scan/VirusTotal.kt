package com.aysmawe.scanner.scan

import org.json.JSONObject
import java.io.File
import java.net.HttpURLConnection
import java.net.URL
import java.security.MessageDigest

/**
 * Cek hash SHA-256 APK ke VirusTotal (API v3). Yang dikirim hanya hash, bukan file APK-nya.
 * Kuota API gratis: 4 permintaan/menit, 500/hari.
 */
object VirusTotal {

    sealed interface Result {
        data class Found(val sha256: String, val malicious: Int, val suspicious: Int, val total: Int) : Result
        data class NotFound(val sha256: String) : Result
        data class Error(val message: String) : Result
    }

    fun sha256(file: File): String {
        val digest = MessageDigest.getInstance("SHA-256")
        file.inputStream().use { input ->
            val buffer = ByteArray(64 * 1024)
            while (true) {
                val read = input.read(buffer)
                if (read < 0) break
                digest.update(buffer, 0, read)
            }
        }
        return digest.digest().joinToString("") { "%02x".format(it) }
    }

    /** Blocking; panggil dari background thread. */
    fun check(apkPath: String, apiKey: String): Result {
        val hash = runCatching { sha256(File(apkPath)) }
            .getOrElse { return Result.Error("Gagal membaca APK: ${it.message}") }

        val conn = (URL("https://www.virustotal.com/api/v3/files/$hash").openConnection() as HttpURLConnection)
        return try {
            conn.connectTimeout = 15_000
            conn.readTimeout = 15_000
            conn.setRequestProperty("x-apikey", apiKey)
            when (val code = conn.responseCode) {
                200 -> {
                    val body = conn.inputStream.bufferedReader().use { it.readText() }
                    val stats = JSONObject(body).getJSONObject("data").getJSONObject("attributes")
                        .getJSONObject("last_analysis_stats")
                    val total = stats.keys().asSequence().sumOf { stats.optInt(it) }
                    Result.Found(hash, stats.optInt("malicious"), stats.optInt("suspicious"), total)
                }
                404 -> Result.NotFound(hash)
                401 -> Result.Error("API key tidak valid.")
                429 -> Result.Error("Kuota VirusTotal habis (maks 4/menit). Coba lagi sebentar.")
                else -> Result.Error("VirusTotal membalas HTTP $code.")
            }
        } catch (e: Exception) {
            Result.Error("Gagal terhubung: ${e.message}")
        } finally {
            conn.disconnect()
        }
    }
}
