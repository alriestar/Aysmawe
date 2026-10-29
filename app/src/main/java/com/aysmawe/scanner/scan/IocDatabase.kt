package com.aysmawe.scanner.scan

import android.content.Context
import org.json.JSONObject

/**
 * Indikator stalkerware/watchware yang dikenal (nama paket + SHA-1 sertifikat penandatangan).
 * Sumber: https://github.com/AssoEchap/stalkerware-indicators (CC-BY 4.0, Echap).
 * Daftar ini tidak lengkap: tidak cocok bukan berarti pasti bersih.
 */
class IocDatabase private constructor(
    val updated: String,
    val familyCount: Int,
    private val byPackage: Map<String, Entry>,
    private val byCert: Map<String, Entry>,
) {
    data class Entry(val name: String, val type: String) {
        val isStalkerware: Boolean get() = type == "stalkerware"
    }

    data class Match(val entry: Entry, val byCertificate: Boolean, val byPackage: Boolean)

    fun match(packageName: String, certSha1s: List<String>): Match? {
        val certEntry = certSha1s.firstNotNullOfOrNull { byCert[it] }
        val pkgEntry = byPackage[packageName]
        val entry = certEntry ?: pkgEntry ?: return null
        return Match(entry, byCertificate = certEntry != null, byPackage = pkgEntry != null)
    }

    fun findings(match: Match): List<Finding> {
        val e = match.entry
        val how = when {
            match.byCertificate && match.byPackage -> "nama paket dan sertifikat"
            match.byCertificate -> "sertifikat penandatangan"
            else -> "nama paket"
        }
        return if (e.isStalkerware) {
            listOf(
                Finding(
                    100, "STALKERWARE DIKENAL: ${e.name}",
                    "Cocok dengan database stalkerware publik (berdasarkan $how). Aplikasi jenis ini " +
                        "dipakai untuk memata-matai lokasi, chat, SMS, panggilan, dan foto secara diam-diam."
                )
            )
        } else {
            listOf(
                Finding(
                    20, "Aplikasi pemantau: ${e.name}",
                    "Cocok dengan daftar \"watchware\" (berdasarkan $how): aplikasi pemantau yang tidak " +
                        "bersembunyi, mis. parental control atau remote access. Wajar jika kamu sendiri yang memasang."
                )
            )
        }
    }

    companion object {
        private const val ASSET = "stalkerware_ioc.json"

        fun load(context: Context): IocDatabase {
            val json = context.assets.open(ASSET).bufferedReader().use { JSONObject(it.readText()) }
            val apps = json.getJSONArray("apps")
            val byPackage = HashMap<String, Entry>()
            val byCert = HashMap<String, Entry>()
            for (i in 0 until apps.length()) {
                val app = apps.getJSONObject(i)
                val entry = Entry(app.getString("name"), app.optString("type", "stalkerware"))
                val packages = app.getJSONArray("packages")
                for (j in 0 until packages.length()) byPackage[packages.getString(j)] = entry
                val certs = app.getJSONArray("certificates")
                for (j in 0 until certs.length()) byCert[certs.getString(j).uppercase()] = entry
            }
            return IocDatabase(json.optString("updated"), apps.length(), byPackage, byCert)
        }
    }
}
