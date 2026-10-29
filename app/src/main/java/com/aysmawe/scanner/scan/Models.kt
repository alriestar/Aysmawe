package com.aysmawe.scanner.scan

enum class RiskLevel(val label: String) {
    SAFE("Aman"),
    LOW("Rendah"),
    MEDIUM("Sedang"),
    HIGH("Tinggi");

    companion object {
        fun fromScore(score: Int): RiskLevel = when {
            score >= 60 -> HIGH
            score >= 30 -> MEDIUM
            score >= 10 -> LOW
            else -> SAFE
        }
    }
}

/** Satu alasan kenapa sebuah aplikasi dianggap berisiko, beserta bobot skornya. */
data class Finding(val points: Int, val title: String, val detail: String)

data class AppReport(
    val packageName: String,
    val label: String,
    val versionName: String?,
    val isSystem: Boolean,
    val installer: String?,
    val apkPath: String,
    val findings: List<Finding>,
) {
    val score: Int = findings.sumOf { it.points }
    val level: RiskLevel = RiskLevel.fromScore(score)
}

data class DeviceCheck(val title: String, val detail: String, val isWarning: Boolean)

data class ScanResult(
    val apps: List<AppReport>,
    val deviceChecks: List<DeviceCheck>,
    val scannedCount: Int,
)
