package com.aysmawe.scanner.scan

/**
 * Status "siapa memegang akses sensitif" di HP saat ini. Dikumpulkan sekali per scan,
 * lalu dicocokkan ke tiap aplikasi.
 */
data class SystemState(
    val enabledAccessibility: Set<String>,
    val enabledImes: Set<String>,
    val defaultIme: String?,
    val activeAdmins: Set<String>,
    val notificationListeners: Set<String>,
    val launcherPackages: Set<String>,
    val defaultSms: String?,
)
