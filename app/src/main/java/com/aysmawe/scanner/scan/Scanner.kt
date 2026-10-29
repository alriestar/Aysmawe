package com.aysmawe.scanner.scan

import android.accessibilityservice.AccessibilityServiceInfo
import android.app.admin.DevicePolicyManager
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.os.Build
import android.provider.Settings
import android.provider.Telephony
import android.view.accessibility.AccessibilityManager
import android.view.inputmethod.InputMethodManager
import java.io.File
import java.time.LocalDate
import java.time.temporal.ChronoUnit

class Scanner(private val context: Context) {

    private val pm: PackageManager = context.packageManager

    /** Jalankan di background thread; bisa memakan waktu beberapa detik. */
    fun scan(includeSystem: Boolean, onProgress: (done: Int, total: Int) -> Unit): ScanResult {
        val state = collectSystemState()
        val names = installedPackageNames()
        val reports = ArrayList<AppReport>()

        names.forEachIndexed { i, name ->
            onProgress(i + 1, names.size)
            if (name == context.packageName) return@forEachIndexed
            val info = packageInfo(name) ?: return@forEachIndexed
            val appInfo = info.applicationInfo ?: return@forEachIndexed
            val isSystem = (appInfo.flags and ApplicationInfo.FLAG_SYSTEM) != 0
            if (isSystem && !includeSystem) return@forEachIndexed

            val installer = installerOf(name)
            reports += AppReport(
                packageName = name,
                label = appInfo.loadLabel(pm).toString(),
                versionName = info.versionName,
                isSystem = isSystem,
                installer = installer,
                apkPath = appInfo.sourceDir,
                findings = Heuristics.evaluate(info, isSystem, installer, state),
            )
        }

        return ScanResult(
            apps = reports.sortedWith(compareByDescending<AppReport> { it.score }.thenBy { it.label.lowercase() }),
            deviceChecks = deviceChecks(),
            scannedCount = reports.size,
        )
    }

    private fun collectSystemState(): SystemState {
        val cr = context.contentResolver

        val accessibility = HashSet<String>()
        runCatching {
            val am = context.getSystemService(AccessibilityManager::class.java)
            am?.getEnabledAccessibilityServiceList(AccessibilityServiceInfo.FEEDBACK_ALL_MASK)
                ?.mapNotNullTo(accessibility) { it.resolveInfo?.serviceInfo?.packageName }
        }
        runCatching {
            Settings.Secure.getString(cr, Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES)
                ?.let { accessibility += packagesFromComponentList(it) }
        }

        val imes = runCatching {
            context.getSystemService(InputMethodManager::class.java)
                ?.enabledInputMethodList?.map { it.packageName }?.toSet()
        }.getOrNull().orEmpty()

        val defaultIme = runCatching {
            Settings.Secure.getString(cr, Settings.Secure.DEFAULT_INPUT_METHOD)
                ?.let { ComponentName.unflattenFromString(it)?.packageName ?: it.substringBefore('/') }
        }.getOrNull()

        val admins = runCatching {
            context.getSystemService(DevicePolicyManager::class.java)
                ?.activeAdmins.orEmpty().map { it.packageName }.toSet()
        }.getOrDefault(emptySet())

        val listeners = runCatching {
            Settings.Secure.getString(cr, "enabled_notification_listeners")
                ?.let { packagesFromComponentList(it) }
        }.getOrNull().orEmpty()

        val defaultSms = runCatching { Telephony.Sms.getDefaultSmsPackage(context) }.getOrNull()

        return SystemState(
            enabledAccessibility = accessibility,
            enabledImes = imes,
            defaultIme = defaultIme,
            activeAdmins = admins,
            notificationListeners = listeners,
            launcherPackages = launcherPackages(),
            defaultSms = defaultSms,
        )
    }

    private fun packagesFromComponentList(value: String): Set<String> =
        value.split(':')
            .filter { it.isNotBlank() }
            .mapNotNull { ComponentName.unflattenFromString(it)?.packageName }
            .toSet()

    @Suppress("DEPRECATION")
    private fun installedPackageNames(): List<String> {
        val packages = if (Build.VERSION.SDK_INT >= 33) {
            pm.getInstalledPackages(PackageManager.PackageInfoFlags.of(0))
        } else {
            pm.getInstalledPackages(0)
        }
        return packages.map { it.packageName }
    }

    // Diambil per paket (bukan sekaligus) supaya tidak kena batas ukuran Binder.
    @Suppress("DEPRECATION")
    private fun packageInfo(name: String): PackageInfo? = runCatching {
        val flags = PackageManager.GET_PERMISSIONS or PackageManager.GET_SERVICES or PackageManager.GET_RECEIVERS
        if (Build.VERSION.SDK_INT >= 33) {
            pm.getPackageInfo(name, PackageManager.PackageInfoFlags.of(flags.toLong()))
        } else {
            pm.getPackageInfo(name, flags)
        }
    }.getOrNull()

    @Suppress("DEPRECATION")
    private fun launcherPackages(): Set<String> {
        val intent = Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER)
        val list = if (Build.VERSION.SDK_INT >= 33) {
            pm.queryIntentActivities(intent, PackageManager.ResolveInfoFlags.of(0))
        } else {
            pm.queryIntentActivities(intent, 0)
        }
        return list.map { it.activityInfo.packageName }.toSet()
    }

    @Suppress("DEPRECATION")
    private fun installerOf(name: String): String? = runCatching {
        if (Build.VERSION.SDK_INT >= 30) {
            pm.getInstallSourceInfo(name).installingPackageName
        } else {
            pm.getInstallerPackageName(name)
        }
    }.getOrNull()

    private fun deviceChecks(): List<DeviceCheck> {
        val cr = context.contentResolver
        val checks = mutableListOf<DeviceCheck>()

        val suPaths = listOf(
            "/system/bin/su", "/system/xbin/su", "/sbin/su", "/system/sbin/su",
            "/vendor/bin/su", "/data/local/bin/su", "/data/local/xbin/su", "/system/app/Superuser.apk",
        )
        val rooted = suPaths.any { File(it).exists() } || Build.TAGS?.contains("test-keys") == true
        checks += if (rooted) {
            DeviceCheck(
                "Indikasi HP di-root", "Ditemukan file su atau build test-keys. Di HP yang di-root, malware " +
                    "bisa mendapat akses penuh dan tidak bisa dideteksi aplikasi biasa.", true
            )
        } else {
            DeviceCheck("Tidak ada indikasi root", "Tidak ditemukan file su yang umum.", false)
        }

        val adb = runCatching { Settings.Global.getInt(cr, Settings.Global.ADB_ENABLED, 0) == 1 }.getOrDefault(false)
        checks += if (adb) {
            DeviceCheck(
                "USB debugging AKTIF", "Orang yang memegang HP-mu dan punya komputer bisa memasang aplikasi " +
                    "diam-diam. Matikan di Opsi Pengembang jika tidak dipakai.", true
            )
        } else {
            DeviceCheck("USB debugging mati", "Bagus.", false)
        }

        val patch = Build.VERSION.SECURITY_PATCH
        val ageDays = runCatching { ChronoUnit.DAYS.between(LocalDate.parse(patch), LocalDate.now()) }.getOrNull()
        checks += when {
            ageDays == null -> DeviceCheck("Patch keamanan: $patch", "Tanggal tidak bisa dibaca.", false)
            ageDays > 365 -> DeviceCheck(
                "Patch keamanan usang ($patch)", "Lebih dari setahun tidak diperbarui. Celah keamanan lama " +
                    "bisa dimanfaatkan malware. Cek pembaruan sistem.", true
            )
            else -> DeviceCheck("Patch keamanan: $patch", "Masih tergolong baru.", false)
        }

        return checks
    }
}
