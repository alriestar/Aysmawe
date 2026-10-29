package com.aysmawe.scanner.scan

import android.content.pm.PackageInfo

/**
 * Aturan heuristik penilaian risiko. Skor tinggi berarti aplikasi memegang kemampuan yang
 * biasa disalahgunakan keylogger/spyware/trojan, BUKAN bukti pasti bahwa itu malware.
 */
object Heuristics {

    private const val BIND_ACCESSIBILITY = "android.permission.BIND_ACCESSIBILITY_SERVICE"
    private const val BIND_IME = "android.permission.BIND_INPUT_METHOD"
    private const val BIND_DEVICE_ADMIN = "android.permission.BIND_DEVICE_ADMIN"

    /** Toko aplikasi resmi; selain ini dianggap pasang manual (sideload). */
    private val TRUSTED_INSTALLERS = setOf(
        "com.android.vending",               // Google Play
        "com.sec.android.app.samsungapps",   // Galaxy Store
        "com.huawei.appmarket",              // Huawei AppGallery
        "com.xiaomi.market",                 // Xiaomi GetApps
        "com.xiaomi.mipicks",
        "com.heytap.market",                 // OPPO / realme
        "com.oppo.market",
        "com.vivo.appstore",                 // vivo
        "com.amazon.venezia",                // Amazon Appstore
        "org.fdroid.fdroid",                 // F-Droid
    )

    fun evaluate(
        info: PackageInfo,
        isSystem: Boolean,
        installer: String?,
        state: SystemState,
    ): List<Finding> {
        val pkg = info.packageName
        val findings = mutableListOf<Finding>()

        val perms = info.requestedPermissions.orEmpty()
        val flags = info.requestedPermissionsFlags
        val requested = perms.toSet()
        val granted = perms.filterIndexed { i, _ ->
            flags != null && i < flags.size && (flags[i] and PackageInfo.REQUESTED_PERMISSION_GRANTED) != 0
        }.toSet()

        fun has(p: String) = "android.permission.$p" in requested
        fun isGranted(p: String) = "android.permission.$p" in granted
        // Izin yang sudah diberikan dapat bobot penuh, yang baru diminta setengah.
        fun weight(p: String, full: Int) = if (isGranted(p)) full else full / 2
        fun note(p: String) = if (isGranted(p)) "sudah diizinkan" else "diminta, belum tentu diizinkan"

        val declaresAccessibility = info.services.orEmpty().any { it.permission == BIND_ACCESSIBILITY }
        val declaresIme = info.services.orEmpty().any { it.permission == BIND_IME }
        val declaresAdmin = info.receivers.orEmpty().any { it.permission == BIND_DEVICE_ADMIN }

        // --- Keylogger: Accessibility Service & keyboard ---
        if (pkg in state.enabledAccessibility) {
            findings += Finding(
                40, "Accessibility Service AKTIF",
                "Bisa membaca semua teks di layar dan yang kamu ketik, serta menekan tombol atas namamu. " +
                    "Ini cara utama keylogger dan trojan perbankan di Android. Wajar hanya untuk aplikasi " +
                    "tepercaya (mis. pengelola password, pembaca layar)."
            )
        } else if (declaresAccessibility) {
            findings += Finding(
                10, "Punya Accessibility Service (belum aktif)",
                "Aplikasi ini bisa meminta akses aksesibilitas. Jangan aktifkan kalau tidak jelas kegunaannya."
            )
        }

        if (pkg == state.defaultIme) {
            findings += Finding(
                35, "Keyboard default pihak ketiga",
                "Semua yang kamu ketik (password, PIN, chat) lewat aplikasi ini. Pastikan ini keyboard yang " +
                    "memang kamu pasang sendiri dari sumber tepercaya."
            )
        } else if (pkg in state.enabledImes) {
            findings += Finding(
                20, "Keyboard pihak ketiga aktif",
                "Keyboard ini sudah diaktifkan dan bisa dipilih untuk mengetik."
            )
        } else if (declaresIme) {
            findings += Finding(5, "Berisi keyboard (tidak aktif)", "Menyediakan keyboard tapi belum diaktifkan.")
        }

        // --- Kontrol perangkat ---
        if (pkg in state.activeAdmins) {
            findings += Finding(
                30, "Device Admin AKTIF",
                "Bisa mengunci/menghapus data HP dan membuat aplikasi sulit di-uninstall. Nonaktifkan dulu di " +
                    "Pengaturan > Keamanan > Aplikasi admin perangkat sebelum menghapus."
            )
        } else if (declaresAdmin) {
            findings += Finding(5, "Bisa meminta Device Admin", "Belum aktif.")
        }

        if (pkg in state.notificationListeners) {
            findings += Finding(
                15, "Membaca semua notifikasi",
                "Bisa melihat isi notifikasi semua aplikasi, termasuk kode OTP dan pesan chat."
            )
        }

        // --- Izin berbahaya ---
        val isDefaultSms = pkg == state.defaultSms
        if (!isDefaultSms && (has("READ_SMS") || has("RECEIVE_SMS"))) {
            val p = if (isGranted("READ_SMS")) "READ_SMS" else if (isGranted("RECEIVE_SMS")) "RECEIVE_SMS" else "READ_SMS"
            findings += Finding(
                weight(p, 20), "Akses SMS (${note(p)})",
                "Bisa membaca SMS, termasuk kode OTP bank/e-wallet, padahal bukan aplikasi SMS default."
            )
        }
        if (!isDefaultSms && has("SEND_SMS")) {
            findings += Finding(
                weight("SEND_SMS", 10), "Bisa mengirim SMS (${note("SEND_SMS")})",
                "Bisa dipakai mengirim SMS premium atau menyebarkan link malware ke kontakmu."
            )
        }
        if (has("SYSTEM_ALERT_WINDOW")) {
            findings += Finding(
                10, "Tampil di atas aplikasi lain",
                "Bisa menampilkan jendela palsu di atas aplikasi lain (mis. halaman login bank palsu)."
            )
            if (declaresAccessibility) {
                findings += Finding(
                    15, "Kombinasi overlay + aksesibilitas",
                    "Kombinasi ini adalah pola khas trojan perbankan Android."
                )
            }
        }
        if (has("RECORD_AUDIO") && (has("CAMERA") || has("ACCESS_FINE_LOCATION")) && has("RECEIVE_BOOT_COMPLETED")) {
            findings += Finding(
                15, "Pola spyware: mikrofon + kamera/lokasi + jalan saat HP menyala",
                "Wajar untuk aplikasi chat/video call, mencurigakan untuk aplikasi yang tidak membutuhkannya."
            )
        }
        if (has("READ_CALL_LOG") || has("PROCESS_OUTGOING_CALLS")) {
            findings += Finding(10, "Akses riwayat panggilan", "Bisa melihat siapa yang kamu telepon dan kapan.")
        }
        if (has("REQUEST_INSTALL_PACKAGES") && !isSystem) {
            findings += Finding(
                10, "Bisa memasang aplikasi lain",
                "Malware tipe \"dropper\" memakai izin ini untuk mengunduh dan memasang malware tambahan."
            )
        }

        // --- Asal & penyamaran ---
        if (!isSystem && (installer == null || installer !in TRUSTED_INSTALLERS)) {
            findings += Finding(
                15, "Dipasang di luar toko resmi",
                "Sumber: ${installer ?: "tidak diketahui"}. APK dari luar Play Store tidak melewati pemeriksaan " +
                    "Google Play Protect saat dipasang."
            )
        }
        if (!isSystem && pkg !in state.launcherPackages && !declaresIme) {
            findings += Finding(
                15, "Tidak punya ikon di menu aplikasi",
                "Malware sering menyembunyikan ikonnya agar tidak ketahuan. Beberapa plugin/add-on resmi juga " +
                    "tidak punya ikon."
            )
        }

        return findings.filter { it.points > 0 }
    }
}
