# Aysmawe Scanner

Aplikasi Android sederhana untuk memeriksa tanda-tanda **keylogger, spyware, dan trojan** di HP.

## Apa yang diperiksa

| Pemeriksaan | Kenapa penting |
|---|---|
| Database stalkerware publik (nama paket + SHA-1 sertifikat) | Mengenali stalkerware/"tracker" yang sudah diketahui, termasuk yang menyamar dengan nama lain |
| Accessibility Service aktif | Cara utama keylogger & trojan perbankan membaca layar dan ketikan |
| Keyboard (IME) pihak ketiga | Semua ketikan lewat keyboard |
| Device Admin aktif | Bisa mengunci HP dan membuat aplikasi sulit dihapus |
| Notification listener | Bisa membaca OTP dan chat dari notifikasi |
| Izin SMS, overlay, mic+kamera+lokasi, call log, pasang aplikasi | Pola izin khas spyware/trojan |
| Sumber instalasi | APK dari luar toko resmi lebih berisiko |
| Ikon tersembunyi | Malware sering menyembunyikan ikonnya |
| Root, USB debugging, umur patch keamanan | Kondisi perangkat yang melemahkan keamanan |
| VirusTotal (opsional) | Cocokkan hash SHA-256 APK dengan 70+ antivirus |

Setiap temuan memberi skor. Total skor menentukan level: **Aman** (<10), **Rendah** (10–29), **Sedang** (30–59), **Tinggi** (≥60).

Kecocokan dengan database stalkerware langsung memberi skor +100 (Tinggi). Kecocokan dengan daftar
"watchware" (aplikasi pemantau yang tidak bersembunyi, mis. parental control) memberi +20.

## Batasan (penting)

- Skor tinggi berarti **perlu dicek**, bukan pasti malware. Contohnya, pengelola password memang memakai Accessibility.
- Karena sandbox Android, aplikasi ini **tidak bisa** memindai isi/memori aplikasi lain. Pendekatannya heuristik (izin dan akses), bukan database signature seperti antivirus komersial.
- Malware di HP yang sudah di-root bisa menyembunyikan diri dari pemeriksaan ini.
- Database stalkerware tidak lengkap; tidak ada kecocokan bukan jaminan bersih.
- Spyware kelas negara seperti **Pegasus** masuk lewat celah sistem (zero-click) dan tidak bisa dideteksi
  aplikasi biasa mana pun. Untuk itu gunakan [MVT](https://github.com/mvt-project/mvt) dari Amnesty
  International di PC, atau minta bantuan Access Now Digital Security Helpline.
- Tetap aktifkan **Google Play Protect** sebagai lapisan utama.

## Memperbarui database stalkerware

```
pip install pyyaml
python3 tools/update_ioc.py
```

Perintah ini menulis ulang `app/src/main/assets/stalkerware_ioc.json`. Commit hasilnya lalu build ulang APK.

## Atribusi

Data indikator stalkerware dari [AssoEchap/stalkerware-indicators](https://github.com/AssoEchap/stalkerware-indicators)
oleh Echap, berlisensi [CC-BY 4.0](https://creativecommons.org/licenses/by/4.0/).

## Cara mendapatkan APK

1. Buka tab **Actions** di repo GitHub ini, lalu pilih run **Build APK** terbaru yang berhasil.
2. Unduh artifact `aysmawe-scanner-apk` (berupa zip), lalu ekstrak untuk mendapatkan file `.apk`.
3. Pindahkan ke HP dan pasang. Izinkan "instal dari sumber tidak dikenal" khusus untuk aplikasi pembuka file tersebut.

APK ditandatangani dengan debug key, jadi cocok untuk pemakaian pribadi, bukan untuk Play Store.

## Build lokal

Butuh JDK 17 dan Android SDK (atau Android Studio):

```
./gradlew assembleRelease
```
