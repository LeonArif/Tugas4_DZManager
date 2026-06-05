# DZManager — Password Manager Terdistribusi (Tugas 4 II4021 Kriptografi)

## ── .✦ Deskripsi singkat
DZManager adalah aplikasi password manager berbasis CLI dengan arsitektur client-server.
Klien melakukan semua operasi kriptografi (pembuatan master key, pembagian share dengan
Shamir Secret Sharing, enkripsi AES-128-GCM, derivasi kunci dengan Argon2id), sedangkan
server hanya menyimpan satu server-share, vault terenkripsi, nonce, dan metadata pengguna.

Desain ini menerapkan prinsip zero-knowledge: server tidak pernah menerima master key,
local share, recovery share, atau isi vault dalam bentuk plaintext.

## ── .✦ Tech stack
- Bahasa: Go
- Database server: SQLite (BLOB storage)
- Kriptografi: AES-128-GCM, Shamir Secret Sharing (GF(256)), Argon2id (KDF), CSPRNG
- HTTP API: net/http (standalone server)

## ── .✦ Dependensi
- golang.org/x/crypto (Argon2id)
- golang.org/x/term (password prompt)
- modernc.org/sqlite (pure-Go SQLite driver)

Semua dependensi dikelola oleh `go.mod`.

## ── .✦ Struktur penting (lokasi file)
- Server storage: [internal/storage/server_store.go](internal/storage/server_store.go)
- Server API: [internal/api/handler.go](internal/api/handler.go)
- Client API helper: [internal/api/client_api.go](internal/api/client_api.go)
- Client local store: [internal/storage/client_store.go](internal/storage/client_store.go)
- Kripto: [internal/crypto/aes_gcm.go](internal/crypto/aes_gcm.go), [internal/crypto/shamir.go](internal/crypto/shamir.go), [internal/crypto/kdf.go](internal/crypto/kdf.go), [internal/crypto/csprng.go](internal/crypto/csprng.go)
- Vault model: [internal/vault/vault.go](internal/vault/vault.go)
- Server entrypoint: [src/server/main.go](src/server/main.go)
- Client CLI: [src/client/main.go](src/client/main.go)

## ── .✦ Cara menjalankan (local development)
1. Pastikan Go terpasang (disarankan Go 1.20+).
2. Ambil dependensi dan build:
```powershell
cd "../Tugas4_DZManager"
go mod tidy
go build ./...
```

3. Jalankan server (default port `:8080` dan database `data/vaults.db`):
```powershell
go run ./src/server -db data/vaults.db -addr :8080
```

4. Di terminal terpisah jalankan client CLI. Catatan: pada CLI ini, flag harus ditulis sebelum subcommand.

Contoh alur uji lengkap untuk user `alice`:

- Buat vault baru. Perintah ini akan membuat master key, memecahnya dengan Shamir Secret Sharing, lalu menampilkan recovery share Base64 yang harus disimpan:
```powershell
go run ./src/client create alice
```

- Buka vault normal. Password master diminta, lalu client menggabungkan local share dan server share:
```powershell
go run ./src/client open alice
```

- Tambah entry password baru. Saat diminta, isi service, username, dan password. Jika password dikosongkan, client bisa membuat password acak:
```powershell
go run ./src/client add alice
```

- Edit entry yang sudah ada. Pilih nomor entry yang ingin diubah, lalu isi field baru atau kosongkan untuk mempertahankan nilai lama:
```powershell
go run ./src/client edit alice
```

- Hapus entry yang sudah ada. Pilih nomor entry yang ingin dihapus:
```powershell
go run ./src/client delete alice
```

- Mode backup saat server tidak tersedia. Gunakan local store + recovery share yang tadi sudah disimpan. Mode ini bersifat read-only:
```powershell
go run ./src/client backup alice
```

- Bonus visualisasi QR / visual cryptography. Program meminta recovery share Base64, lalu menghasilkan QR dan file share gambar:
```powershell
go run ./src/client/main.go -visual-out data/visual/alice visual alice
```

- Jika `-visual-out` tidak ditulis, hasil akan disimpan ke `data/visual/<user>` secara default.
- Setelah command dijalankan, program akan meminta input recovery share Base64 yang sama seperti yang muncul saat `create`.

5. Mengecek isi yang disimpan di server (menggunakan PowerShell):
```powershell
Invoke-RestMethod -Uri "http://localhost:8080/vault?user_id=alice"
```
Hasilnya berisi `server_share`, `vault`, `nonce` dalam base64 — bukan plaintext.

## ── .✦ Skenario pengujian yang disarankan
1. Jalankan `create alice`, simpan recovery share Base64 yang tampil di layar.
2. Jalankan `open alice` untuk memastikan vault bisa dibuka dalam mode normal.
3. Jalankan `add alice`, lalu `open alice` lagi untuk memastikan entry baru tersimpan.
4. Jalankan `edit alice` untuk mengubah salah satu entry, lalu `open alice` lagi untuk verifikasi.
5. Jalankan `delete alice` untuk menghapus salah satu entry, lalu `open alice` lagi untuk verifikasi.
6. Simulasikan backup dengan mematikan server, lalu jalankan `backup alice` dan masukkan recovery share Base64 yang sudah disimpan.
7. Jalankan `visual alice` dan masukkan recovery share Base64 yang sama untuk menghasilkan `qr.png`, `share1.png`, `share2.png`, dan `combined.png`.
8. Buka file-file hasil visualisasi di folder output untuk memastikan QR dan share gambar terbentuk dengan benar.

## ── .✦ Environment / konfigurasi
- Go: minimal versi 1.20 direkomendasikan.
- Port default server: `:8080` (ubah dengan flag `-addr`).
- Lokasi database server default: `data/vaults.db` (ubah dengan flag `-db`).
- Lokasi penyimpanan lokal client default: `data/client/`.
- Driver SQLite: `modernc.org/sqlite` (pure-Go) — tidak membutuhkan toolchain C/CGO.