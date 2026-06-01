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

4. Di terminal terpisah jalankan client CLI. Contoh alur dasar untuk user `alice`:
- Buat vault baru (mencetak recovery share):
```powershell
go run ./src/client create alice
```
- Buka vault (akses normal — gabungan local share + server share):
```powershell
go run ./src/client open alice
```
- Tambah entry ke vault:
```powershell
go run ./src/client add alice
```

5. Mengecek isi yang disimpan di server (menggunakan PowerShell):
```powershell
Invoke-RestMethod -Uri "http://localhost:8080/vault?user_id=alice"
```
Hasilnya berisi `server_share`, `vault`, `nonce` dalam base64 — bukan plaintext.

## ── .✦ Environment / konfigurasi
- Go: minimal versi 1.20 direkomendasikan.
- Port default server: `:8080` (ubah dengan flag `-addr`).
- Lokasi database server default: `data/vaults.db` (ubah dengan flag `-db`).
- Lokasi penyimpanan lokal client default: `data/client/`.
- Driver SQLite: `modernc.org/sqlite` (pure-Go) — tidak membutuhkan toolchain C/CGO.