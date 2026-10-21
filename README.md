# 🔒 Simulasi Keamanan Password - Hashing SHA-256 & Salting

Proyek ini adalah aplikasi simulasi Keamanan Siber yang mengimplementasikan sistem registrasi dan autentikasi (login) menggunakan algoritma kriptografi **SHA-256** dengan perbandingan 4 metode penyimpanan password:
1. **Plaintext** (Password biasa tanpa enkripsi/hash)
2. **Hash Saja** (`SHA256(password)`)
3. **Password + Hash** (`SHA256(password + SHA256(password))`)
4. **Password + Salting** (`SHA256(password + salt)`) — digunakan untuk verifikasi login

## 📁 Struktur File

- `index.php` — Logika backend PHP (koneksi PDO MySQL, manajemen Session PRG/Flash, perhitungan hash SHA-256) dan struktur tampilan HTML.
- `style.css` — File stylesheet terpisah untuk seluruh tata letak halaman, komponen form, tombol lihat/sembunyikan password, dan tabel responsif.
- `README.md` — Dokumentasi instalasi dan penggunaan aplikasi.

## 🛠️ Prasyarat & Instalasi Database

Aplikasi ini secara otomatis membuat database `kss_login` dan tabel `users` saat pertama kali dijalankan. Namun, jika Anda ingin membuatnya secara manual melalui **phpMyAdmin**, jalankan query SQL berikut:

```sql
-- 1. Membuat Database
CREATE DATABASE IF NOT EXISTS kss_login
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_unicode_ci;

USE kss_login;

-- 2. Membuat Struktur Tabel Users
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(100) NOT NULL UNIQUE,
    plaintext VARCHAR(255) NOT NULL COMMENT '1. Password biasa (Plaintext)',
    hash_only VARCHAR(255) NOT NULL COMMENT '2. Hash SHA-256 murni tanpa salt',
    pass_plus_hash VARCHAR(255) NOT NULL COMMENT '3. Password + Hash (SHA-256(password + hash_only))',
    salt VARCHAR(64) NOT NULL COMMENT '4a. Salt unik per user',
    salted_hash VARCHAR(255) NOT NULL COMMENT '4b. Password + Salting (SHA-256(password + salt)) - Dipakai untuk Login',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
```

## 🚀 Cara Menjalankan Aplikasi

1. Pastikan modul **Apache** dan **MySQL** pada XAMPP / Laragon sudah berjalan (*Start*).
2. Simpan file `index.php` dan `style.css` di dalam satu folder yang sama pada direktori web server Anda (contoh: `xampp/htdocs/KSS/`).
3. Buka browser dan akses URL: **`http://localhost/KSS/index.php`**.
