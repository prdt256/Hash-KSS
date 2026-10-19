# 🔒 Sistem Login - Hashing & Salting Dinamis

Proyek ini adalah tugas Keamanan Siber yang mengimplementasikan sistem autentikasi (login) menggunakan berbagai metode pengamanan password, mulai dari plaintext, hash murni, hingga kombinasi *Salt* dinamis per user.

---

## 🛠️ Prasyarat & Instalasi Database (Wajib)

Sebelum menjalankan aplikasi di XAMPP, **Anda wajib membuat database terlebih dahulu**. Ikuti langkah-langkah berikut:

1. Buka **XAMPP Control Panel** dan pastikan modul **Apache** dan **MySQL** sudah berjalan (*Start*).
2. Buka browser dan akses **[http://localhost/phpmyadmin](http://localhost/phpmyadmin)**.
3. Masuk ke menu **SQL**.
4. *Copy* (salin) dan *paste* (tempel) query SQL di bawah ini, lalu klik **Go**:

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

> **Catatan:** Tabel ini sengaja dikosongkan. Semua data *user*, *password*, *hash*, dan *salt* akan terisi secara dinamis saat Anda melakukan registrasi/input melalui halaman web (`index.php`).

---

## 🚀 Cara Menjalankan Aplikasi

1. Pastikan folder proyek berada di dalam direktori htdocs (`xampp/htdocs/KSS`).
2. Buka browser Anda.
3. Akses aplikasi melalui URL: **`http://localhost/KSS/index.php`**
