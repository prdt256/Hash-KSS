<?php
session_start();

// =========================================================
// KONFIGURASI KONEKSI DATABASE MYSQL
// =========================================================
$db_host = "localhost";
$db_user = "root";
$db_pass = "";          // Kosongkan untuk default XAMPP / Laragon
$db_name = "kss_login";

$koneksi_db = null;
$error_db = "";

try {
    // 1. Koneksi ke server MySQL
    $pdo_server = new PDO("mysql:host=$db_host;charset=utf8mb4", $db_user, $db_pass, [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION
    ]);

    // 2. Buat database jika belum ada
    $pdo_server->exec("CREATE DATABASE IF NOT EXISTS `$db_name` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci");

    // 3. Koneksi ke database kss_login
    $koneksi_db = new PDO("mysql:host=$db_host;dbname=$db_name;charset=utf8mb4", $db_user, $db_pass, [
        PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC
    ]);

    // 4. Buat tabel users jika belum ada
    $koneksi_db->exec("
        CREATE TABLE IF NOT EXISTS `users` (
            `id` INT AUTO_INCREMENT PRIMARY KEY,
            `username` VARCHAR(100) NOT NULL UNIQUE,
            `plaintext` VARCHAR(255) NOT NULL,
            `hash_only` VARCHAR(255) NOT NULL,
            `pass_plus_hash` VARCHAR(255) NOT NULL,
            `salt` VARCHAR(64) NOT NULL,
            `salted_hash` VARCHAR(255) NOT NULL,
            `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            `updated_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    ");

} catch (PDOException $e) {
    $error_db = $e->getMessage();
}

// Helper untuk redirect bersih (Post/Redirect/Get pattern) agar refresh tidak memicu Confirm Form Resubmission
function redirectClean(): void {
    $clean_url = strtok($_SERVER["REQUEST_URI"], '?');
    header("Location: " . $clean_url);
    exit;
}

// =========================================================
// PROSES 1: REGISTRASI / SIMPAN USER BARU SECARA DINAMIS
// =========================================================
if ($_SERVER["REQUEST_METHOD"] === "POST" && ($_POST['aksi'] ?? '') === 'registrasi' && $koneksi_db) {
    $username = trim($_POST['reg_username'] ?? '');
    $password = $_POST['reg_password'] ?? '';
    $custom_salt = trim($_POST['reg_custom_salt'] ?? '');

    if ($username !== '' && $password !== '') {
        // 1. Password Biasa (Plaintext)
        $plaintext = $password;

        // 2. Hash Saja (SHA-256 murni dari password)
        $hash_only = hash('sha256', $password);

        // 3. Password + Hash (Password digabung dengan hasil Hash Saja, lalu di-hash SHA-256)
        $gabungan_pass_hash = $password . $hash_only;
        $pass_plus_hash = hash('sha256', $gabungan_pass_hash);

        // 4. Password + Salting (Gunakan custom salt jika diisi, atau generate acak 16 karakter hex)
        $salt = ($custom_salt !== '') ? $custom_salt : bin2hex(random_bytes(8));
        $gabungan_pass_salt = $password . $salt;
        $salted_hash = hash('sha256', $gabungan_pass_salt);

        // Cek terlebih dahulu apakah username sudah terdaftar agar AUTO_INCREMENT tidak loncat
        $stmt_cek = $koneksi_db->prepare("SELECT `id` FROM `users` WHERE `username` = :username LIMIT 1");
        $stmt_cek->execute([':username' => $username]);
        $existing_user = $stmt_cek->fetch();

        if ($existing_user) {
            // Update data tanpa memicu penambahan AUTO_INCREMENT
            $stmt_upd = $koneksi_db->prepare("
                UPDATE `users`
                SET `plaintext`      = :plaintext,
                    `hash_only`      = :hash_only,
                    `pass_plus_hash` = :pass_plus_hash,
                    `salt`           = :salt,
                    `salted_hash`    = :salted_hash
                WHERE `id` = :id
            ");
            $stmt_upd->execute([
                ':plaintext'      => $plaintext,
                ':hash_only'      => $hash_only,
                ':pass_plus_hash' => $pass_plus_hash,
                ':salt'           => $salt,
                ':salted_hash'    => $salted_hash,
                ':id'             => $existing_user['id']
            ]);
            $pesan = "Data user <b>" . htmlspecialchars($username) . "</b> sudah ada dan berhasil diperbarui di database MySQL!";
        } else {
            // Rapikan nilai AUTO_INCREMENT ke MAX(id) + 1 sebelum insert agar urutan ID tidak loncat
            $koneksi_db->exec("ALTER TABLE `users` AUTO_INCREMENT = 1");

            $stmt_ins = $koneksi_db->prepare("
                INSERT INTO `users` (`username`, `plaintext`, `hash_only`, `pass_plus_hash`, `salt`, `salted_hash`)
                VALUES (:username, :plaintext, :hash_only, :pass_plus_hash, :salt, :salted_hash)
            ");
            $stmt_ins->execute([
                ':username'       => $username,
                ':plaintext'      => $plaintext,
                ':hash_only'      => $hash_only,
                ':pass_plus_hash' => $pass_plus_hash,
                ':salt'           => $salt,
                ':salted_hash'    => $salted_hash
            ]);
            $pesan = "User baru <b>" . htmlspecialchars($username) . "</b> berhasil diproses dan disimpan ke database MySQL!";
        }

        // Simpan ke flash session untuk ditampilkan 1x setelah redirect (hilang otomatis jika di-refresh)
        $_SESSION['kss_flash'] = [
            'pesan_aksi'       => $pesan,
            'tipe_pesan'       => 'ok',
            'selected_user'    => $username,
            'hasil_registrasi' => [
                'username'           => $username,
                'plaintext'          => $plaintext,
                'hash_only'          => $hash_only,
                'gabungan_pass_hash' => $gabungan_pass_hash,
                'pass_plus_hash'     => $pass_plus_hash,
                'salt'               => $salt,
                'jenis_salt'         => ($custom_salt !== '') ? 'Input Manual (Custom)' : 'Acak Otomatis (16 Karakter Hex)',
                'gabungan_pass_salt' => $gabungan_pass_salt,
                'salted_hash'        => $salted_hash
            ]
        ];

        redirectClean();
    }
}

// =========================================================
// PROSES 2: VERIFIKASI LOGIN DARI DATABASE (METODE SALTING)
// =========================================================
if ($_SERVER["REQUEST_METHOD"] === "POST" && ($_POST['aksi'] ?? '') === 'login' && $koneksi_db) {
    $input_user = trim($_POST['login_username'] ?? '');
    $input_pass = $_POST['login_password'] ?? '';

    $stmt = $koneksi_db->prepare("SELECT * FROM `users` WHERE `username` = :username LIMIT 1");
    $stmt->execute([':username' => $input_user]);
    $row_db = $stmt->fetch();

    if ($row_db) {
        $stored_salt = $row_db['salt'];
        $stored_hash = $row_db['salted_hash'];
        $string_gabungan = $input_pass . $stored_salt;
        $computed_hash = hash('sha256', $string_gabungan);
        $cocok = hash_equals($stored_hash, $computed_hash);

        $_SESSION['kss_flash'] = [
            'selected_user' => $row_db['username'],
            'hasil_login'   => [
                'ditemukan'       => true,
                'sukses'          => $cocok,
                'input_user'      => $input_user,
                'input_pass'      => $input_pass,
                'stored_salt'     => $stored_salt,
                'string_gabungan' => $string_gabungan,
                'computed_hash'   => $computed_hash,
                'stored_hash'     => $stored_hash
            ]
        ];
    } else {
        $_SESSION['kss_flash'] = [
            'hasil_login' => [
                'ditemukan'  => false,
                'sukses'     => false,
                'input_user' => $input_user,
                'input_pass' => $input_pass
            ]
        ];
    }

    redirectClean();
}

// =========================================================
// PROSES 3: LIHAT DETAIL, HAPUS USER, ATAU RESET DATABASE
// =========================================================
if ($_SERVER["REQUEST_METHOD"] === "POST" && ($_POST['aksi'] ?? '') === 'lihat_detail' && $koneksi_db) {
    $detail_user = trim($_POST['detail_username'] ?? '');
    if ($detail_user !== '') {
        $_SESSION['kss_flash'] = [
            'selected_user' => $detail_user
        ];
    }
    redirectClean();
}

if ($_SERVER["REQUEST_METHOD"] === "POST" && ($_POST['aksi'] ?? '') === 'hapus_user' && $koneksi_db) {
    $id_hapus = (int)($_POST['id_user'] ?? 0);
    $stmt = $koneksi_db->prepare("DELETE FROM `users` WHERE `id` = :id");
    $stmt->execute([':id' => $id_hapus]);

    // Sesuaikan kembali AUTO_INCREMENT ke MAX(id) + 1 agar tidak ada loncatan ID untuk user berikutnya
    $koneksi_db->exec("ALTER TABLE `users` AUTO_INCREMENT = 1");

    $_SESSION['kss_flash'] = [
        'pesan_aksi' => "Data user berhasil dihapus dari database.",
        'tipe_pesan' => "warn"
    ];
    redirectClean();
}

if ($_SERVER["REQUEST_METHOD"] === "POST" && ($_POST['aksi'] ?? '') === 'reset_db' && $koneksi_db) {
    $koneksi_db->exec("TRUNCATE TABLE `users`");
    $_SESSION['kss_flash'] = [
        'pesan_aksi' => "Tabel <code>users</code> berhasil dikosongkan! Silakan mulai pengujian dari awal.",
        'tipe_pesan' => "warn"
    ];
    redirectClean();
}

// Jika ada parameter GET ?lihat=username, simpan ke flash lalu redirect bersih agar saat refresh kembali kosong
if ($_SERVER["REQUEST_METHOD"] === "GET" && isset($_GET['lihat']) && $koneksi_db) {
    $lihat_user = trim($_GET['lihat']);
    if ($lihat_user !== '') {
        $_SESSION['kss_flash'] = [
            'selected_user' => $lihat_user
        ];
    }
    redirectClean();
}

// =========================================================
// BACA FLASH DATA SATU KALI (HILANG SAAT HALAMAN DI-REFRESH)
// =========================================================
$flash = $_SESSION['kss_flash'] ?? [];
unset($_SESSION['kss_flash']);

$pesan_aksi       = $flash['pesan_aksi'] ?? "";
$tipe_pesan       = $flash['tipe_pesan'] ?? "ok";
$hasil_registrasi = $flash['hasil_registrasi'] ?? null;
$hasil_login      = $flash['hasil_login'] ?? null;
$selected_uname   = $flash['selected_user'] ?? null;
$user_terpilih    = null;

// Ambil seluruh daftar user yang ada di database saat ini
$daftar_users = [];
if ($koneksi_db) {
    $daftar_users = $koneksi_db->query("SELECT * FROM `users` ORDER BY `id` DESC")->fetchAll();

    // Tampilkan perbandingan di Bagian 3 HANYA jika baru saja ada aksi (Registrasi / Login / Klik Detail)
    if ($selected_uname !== null) {
        $stmt_sel = $koneksi_db->prepare("SELECT * FROM `users` WHERE `username` = :u LIMIT 1");
        $stmt_sel->execute([':u' => $selected_uname]);
        $user_terpilih = $stmt_sel->fetch() ?: null;
    }
}
?>
<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Simulasi Keamanan Password: Hashing SHA-256 &amp; Salting</title>
    <link rel="stylesheet" href="style.css">
</head>
<body>

<div class="container">
    <!-- Banner Header -->
    <div class="banner">
        <div class="banner-content">
            <span class="banner-tag">Keamanan Siber &bull; Algoritma Hashing SHA-256 &amp; Salting</span>
            <h1>Sistem Registrasi, Login &amp; Perbandingan Hashing Password</h1>
            <p>Simulasi pengamanan password dengan algoritma kriptografi <b>SHA-256</b> (Plaintext, Hash Murni, Password + Hash, serta Salted Hash) dan verifikasi login pada database MySQL.</p>
        </div>
        <div class="db-badge">
            <?php if ($koneksi_db): ?>
                <span class="status-dot online">&#9679;</span> Database Aktif: <b><?= htmlspecialchars($db_name); ?>.users</b> (<?= count($daftar_users); ?> akun)
            <?php else: ?>
                <span class="status-dot offline">&#9679;</span> Database Terputus
            <?php endif; ?>
        </div>
    </div>

    <!-- Peringatan jika MySQL mati -->
    <?php if (!$koneksi_db): ?>
        <div class="alert alert-err">
            <b>Koneksi ke Database MySQL Gagal!</b> (<code><?= htmlspecialchars($error_db); ?></code>)<br>
            Pastikan service <b>MySQL</b> pada XAMPP atau Laragon sudah dijalankan (Start), lalu muat ulang halaman ini.
        </div>
    <?php endif; ?>

    <!-- Notifikasi Aksi -->
    <?php if ($pesan_aksi !== ""): ?>
        <div class="alert <?= $tipe_pesan === 'ok' ? 'alert-ok' : 'alert-warn'; ?>">
            <?= $pesan_aksi; ?>
        </div>
    <?php endif; ?>

    <!-- DUA PANEL UTAMA: 1. REGISTRASI USER BARU & 2. PERCOBAAN LOGIN -->
    <div class="grid-2">
        <!-- Bagian 1: Form Registrasi User Baru -->
        <div class="card mb-0">
            <h2 class="card-header">
                <span>1. Registrasi User Baru</span>
                <span class="badge badge-safe">Input ke Database</span>
            </h2>
            <p class="desc">
                Daftarkan akun pengguna baru. Sistem akan mengolah password ke dalam 4 metode perbandingan menggunakan algoritma <b>SHA-256</b> lalu menyimpannya ke tabel <code>users</code>.
            </p>
            <p class="req-note">Ket: Tanda (<span class="req">*</span>) wajib diisi</p>

            <form method="POST" action="" autocomplete="off">
                <input type="hidden" name="aksi" value="registrasi">

                <label for="reg_username">Username Baru <span class="req">*</span></label>
                <input type="text" id="reg_username" name="reg_username" placeholder="Contoh: budi, andi, siregar..." required>

                <label for="reg_password">Password <span class="req">*</span></label>
                <div class="password-wrapper">
                    <input type="password" id="reg_password" name="reg_password" placeholder="Masukkan password akun..." required>
                    <button type="button" class="toggle-password" onclick="togglePassword('reg_password', this)" aria-label="Tampilkan atau sembunyikan password">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path>
                            <circle cx="12" cy="12" r="3"></circle>
                        </svg>
                        <span>Lihat</span>
                    </button>
                </div>

                <label for="reg_custom_salt">
                    Custom Salt <span class="hint">(Opsional &mdash; kosongkan agar dibuat acak otomatis 16 karakter hex)</span>
                </label>
                <input type="text" id="reg_custom_salt" name="reg_custom_salt" placeholder="Otomatis: random 16 karakter hex">

                <button type="submit" class="btn btn-blue" <?= !$koneksi_db ? 'disabled' : ''; ?>>
                    Proses &amp; Simpan User ke Database
                </button>
            </form>
        </div>

        <!-- Bagian 2: Form Percobaan Login -->
        <div class="card mb-0">
            <h2 class="card-header">
                <span>2. Percobaan Login (Verifikasi Salting)</span>
                <span class="badge badge-warn">Uji Autentikasi</span>
            </h2>
            <p class="desc">
                Uji login menggunakan akun yang sudah terdaftar. Sistem akan mengambil nilai <code>salt</code> milik user dari database, menggabungkannya dengan password login, lalu memverifikasi kecocokan hash SHA-256.
            </p>
            <p class="req-note">Ket: Tanda (<span class="req">*</span>) wajib diisi</p>

            <form method="POST" action="" autocomplete="off">
                <input type="hidden" name="aksi" value="login">

                <label for="login_username">Username <span class="req">*</span></label>
                <input type="text" id="login_username" name="login_username" value="<?= htmlspecialchars($hasil_login['input_user'] ?? ''); ?>" placeholder="Masukkan username yang terdaftar..." required>

                <label for="login_password">Password Login <span class="req">*</span></label>
                <div class="password-wrapper">
                    <input type="password" id="login_password" name="login_password" placeholder="Masukkan password untuk diuji..." required>
                    <button type="button" class="toggle-password" onclick="togglePassword('login_password', this)" aria-label="Tampilkan atau sembunyikan password login">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path>
                            <circle cx="12" cy="12" r="3"></circle>
                        </svg>
                        <span>Lihat</span>
                    </button>
                </div>

                <button type="submit" class="btn btn-emerald" <?= !$koneksi_db ? 'disabled' : ''; ?>>
                    Uji Login &amp; Tampilkan Alur Verifikasi
                </button>
            </form>

            <?php if ($hasil_login !== null): ?>
                <div style="margin-top: 14px;">
                    <?php if (!$hasil_login['ditemukan']): ?>
                        <div class="alert alert-err mb-0">
                            <b>AKUN TIDAK DITEMUKAN!</b><br>
                            Username: <code><?= htmlspecialchars($hasil_login['input_user']); ?></code> |
                            Password diuji: <code><?= htmlspecialchars($hasil_login['input_pass']); ?></code><br>
                            Akun belum terdaftar di database. Silakan daftarkan terlebih dahulu pada Bagian 1.
                        </div>
                    <?php elseif ($hasil_login['sukses']): ?>
                        <div class="alert alert-ok mb-0">
                            <b>LOGIN BERHASIL!</b><br>
                            Username: <code><?= htmlspecialchars($hasil_login['input_user']); ?></code> |
                            Password diuji: <code><?= htmlspecialchars($hasil_login['input_pass']); ?></code><br>
                            Perhitungan <code>SHA256(password_login + salt_db)</code> cocok 100% dengan <code>salted_hash</code> di database.
                        </div>
                    <?php else: ?>
                        <div class="alert alert-err mb-0">
                            <b>LOGIN GAGAL (PASSWORD SALAH)!</b><br>
                            Username: <code><?= htmlspecialchars($hasil_login['input_user']); ?></code> |
                            Password diuji: <code><?= htmlspecialchars($hasil_login['input_pass']); ?></code><br>
                            Perhitungan <code>SHA256(password_login + salt_db)</code> tidak cocok dengan <code>salted_hash</code> di database.
                        </div>
                    <?php endif; ?>
                </div>
            <?php endif; ?>
        </div>
    </div>

    <!-- HASIL PEMBENTUKAN DATA SAAT BARU REGISTRASI -->
    <?php if ($hasil_registrasi !== null): ?>
    <div class="card">
        <h2 class="card-header">
            <span>Rincian Pembentukan Hash SHA-256 Saat Registrasi User: <code><?= htmlspecialchars($hasil_registrasi['username']); ?></code></span>
            <span class="badge badge-safe">Tersimpan ke Database</span>
        </h2>
        <div class="step-box">
            <b>1. Password Biasa (Plaintext):</b><br>
            Nilai asli: <code><?= htmlspecialchars($hasil_registrasi['plaintext']); ?></code>
        </div>
        <div class="step-box">
            <b>2. Hash Saja (SHA-256 Murni Tanpa Salt):</b><br>
            Rumus: <code>SHA256("<?= htmlspecialchars($hasil_registrasi['plaintext']); ?>")</code><br>
            Hasil: <code><?= htmlspecialchars($hasil_registrasi['hash_only']); ?></code>
        </div>
        <div class="step-box">
            <b>3. Password + Hash (Kombinasi Statis):</b><br>
            Rumus: <code>SHA256("<?= htmlspecialchars($hasil_registrasi['plaintext']); ?>" + "<?= htmlspecialchars($hasil_registrasi['hash_only']); ?>")</code><br>
            Hasil: <code><?= htmlspecialchars($hasil_registrasi['pass_plus_hash']); ?></code>
        </div>
        <div class="step-box step-success">
            <b>4. Password + Salting (Metode Utama untuk Verifikasi Login):</b><br>
            Salt (<?= htmlspecialchars($hasil_registrasi['jenis_salt']); ?>): <code><?= htmlspecialchars($hasil_registrasi['salt']); ?></code><br>
            Gabungan (<code>password + salt</code>): <code><?= htmlspecialchars($hasil_registrasi['gabungan_pass_salt']); ?></code><br>
            Hasil <code>SHA256("<?= htmlspecialchars($hasil_registrasi['gabungan_pass_salt']); ?>")</code>: <code><?= htmlspecialchars($hasil_registrasi['salted_hash']); ?></code>
        </div>
    </div>
    <?php endif; ?>

    <!-- HASIL ALUR PENCOCOKAN SAAT PERCOBAAN LOGIN -->
    <?php if ($hasil_login !== null && $hasil_login['ditemukan']): ?>
    <div class="card">
        <h2 class="card-header">
            <span>Alur Verifikasi Login (SHA-256 + Salt) untuk User: <code><?= htmlspecialchars($hasil_login['input_user']); ?></code></span>
            <span class="badge <?= $hasil_login['sukses'] ? 'badge-safe' : 'badge-danger'; ?>">
                <?= $hasil_login['sukses'] ? 'VERIFIKASI COCOK' : 'VERIFIKASI DITOLAK'; ?>
            </span>
        </h2>
        <div class="step-box">
            <b>Langkah 1 &mdash; Terima Input dari Form Percobaan Login:</b><br>
            Username: <code><?= htmlspecialchars($hasil_login['input_user']); ?></code> &nbsp;|&nbsp;
            Password yang diinput: <code><?= htmlspecialchars($hasil_login['input_pass']); ?></code>
        </div>
        <div class="step-box">
            <b>Langkah 2 &mdash; Ambil Data <code>salt</code> dan <code>salted_hash</code> dari Database MySQL:</b><br>
            Query: <code>SELECT salt, salted_hash FROM users WHERE username = '<?= htmlspecialchars($hasil_login['input_user']); ?>'</code><br>
            Salt di Database: <code><?= htmlspecialchars($hasil_login['stored_salt']); ?></code><br>
            Salted Hash di Database: <code><?= htmlspecialchars($hasil_login['stored_hash']); ?></code>
        </div>
        <div class="step-box">
            <b>Langkah 3 &mdash; Gabungkan Password Input dengan Salt Database, Lalu Hitung Hash SHA-256:</b><br>
            String Gabungan (<code>password_input + salt_db</code>): <code><?= htmlspecialchars($hasil_login['string_gabungan']); ?></code><br>
            Hasil Hitung <code>SHA256("<?= htmlspecialchars($hasil_login['string_gabungan']); ?>")</code>: <code><?= htmlspecialchars($hasil_login['computed_hash']); ?></code>
        </div>
        <div class="step-box <?= $hasil_login['sukses'] ? 'step-success' : 'step-error'; ?>">
            <b>Langkah 4 &mdash; Perbandingan Hash (<code>hash_equals</code>):</b><br>
            Hash dari Input Login : <code><?= htmlspecialchars($hasil_login['computed_hash']); ?></code><br>
            Hash di Database MySQL: <code><?= htmlspecialchars($hasil_login['stored_hash']); ?></code><br>
            Kesimpulan: <b><?= $hasil_login['sukses'] ? 'KEDUA HASH IDENTIK &rarr; Password Benar, Login Diizinkan!' : 'KEDUA HASH BERBEDA &rarr; Password Salah, Login Ditolak!'; ?></b>
        </div>
    </div>
    <?php endif; ?>

    <!-- BAGIAN 3: TABEL PERBANDINGAN 4 METODE PENYIMPANAN PASSWORD -->
    <div class="card">
        <div class="card-header">
            <span>3. Perbandingan Lengkap 4 Metode Penyimpanan Password <?= $user_terpilih ? '(User: ' . htmlspecialchars($user_terpilih['username']) . ')' : ''; ?></span>
            <?php if ($user_terpilih): ?>
                <div class="card-actions">
                    <a href="<?= htmlspecialchars(strtok($_SERVER["REQUEST_URI"], '?')); ?>" class="btn-neutral-sm">Bersihkan Tampilan</a>
                </div>
            <?php endif; ?>
        </div>
        <?php if (!$user_terpilih): ?>
            <div class="empty-state">
                 Konten perbandingan masih bersih. Silakan <b>daftarkan user baru (Bagian 1)</b>, <b>lakukan percobaan login (Bagian 2)</b>, atau klik tombol <b>Detail</b> pada tabel database di bawah untuk menampilkan perbandingan ke-4 metode.
            </div>
        <?php else: ?>
            <div class="table-wrap">
                <table>
                    <thead>
                        <tr>
                            <th style="width: 20%;">Metode Penyimpanan</th>
                            <th style="width: 25%;">Rumus Proses (SHA-256)</th>
                            <th style="width: 37%;">Nilai Tersimpan di Database</th>
                            <th style="width: 18%;">Tingkat Keamanan</th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr>
                            <td><b>1. Password Biasa</b><br><small>(Plaintext)</small></td>
                            <td><code>password</code></td>
                            <td><code><?= htmlspecialchars($user_terpilih['plaintext']); ?></code></td>
                            <td><span class="badge badge-danger">Tidak Aman</span><br><small>Password langsung terbaca jika database bocor.</small></td>
                        </tr>
                        <tr>
                            <td><b>2. Hash Saja</b><br><small>(SHA-256 Murni)</small></td>
                            <td><code>SHA256(password)</code></td>
                            <td><code><?= htmlspecialchars($user_terpilih['hash_only']); ?></code></td>
                            <td><span class="badge badge-warn">Rentan Rainbow Table</span><br><small>Password yang sama selalu menghasilkan hash yang sama.</small></td>
                        </tr>
                        <tr>
                            <td><b>3. Password + Hash</b><br><small>(Kombinasi Statis)</small></td>
                            <td><code>SHA256(password + SHA256(password))</code></td>
                            <td><code><?= htmlspecialchars($user_terpilih['pass_plus_hash']); ?></code></td>
                            <td><span class="badge badge-warn">Masih Deterministik</span><br><small>Tanpa salt acak, input yang sama tetap menghasilkan hash identik.</small></td>
                        </tr>
                        <tr class="highlight-row">
                            <td><b>4. Password + Salting</b><br><small>(Digunakan saat Login)</small></td>
                            <td><code>SHA256(password + salt)</code></td>
                            <td>
                                <b>Salt:</b> <code><?= htmlspecialchars($user_terpilih['salt']); ?></code><br>
                                <b>Hash:</b> <code><?= htmlspecialchars($user_terpilih['salted_hash']); ?></code>
                            </td>
                            <td><span class="badge badge-safe">Aman (Rekomendasi)</span><br><small>Salt unik menghasilkan hash berbeda meskipun password antar-user sama.</small></td>
                        </tr>
                    </tbody>
                </table>
            </div>
        <?php endif; ?>
    </div>

    <!-- BAGIAN 4: DAFTAR SELURUH ISI TABEL DATABASE MYSQL -->
    <div class="card mb-0">
        <div class="card-header">
            <span>4. Data Tabel <code>users</code> di Database MySQL</span>
            <?php if (!empty($daftar_users)): ?>
                <form method="POST" action="" class="inline-form">
                    <input type="hidden" name="aksi" value="reset_db">
                    <button type="submit" class="btn-red-sm">Kosongkan / Reset Tabel Database</button>
                </form>
            <?php endif; ?>
        </div>
        <p class="desc">
            Data di bawah ini diambil secara langsung (<i>real-time</i>) dari tabel <code>users</code> pada database MySQL (<code><?= htmlspecialchars($db_name); ?></code>). Klik tombol <b>Detail</b> pada salah satu baris untuk melihat perbandingan utuh pada Bagian 3, atau klik <b>Hapus</b> untuk menghapus data user dari database.
        </p>

        <?php if (empty($daftar_users)): ?>
            <div class="empty-state">
                Tabel <code>users</code> di database MySQL saat ini masih kosong (0 data). Silakan tambahkan user baru melalui form Registrasi pada Bagian 1.
            </div>
        <?php else: ?>
            <div class="table-wrap">
                <table>
                    <thead>
                        <tr>
                            <th>ID</th>
                            <th>Username</th>
                            <th>1. Plaintext</th>
                            <th>2. Hash Saja</th>
                            <th>3. Password + Hash</th>
                            <th>4a. Salt</th>
                            <th>4b. Salted Hash</th>
                            <th>Aksi</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($daftar_users as $u): ?>
                            <tr class="<?= ($user_terpilih && $user_terpilih['id'] == $u['id']) ? 'highlight-row' : ''; ?>">
                                <td><?= (int)$u['id']; ?></td>
                                <td><b><?= htmlspecialchars($u['username']); ?></b></td>
                                <td><code><?= htmlspecialchars($u['plaintext']); ?></code></td>
                                <td><code><?= htmlspecialchars(substr($u['hash_only'], 0, 14)) . '...'; ?></code></td>
                                <td><code><?= htmlspecialchars(substr($u['pass_plus_hash'], 0, 14)) . '...'; ?></code></td>
                                <td><code><?= htmlspecialchars($u['salt']); ?></code></td>
                                <td><code><?= htmlspecialchars(substr($u['salted_hash'], 0, 14)) . '...'; ?></code></td>
                                <td class="nowrap">
                                    <form method="POST" action="" class="inline-form">
                                        <input type="hidden" name="aksi" value="lihat_detail">
                                        <input type="hidden" name="detail_username" value="<?= htmlspecialchars($u['username']); ?>">
                                        <button type="submit" class="btn-link-sm">Detail</button>
                                    </form>
                                    <form method="POST" action="" class="inline-form">
                                        <input type="hidden" name="aksi" value="hapus_user">
                                        <input type="hidden" name="id_user" value="<?= (int)$u['id']; ?>">
                                        <button type="submit" class="btn-red-sm">Hapus</button>
                                    </form>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
        <?php endif; ?>
    </div>
</div>

<script>
function togglePassword(inputId, btn) {
    var input = document.getElementById(inputId);
    var label = btn.querySelector('span');
    if (!input) return;

    if (input.type === 'password') {
        input.type = 'text';
        if (label) label.textContent = 'Tutup';
    } else {
        input.type = 'password';
        if (label) label.textContent = 'Lihat';
    }
}
</script>

</body>
</html>