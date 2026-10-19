<?php
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

    // 4. Buat tabel users jika belum ada (TANPA data statis/dummy otomatis)
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

$pesan_aksi = "";
$tipe_pesan = "ok";
$hasil_registrasi = null;
$hasil_login = null;
$user_terpilih = null;

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

        // Simpan ke tabel users di MySQL
        $stmt = $koneksi_db->prepare("
            INSERT INTO `users` (`username`, `plaintext`, `hash_only`, `pass_plus_hash`, `salt`, `salted_hash`)
            VALUES (:username, :plaintext, :hash_only, :pass_plus_hash, :salt, :salted_hash)
            ON DUPLICATE KEY UPDATE
                `plaintext`      = VALUES(`plaintext`),
                `hash_only`      = VALUES(`hash_only`),
                `pass_plus_hash` = VALUES(`pass_plus_hash`),
                `salt`           = VALUES(`salt`),
                `salted_hash`    = VALUES(`salted_hash`)
        ");

        $stmt->execute([
            ':username'       => $username,
            ':plaintext'      => $plaintext,
            ':hash_only'      => $hash_only,
            ':pass_plus_hash' => $pass_plus_hash,
            ':salt'           => $salt,
            ':salted_hash'    => $salted_hash
        ]);

        $pesan_aksi = "User <b>" . htmlspecialchars($username) . "</b> berhasil diproses dan disimpan ke database MySQL!";
        $tipe_pesan = "ok";

        // Simpan rincian pembentukan untuk ditampilkan ke layar saat demo
        $hasil_registrasi = [
            'username'           => $username,
            'plaintext'          => $plaintext,
            'hash_only'          => $hash_only,
            'gabungan_pass_hash' => $gabungan_pass_hash,
            'pass_plus_hash'     => $pass_plus_hash,
            'salt'               => $salt,
            'jenis_salt'         => ($custom_salt !== '') ? 'Input Manual (Custom)' : 'Acak Otomatis (random_bytes)',
            'gabungan_pass_salt' => $gabungan_pass_salt,
            'salted_hash'        => $salted_hash
        ];

        // Jadikan user yang baru disimpan sebagai user aktif di tabel perbandingan detail
        $stmt_get = $koneksi_db->prepare("SELECT * FROM `users` WHERE `username` = :u LIMIT 1");
        $stmt_get->execute([':u' => $username]);
        $user_terpilih = $stmt_get->fetch();
    }
}

// =========================================================
// PROSES 2: VERIFIKASI LOGIN DARI DATABASE (METODE SALTING)
// =========================================================
if ($_SERVER["REQUEST_METHOD"] === "POST" && ($_POST['aksi'] ?? '') === 'login' && $koneksi_db) {
    $input_user = trim($_POST['login_username'] ?? '');
    $input_pass = $_POST['login_password'] ?? '';

    // Cari username di database MySQL
    $stmt = $koneksi_db->prepare("SELECT * FROM `users` WHERE `username` = :username LIMIT 1");
    $stmt->execute([':username' => $input_user]);
    $row_db = $stmt->fetch();

    if ($row_db) {
        // Ambil salt & salted_hash milik user tersebut dari database
        $stored_salt = $row_db['salt'];
        $stored_hash = $row_db['salted_hash'];

        // Gabungkan password yang baru diinput saat login dengan salt dari database
        $string_gabungan = $input_pass . $stored_salt;

        // Hitung ulang hash SHA-256
        $computed_hash = hash('sha256', $string_gabungan);

        // Cek apakah hasil hash baru sama persis dengan salted_hash di database
        $cocok = hash_equals($stored_hash, $computed_hash);

        $hasil_login = [
            'ditemukan'       => true,
            'sukses'          => $cocok,
            'input_user'      => $input_user,
            'input_pass'      => $input_pass,
            'stored_salt'     => $stored_salt,
            'string_gabungan' => $string_gabungan,
            'computed_hash'   => $computed_hash,
            'stored_hash'     => $stored_hash
        ];

        $user_terpilih = $row_db;
    } else {
        $hasil_login = [
            'ditemukan'  => false,
            'sukses'     => false,
            'input_user' => $input_user,
            'input_pass' => $input_pass
        ];
    }
}

// =========================================================
// PROSES 3: HAPUS 1 USER ATAU RESET SELURUH TABEL DATABASE
// =========================================================
if ($_SERVER["REQUEST_METHOD"] === "POST" && ($_POST['aksi'] ?? '') === 'hapus_user' && $koneksi_db) {
    $id_hapus = (int)($_POST['id_user'] ?? 0);
    $stmt = $koneksi_db->prepare("DELETE FROM `users` WHERE `id` = :id");
    $stmt->execute([':id' => $id_hapus]);
    $pesan_aksi = "Data user berhasil dihapus dari database.";
    $tipe_pesan = "warn";
}

if ($_SERVER["REQUEST_METHOD"] === "POST" && ($_POST['aksi'] ?? '') === 'reset_db' && $koneksi_db) {
    $koneksi_db->exec("TRUNCATE TABLE `users`");
    $pesan_aksi = "Tabel <code>users</code> berhasil dikosongkan! Silakan mulai demo dari nol.";
    $tipe_pesan = "warn";
}

// Ambil seluruh daftar user yang ada di database saat ini
$daftar_users = [];
if ($koneksi_db) {
    $daftar_users = $koneksi_db->query("SELECT * FROM `users` ORDER BY `id` DESC")->fetchAll();

    // Jika ada parameter GET ?lihat=username, tampilkan perbandingan detail untuk user tersebut
    if (!$user_terpilih && isset($_GET['lihat'])) {
        $stmt_lihat = $koneksi_db->prepare("SELECT * FROM `users` WHERE `username` = :u LIMIT 1");
        $stmt_lihat->execute([':u' => $_GET['lihat']]);
        $user_terpilih = $stmt_lihat->fetch();
    }

    // Jika belum ada yang dipilih tapi tabel punya isi, pilih user terbaru
    if (!$user_terpilih && !empty($daftar_users)) {
        $user_terpilih = $daftar_users[0];
    }
}
?>
<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Demo Dinamis Keamanan Siber: Registrasi, Login, Hashing &amp; Salting</title>
    <style>
        /* CSS Murni bergaya Tailwind (0% JavaScript) */
        * { box-sizing: border-box; }
        body {
            font-family: system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
            background-color: #f1f5f9;
            color: #0f172a;
            margin: 0;
            padding: 24px 16px;
            line-height: 1.5;
        }
        .container {
            max-width: 1100px;
            margin: 0 auto;
        }
        .banner {
            background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
            color: #ffffff;
            padding: 22px 26px;
            border-radius: 12px;
            margin-bottom: 20px;
            box-shadow: 0 4px 12px rgba(15, 23, 42, 0.12);
            display: flex;
            flex-wrap: wrap;
            justify-content: space-between;
            align-items: center;
            gap: 16px;
        }
        .banner-tag {
            display: inline-block;
            background: #2563eb;
            color: #ffffff;
            font-size: 0.74rem;
            font-weight: 700;
            padding: 4px 10px;
            border-radius: 999px;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            margin-bottom: 8px;
        }
        .banner h1 { margin: 0 0 6px 0; font-size: 1.4rem; }
        .banner p { margin: 0; color: #cbd5e1; font-size: 0.9rem; }
        .db-badge {
            font-size: 0.84rem;
            padding: 8px 14px;
            border-radius: 8px;
            background: rgba(255, 255, 255, 0.1);
            color: #f8fafc;
        }
        .grid-2 {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(340px, 1fr));
            gap: 20px;
            margin-bottom: 22px;
        }
        .card {
            background: #ffffff;
            border: 1px solid #e2e8f0;
            border-radius: 12px;
            padding: 20px 22px;
            margin-bottom: 22px;
            box-shadow: 0 1px 3px rgba(15, 23, 42, 0.06);
        }
        .card-header {
            margin-top: 0;
            margin-bottom: 12px;
            padding-bottom: 10px;
            border-bottom: 1px solid #f1f5f9;
            font-size: 1.05rem;
            font-weight: 700;
            color: #0f172a;
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 8px;
        }
        .desc {
            font-size: 0.85rem;
            color: #475569;
            margin-top: 0;
            margin-bottom: 14px;
        }
        label {
            display: block;
            font-size: 0.83rem;
            font-weight: 600;
            color: #334155;
            margin-bottom: 4px;
            margin-top: 10px;
        }
        .hint {
            font-weight: 400;
            color: #64748b;
            font-size: 0.78rem;
        }
        input[type="text"],
        input[type="password"] {
            width: 100%;
            padding: 10px 12px;
            border: 1px solid #cbd5e1;
            border-radius: 8px;
            font-size: 0.92rem;
            background-color: #ffffff;
            color: #0f172a;
        }
        input:focus {
            outline: 2px solid #2563eb;
            border-color: #2563eb;
        }
        .btn {
            display: inline-block;
            width: 100%;
            padding: 11px 16px;
            margin-top: 16px;
            border: none;
            border-radius: 8px;
            font-size: 0.92rem;
            font-weight: 600;
            cursor: pointer;
            text-align: center;
            text-decoration: none;
        }
        .btn-blue { background-color: #2563eb; color: #ffffff; }
        .btn-blue:hover { background-color: #1d4ed8; }
        .btn-emerald { background-color: #059669; color: #ffffff; }
        .btn-emerald:hover { background-color: #047857; }
        .btn-red-sm {
            background-color: #fee2e2;
            color: #991b1b;
            border: 1px solid #fecaca;
            padding: 5px 10px;
            border-radius: 6px;
            font-size: 0.78rem;
            font-weight: 600;
            cursor: pointer;
        }
        .btn-red-sm:hover { background-color: #fecaca; }
        .btn-link-sm {
            background-color: #eff6ff;
            color: #1d4ed8;
            border: 1px solid #bfdbfe;
            padding: 5px 10px;
            border-radius: 6px;
            font-size: 0.78rem;
            font-weight: 600;
            text-decoration: none;
            display: inline-block;
        }
        .btn-link-sm:hover { background-color: #dbeafe; }
        .alert {
            margin-bottom: 20px;
            padding: 12px 16px;
            border-radius: 8px;
            font-size: 0.88rem;
        }
        .alert-ok { background-color: #ecfdf5; color: #065f46; border: 1px solid #a7f3d0; }
        .alert-err { background-color: #fef2f2; color: #991b1b; border: 1px solid #fecaca; }
        .alert-warn { background-color: #fffbeb; color: #92400e; border: 1px solid #fde68a; }
        .table-wrap { overflow-x: auto; }
        table {
            width: 100%;
            border-collapse: collapse;
            font-size: 0.85rem;
        }
        th, td {
            padding: 10px 12px;
            text-align: left;
            border-bottom: 1px solid #e2e8f0;
            vertical-align: top;
        }
        th {
            background-color: #f8fafc;
            color: #334155;
            font-weight: 700;
            font-size: 0.78rem;
            text-transform: uppercase;
            letter-spacing: 0.03em;
        }
        tr.highlight-row { background-color: #f0fdf4; }
        code {
            font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
            font-size: 0.8rem;
            background-color: #f1f5f9;
            color: #0f172a;
            padding: 3px 6px;
            border-radius: 4px;
            word-break: break-all;
            display: inline-block;
        }
        .badge {
            display: inline-block;
            padding: 2px 8px;
            border-radius: 999px;
            font-size: 0.72rem;
            font-weight: 700;
        }
        .badge-danger { background-color: #fee2e2; color: #991b1b; }
        .badge-warn { background-color: #fef3c7; color: #92400e; }
        .badge-safe { background-color: #dcfce7; color: #166534; }
        .step-box {
            background-color: #f8fafc;
            border-left: 4px solid #2563eb;
            padding: 11px 14px;
            margin-top: 10px;
            border-radius: 0 8px 8px 0;
            font-size: 0.86rem;
        }
        .empty-state {
            text-align: center;
            padding: 28px 16px;
            color: #64748b;
            background: #f8fafc;
            border: 1px dashed #cbd5e1;
            border-radius: 8px;
            font-size: 0.9rem;
        }
    </style>
</head>
<body>

<div class="container">
    <!-- Banner Header -->
    <div class="banner">
        <div>
            <span class="banner-tag">Demo Dinamis &bull; PHP + MySQL &bull; 0% JS</span>
            <h1>Sistem Registrasi, Login &amp; Perbandingan Hash + Salting</h1>
            <p>Input akun baru secara langsung, simpan ke MySQL, bandingkan ke-4 metode, dan uji alur pencocokan login</p>
        </div>
        <div class="db-badge">
            <?php if ($koneksi_db): ?>
                <span style="color: #4ade80;">&#9679;</span> MySQL Aktif: <b><?= htmlspecialchars($db_name); ?>.users</b> (<?= count($daftar_users); ?> akun)
            <?php else: ?>
                <span style="color: #f87171;">&#9679;</span> MySQL Terputus
            <?php endif; ?>
        </div>
    </div>

    <!-- Peringatan jika MySQL mati -->
    <?php if (!$koneksi_db): ?>
        <div class="alert alert-err">
            <b>Koneksi ke MySQL Gagal!</b> (<code><?= htmlspecialchars($error_db); ?></code>)<br>
            Pastikan modul <b>MySQL</b> di XAMPP atau Laragon sudah dinyalakan (Start), lalu refresh halaman ini.
        </div>
    <?php endif; ?>

    <!-- Notifikasi Aksi -->
    <?php if ($pesan_aksi !== ""): ?>
        <div class="alert <?= $tipe_pesan === 'ok' ? 'alert-ok' : 'alert-warn'; ?>">
            <?= $pesan_aksi; ?>
        </div>
    <?php endif; ?>

    <!-- DUA PANEL UTAMA: 1. REGISTRASI USER BARU & 2. LOGIN USER -->
    <div class="grid-2">
        <!-- Panel 1: Form Input / Registrasi User ke Database -->
        <div class="card" style="margin-bottom: 0;">
            <h2 class="card-header">
                <span>1. Registrasi User Baru ke Database</span>
                <span class="badge badge-safe">Input Dinamis</span>
            </h2>
            <p class="desc">
                Masukkan username dan password baru. Sistem akan memproses password tersebut ke dalam 4 metode (Plaintext, Hash, Password+Hash, dan Password+Salt) lalu menyimpannya ke tabel MySQL <code>users</code>.
            </p>
            <form method="POST" action="">
                <input type="hidden" name="aksi" value="registrasi">

                <label for="reg_username">Username Baru</label>
                <input type="text" id="reg_username" name="reg_username" placeholder="Contoh: budi, andi, dosen..." required>

                <label for="reg_password">Password</label>
                <input type="text" id="reg_password" name="reg_password" placeholder="Ketik password yang ingin diuji..." required>

                <label for="reg_custom_salt">
                    Salt <span class="hint">(Kosongkan agar di-generate acak otomatis oleh PHP, atau isi manual untuk tes)</span>
                </label>
                <input type="text" id="reg_custom_salt" name="reg_custom_salt" placeholder="Otomatis: random 16 karakter hex">

                <button type="submit" class="btn btn-blue" <?= !$koneksi_db ? 'disabled' : ''; ?>>
                    Proses &amp; Simpan User ke Database MySQL
                </button>
            </form>
        </div>

        <!-- Panel 2: Form Login (Mencocokkan Hash + Salt dari Database) -->
        <div class="card" style="margin-bottom: 0;">
            <h2 class="card-header">
                <span>2. Halaman Login (Verifikasi Salting)</span>
                <span class="badge badge-warn">Cek dari Database</span>
            </h2>
            <p class="desc">
                Gunakan akun yang sudah kamu daftarkan di sebelah kiri. Sistem akan mengambil <code>salt</code> milik user tersebut dari MySQL, menggabungkannya dengan password login, lalu mencocokkan hasil hash-nya.
            </p>
            <form method="POST" action="">
                <input type="hidden" name="aksi" value="login">

                <label for="login_username">Username</label>
                <input type="text" id="login_username" name="login_username" value="<?= htmlspecialchars($user_terpilih['username'] ?? ''); ?>" placeholder="Ketik username yang sudah didaftarkan..." required>

                <label for="login_password">Password Login</label>
                <input type="password" id="login_password" name="login_password" placeholder="Ketik password untuk dicocokkan..." required>

                <button type="submit" class="btn btn-emerald" <?= !$koneksi_db ? 'disabled' : ''; ?>>
                    Login &amp; Tampilkan Alur Pencocokan Hash
                </button>
            </form>

            <?php if ($hasil_login !== null): ?>
                <div style="margin-top: 14px;">
                    <?php if (!$hasil_login['ditemukan']): ?>
                        <div class="alert alert-err" style="margin-bottom: 0;">
                            <b>USER TIDAK DITEMUKAN!</b> Username <code><?= htmlspecialchars($hasil_login['input_user']); ?></code> belum ada di database. Silakan daftarkan dulu di Panel 1.
                        </div>
                    <?php elseif ($hasil_login['sukses']): ?>
                        <div class="alert alert-ok" style="margin-bottom: 0;">
                            <b>LOGIN BERHASIL!</b> Hasil perhitungan <code>SHA256(input_password + salt_db)</code> cocok 100% dengan <code>salted_hash</code> di database.
                        </div>
                    <?php else: ?>
                        <div class="alert alert-err" style="margin-bottom: 0;">
                            <b>LOGIN GAGAL / PASSWORD SALAH!</b> Hasil perhitungan <code>SHA256(input_password + salt_db)</code> berbeda dengan hash di database.
                        </div>
                    <?php endif; ?>
                </div>
            <?php endif; ?>
        </div>
    </div>

    <!-- HASIL LIVE SAAT BARU REGISTRASI: BAGAIMANA PASSWORD DIUBAH KE 4 METODE -->
    <?php if ($hasil_registrasi !== null): ?>
    <div class="card">
        <h2 class="card-header">
            <span>Rincian Pembentukan Data Saat Menyimpan User: <code><?= htmlspecialchars($hasil_registrasi['username']); ?></code></span>
            <span class="badge badge-safe">Baru Disimpan ke MySQL</span>
        </h2>
        <div class="step-box">
            <b>1. Password Biasa (Plaintext):</b><br>
            Input asli: <code><?= htmlspecialchars($hasil_registrasi['plaintext']); ?></code>
        </div>
        <div class="step-box">
            <b>2. Hash Saja (Tanpa Salt):</b><br>
            Rumus: <code>SHA256("<?= htmlspecialchars($hasil_registrasi['plaintext']); ?>")</code><br>
            Hasil: <code><?= htmlspecialchars($hasil_registrasi['hash_only']); ?></code>
        </div>
        <div class="step-box">
            <b>3. Password + Hash:</b><br>
            Rumus: <code>SHA256("<?= htmlspecialchars($hasil_registrasi['plaintext']); ?>" + "<?= htmlspecialchars($hasil_registrasi['hash_only']); ?>")</code><br>
            Hasil: <code><?= htmlspecialchars($hasil_registrasi['pass_plus_hash']); ?></code>
        </div>
        <div class="step-box" style="border-left-color: #059669;">
            <b>4. Password + Salting (Metode yang Dipakai untuk Login):</b><br>
            Salt (<?= htmlspecialchars($hasil_registrasi['jenis_salt']); ?>): <code><?= htmlspecialchars($hasil_registrasi['salt']); ?></code><br>
            Digabung (<code>password + salt</code>): <code><?= htmlspecialchars($hasil_registrasi['gabungan_pass_salt']); ?></code><br>
            Hasil <code>SHA256("<?= htmlspecialchars($hasil_registrasi['gabungan_pass_salt']); ?>")</code>: <code><?= htmlspecialchars($hasil_registrasi['salted_hash']); ?></code>
        </div>
    </div>
    <?php endif; ?>

    <!-- HASIL LIVE SAAT TOMBOL LOGIN DITEKAN: ALUR PENCOCOKAN HASH + SALT -->
    <?php if ($hasil_login !== null && $hasil_login['ditemukan']): ?>
    <div class="card">
        <h2 class="card-header">
            <span>Alur Pencocokan (Verifikasi) Login untuk User: <code><?= htmlspecialchars($hasil_login['input_user']); ?></code></span>
            <span class="badge <?= $hasil_login['sukses'] ? 'badge-safe' : 'badge-danger'; ?>">
                <?= $hasil_login['sukses'] ? 'VERIFIKASI COCOK' : 'VERIFIKASI DITOLAK'; ?>
            </span>
        </h2>
        <div class="step-box">
            <b>Langkah 1 &mdash; Terima Input dari Form Login:</b><br>
            Username: <code><?= htmlspecialchars($hasil_login['input_user']); ?></code> &nbsp;|&nbsp;
            Password yang diketik: <code><?= htmlspecialchars($hasil_login['input_pass']); ?></code>
        </div>
        <div class="step-box">
            <b>Langkah 2 &mdash; Ambil <code>salt</code> dan <code>salted_hash</code> Milik User dari Tabel MySQL:</b><br>
            Query: <code>SELECT salt, salted_hash FROM users WHERE username = '<?= htmlspecialchars($hasil_login['input_user']); ?>'</code><br>
            Salt dari DB: <code><?= htmlspecialchars($hasil_login['stored_salt']); ?></code><br>
            Salted Hash dari DB: <code><?= htmlspecialchars($hasil_login['stored_hash']); ?></code>
        </div>
        <div class="step-box">
            <b>Langkah 3 &mdash; Gabungkan Password Input dengan Salt dari DB, Lalu Hitung Ulang Hash:</b><br>
            String Gabungan (<code>input_password + salt_db</code>): <code><?= htmlspecialchars($hasil_login['string_gabungan']); ?></code><br>
            Hasil <code>SHA256("<?= htmlspecialchars($hasil_login['string_gabungan']); ?>")</code>: <code><?= htmlspecialchars($hasil_login['computed_hash']); ?></code>
        </div>
        <div class="step-box" style="border-left-color: <?= $hasil_login['sukses'] ? '#059669' : '#dc2626'; ?>;">
            <b>Langkah 4 &mdash; Pencocokan Akhir (<code>hash_equals</code>):</b><br>
            Hash Hasil Input Login : <code><?= htmlspecialchars($hasil_login['computed_hash']); ?></code><br>
            Hash Tersimpan di DB &nbsp;&nbsp;: <code><?= htmlspecialchars($hasil_login['stored_hash']); ?></code><br>
            Kesimpulan: <b><?= $hasil_login['sukses'] ? 'KEDUA HASH IDENTIK &rarr; Password Benar, Akses Login Diberikan!' : 'KEDUA HASH BERBEDA &rarr; Password Salah, Akses Ditolak!'; ?></b>
        </div>
    </div>
    <?php endif; ?>

    <!-- PANEL 3: TABEL PERBANDINGAN UTUH 4 METODE UNTUK USER TERPILIH -->
    <div class="card">
        <h2 class="card-header">
            <span>3. Perbandingan Lengkap 4 Metode <?= $user_terpilih ? '(User: ' . htmlspecialchars($user_terpilih['username']) . ')' : ''; ?></span>
        </h2>
        <?php if (!$user_terpilih): ?>
            <div class="empty-state">
                Belum ada data user di database. Silakan input user &amp; password baru pada <b>Panel 1 (Registrasi User Baru)</b> di atas untuk melihat tabel perbandingan.
            </div>
        <?php else: ?>
            <div class="table-wrap">
                <table>
                    <thead>
                        <tr>
                            <th style="width: 20%;">Metode Penyimpanan</th>
                            <th style="width: 25%;">Rumus Proses</th>
                            <th style="width: 37%;">Nilai Lengkap di Database MySQL</th>
                            <th style="width: 18%;">Keterangan</th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr>
                            <td><b>1. Password Biasa</b><br><small>(Plaintext)</small></td>
                            <td><code>password</code></td>
                            <td><code><?= htmlspecialchars($user_terpilih['plaintext']); ?></code></td>
                            <td><span class="badge badge-danger">Tidak Aman</span><br><small>Langsung terbaca jika DB bocor.</small></td>
                        </tr>
                        <tr>
                            <td><b>2. Hash Saja</b><br><small>(Tanpa Salt)</small></td>
                            <td><code>SHA256(password)</code></td>
                            <td><code><?= htmlspecialchars($user_terpilih['hash_only']); ?></code></td>
                            <td><span class="badge badge-warn">Rentan Rainbow Table</span><br><small>Password sama = Hash pasti sama.</small></td>
                        </tr>
                        <tr>
                            <td><b>3. Password + Hash</b><br><small>(Kombinasi Statis)</small></td>
                            <td><code>SHA256(password + SHA256(password))</code></td>
                            <td><code><?= htmlspecialchars($user_terpilih['pass_plus_hash']); ?></code></td>
                            <td><span class="badge badge-warn">Masih Deterministik</span><br><small>Password sama tetap menghasilkan hash akhir yang sama.</small></td>
                        </tr>
                        <tr class="highlight-row">
                            <td><b>4. Password + Salting</b><br><small>(Dipakai untuk Login)</small></td>
                            <td><code>SHA256(password + salt)</code></td>
                            <td>
                                <b>Salt:</b> <code><?= htmlspecialchars($user_terpilih['salt']); ?></code><br>
                                <b>Hash:</b> <code><?= htmlspecialchars($user_terpilih['salted_hash']); ?></code>
                            </td>
                            <td><span class="badge badge-safe">Aman (Dipakai Login)</span><br><small>Salt unik membuat hash selalu berbeda tiap user.</small></td>
                        </tr>
                    </tbody>
                </table>
            </div>
        <?php endif; ?>
    </div>

    <!-- PANEL 4: DAFTAR SELURUH ISI TABEL DATABASE MYSQL -->
    <div class="card" style="margin-bottom: 0;">
        <div class="card-header">
            <span>4. Isi Tabel <code>users</code> di Database MySQL Saat Ini</span>
            <?php if (!empty($daftar_users)): ?>
                <form method="POST" action="" style="margin: 0;">
                    <input type="hidden" name="aksi" value="reset_db">
                    <button type="submit" class="btn-red-sm">Kosongkan / Reset Tabel Database</button>
                </form>
            <?php endif; ?>
        </div>
        <p class="desc">
            <b>Tips Demo ke Dosen:</b> Coba daftarkan 2 user berbeda (misal <code>budi</code> dan <code>andi</code>) dengan password yang <b>sama persis</b>. Lalu tunjukkan pada tabel di bawah bahwa kolom <b>Hash Saja</b> dan <b>Password + Hash</b> keduanya bernilai sama, sedangkan kolom <b>Salt</b> dan <b>Salted Hash</b> keduanya berbeda!
        </p>

        <?php if (empty($daftar_users)): ?>
            <div class="empty-state">
                Tabel <code>users</code> di MySQL saat ini masih kosong (0 baris). Silakan tambahkan user melalui form Registrasi di atas.
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
                                <td><?= $u['id']; ?></td>
                                <td><b><?= htmlspecialchars($u['username']); ?></b></td>
                                <td><code><?= htmlspecialchars($u['plaintext']); ?></code></td>
                                <td><code><?= htmlspecialchars(substr($u['hash_only'], 0, 14)) . '...'; ?></code></td>
                                <td><code><?= htmlspecialchars(substr($u['pass_plus_hash'], 0, 14)) . '...'; ?></code></td>
                                <td><code><?= htmlspecialchars($u['salt']); ?></code></td>
                                <td><code><?= htmlspecialchars(substr($u['salted_hash'], 0, 14)) . '...'; ?></code></td>
                                <td style="white-space: nowrap;">
                                    <a href="?lihat=<?= urlencode($u['username']); ?>" class="btn-link-sm">Detail</a>
                                    <form method="POST" action="" style="display: inline; margin: 0;">
                                        <input type="hidden" name="aksi" value="hapus_user">
                                        <input type="hidden" name="id_user" value="<?= $u['id']; ?>">
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

</body>
</html>