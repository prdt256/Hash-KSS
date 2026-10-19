<?php
session_start();

// Inisialisasi data akun default di session (tanpa perlu setup database MySQL)
if (!isset($_SESSION['user_db'])) {
    $default_pass = "rahasia123";
    $default_salt = bin2hex(random_bytes(8)); // Salt acak 16 karakter hex

    $hash_murni      = hash('sha256', $default_pass);
    $pass_plus_hash  = hash('sha256', $default_pass . $hash_murni);
    $pass_plus_salt  = hash('sha256', $default_pass . $default_salt);

    $_SESSION['user_db'] = [
        'username'       => 'mahasiswa',
        'plaintext'      => $default_pass,
        'hash_only'      => $hash_murni,
        'pass_plus_hash' => $pass_plus_hash,
        'salt'           => $default_salt,
        'salted_hash'    => $pass_plus_salt
    ];
}

$pesan_registrasi = "";
$hasil_login = null;

// 1. PROSES UBAH PASSWORD / REGISTRASI SIMULASI
if ($_SERVER["REQUEST_METHOD"] === "POST" && ($_POST['aksi'] ?? '') === 'simpan_akun') {
    $username = htmlspecialchars(trim($_POST['username'] ?? 'mahasiswa'));
    $password = $_POST['password_baru'] ?? '';

    if ($password !== '') {
        // Metode 1: Password Biasa (Plaintext)
        $plaintext = $password;

        // Metode 2: Hash Saja (SHA-256 murni tanpa salt)
        $hash_only = hash('sha256', $password);

        // Metode 3: Password + Hash (Password digabung dengan hasil hash-nya lalu di-hash)
        $pass_plus_hash = hash('sha256', $password . $hash_only);

        // Metode 4: Password + Salting (Password digabung dengan Random Salt unik lalu di-hash)
        $salt = bin2hex(random_bytes(8));
        $salted_hash = hash('sha256', $password . $salt);

        $_SESSION['user_db'] = [
            'username'       => $username,
            'plaintext'      => $plaintext,
            'hash_only'      => $hash_only,
            'pass_plus_hash' => $pass_plus_hash,
            'salt'           => $salt,
            'salted_hash'    => $salted_hash
        ];

        $pesan_registrasi = "Data akun <b>$username</b> berhasil diperbarui! Perhatikan tabel perbandingan di bawah.";
    }
}

// 2. PROSES LOGIN (MENGGUNAKAN METODE PASSWORD + SALTING)
if ($_SERVER["REQUEST_METHOD"] === "POST" && ($_POST['aksi'] ?? '') === 'login') {
    $input_user = htmlspecialchars(trim($_POST['login_username'] ?? ''));
    $input_pass = $_POST['login_password'] ?? '';
    $db = $_SESSION['user_db'];

    // Langkah A: Ambil salt dan salted_hash milik user dari penyimpanan
    $stored_salt = $db['salt'];
    $stored_hash = $db['salted_hash'];

    // Langkah B: Gabungkan password yang diinput saat login dengan salt dari database
    $string_gabungan = $input_pass . $stored_salt;

    // Langkah C: Hitung hash SHA-256 dari string gabungan tersebut
    $hash_input_login = hash('sha256', $string_gabungan);

    // Langkah D: Bandingkan hash baru dengan hash yang tersimpan di database
    $user_cocok = ($input_user === $db['username']);
    $hash_cocok = hash_equals($stored_hash, $hash_input_login);
    $login_berhasil = ($user_cocok && $hash_cocok);

    $hasil_login = [
        'sukses'           => $login_berhasil,
        'user_cocok'       => $user_cocok,
        'hash_cocok'       => $hash_cocok,
        'input_user'       => $input_user,
        'input_pass'       => $input_pass,
        'stored_salt'      => $stored_salt,
        'string_gabungan'  => $string_gabungan,
        'hash_input_login' => $hash_input_login,
        'stored_hash'      => $stored_hash
    ];
}

$akun = $_SESSION['user_db'];
?>
<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Tugas Keamanan Siber - Login, Hash &amp; Salting (PHP + HTML/CSS Murni)</title>
    <style>
        /* Styling CSS Murni bergaya Tailwind (0% JavaScript) */
        * { box-sizing: border-box; }
        body {
            font-family: system-ui, -apple-system, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
            background-color: #f8fafc;
            color: #0f172a;
            margin: 0;
            padding: 28px 16px;
            line-height: 1.5;
        }
        .container {
            max-width: 1024px;
            margin: 0 auto;
        }
        .banner {
            background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
            color: #f8fafc;
            padding: 24px 28px;
            border-radius: 12px;
            margin-bottom: 24px;
            box-shadow: 0 4px 12px rgba(15, 23, 42, 0.12);
        }
        .banner-tag {
            display: inline-block;
            background: #3b82f6;
            color: #ffffff;
            font-size: 0.75rem;
            font-weight: 700;
            padding: 4px 10px;
            border-radius: 999px;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            margin-bottom: 8px;
        }
        .banner h1 {
            margin: 0 0 6px 0;
            font-size: 1.45rem;
            font-weight: 700;
        }
        .banner p {
            margin: 0;
            color: #cbd5e1;
            font-size: 0.92rem;
        }
        .grid-2 {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(340px, 1fr));
            gap: 20px;
            margin-bottom: 24px;
        }
        .card {
            background: #ffffff;
            border: 1px solid #e2e8f0;
            border-radius: 12px;
            padding: 22px;
            margin-bottom: 24px;
            box-shadow: 0 1px 3px rgba(15, 23, 42, 0.05);
        }
        .card-header {
            margin-top: 0;
            margin-bottom: 14px;
            padding-bottom: 10px;
            border-bottom: 1px solid #f1f5f9;
            font-size: 1.08rem;
            font-weight: 700;
            color: #0f172a;
        }
        .desc {
            font-size: 0.86rem;
            color: #475569;
            margin-top: 0;
            margin-bottom: 14px;
        }
        label {
            display: block;
            font-size: 0.84rem;
            font-weight: 600;
            color: #334155;
            margin-bottom: 5px;
            margin-top: 12px;
        }
        input[type="text"],
        input[type="password"] {
            width: 100%;
            padding: 10px 12px;
            border: 1px solid #cbd5e1;
            border-radius: 8px;
            font-size: 0.94rem;
            color: #0f172a;
            background-color: #ffffff;
        }
        input[type="text"]:focus,
        input[type="password"]:focus {
            outline: 2px solid #3b82f6;
            border-color: #3b82f6;
        }
        .btn {
            display: block;
            width: 100%;
            padding: 11px 16px;
            margin-top: 16px;
            border: none;
            border-radius: 8px;
            font-size: 0.94rem;
            font-weight: 600;
            cursor: pointer;
            text-align: center;
        }
        .btn-blue { background-color: #2563eb; color: #ffffff; }
        .btn-blue:hover { background-color: #1d4ed8; }
        .btn-emerald { background-color: #059669; color: #ffffff; }
        .btn-emerald:hover { background-color: #047857; }
        .alert {
            margin-top: 14px;
            padding: 12px 14px;
            border-radius: 8px;
            font-size: 0.88rem;
        }
        .alert-ok {
            background-color: #ecfdf5;
            color: #065f46;
            border: 1px solid #a7f3d0;
        }
        .alert-err {
            background-color: #fef2f2;
            color: #991b1b;
            border: 1px solid #fecaca;
        }
        .table-wrap {
            overflow-x: auto;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            font-size: 0.87rem;
        }
        th, td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #e2e8f0;
            vertical-align: top;
        }
        th {
            background-color: #f8fafc;
            color: #334155;
            font-weight: 700;
            font-size: 0.8rem;
            text-transform: uppercase;
            letter-spacing: 0.03em;
        }
        tr.highlight-row {
            background-color: #f0fdf4;
        }
        code {
            font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
            font-size: 0.81rem;
            background-color: #f1f5f9;
            color: #0f172a;
            padding: 3px 6px;
            border-radius: 5px;
            word-break: break-all;
            display: inline-block;
        }
        .badge {
            display: inline-block;
            padding: 3px 9px;
            border-radius: 999px;
            font-size: 0.74rem;
            font-weight: 700;
            margin-bottom: 4px;
        }
        .badge-danger { background-color: #fee2e2; color: #991b1b; }
        .badge-warn { background-color: #fef3c7; color: #92400e; }
        .badge-safe { background-color: #dcfce7; color: #166534; }
        .flow-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(210px, 1fr));
            gap: 12px;
            margin-top: 10px;
        }
        .flow-step {
            background-color: #f8fafc;
            border: 1px solid #e2e8f0;
            border-top: 4px solid #2563eb;
            border-radius: 8px;
            padding: 12px;
            font-size: 0.84rem;
        }
        .flow-step strong {
            display: block;
            color: #0f172a;
            margin-bottom: 6px;
            font-size: 0.88rem;
        }
        .verify-box {
            background-color: #f8fafc;
            border-left: 4px solid #2563eb;
            padding: 12px 14px;
            margin-top: 10px;
            border-radius: 0 8px 8px 0;
            font-size: 0.87rem;
        }
    </style>
</head>
<body>

<div class="container">
    <!-- Header -->
    <div class="banner">
        <span class="banner-tag">PHP Native + HTML &amp; CSS (Tanpa JS)</span>
        <h1>Simulasi Halaman Login: Perbandingan Password, Hash &amp; Salting</h1>
        <p>Penugasan Keamanan Siber &mdash; Perbandingan 4 metode penyimpanan password serta alur verifikasi login berbasis Hash + Salt</p>
    </div>

    <!-- Form Registrasi/Set Password & Form Login -->
    <div class="grid-2">
        <!-- Kolom Kiri: Atur Password -->
        <div class="card" style="margin-bottom: 0;">
            <h2 class="card-header">1. Set Akun / Ubah Password (Simulasi DB)</h2>
            <p class="desc">
                Masukkan password untuk melihat perbandingan hasil penyimpanan pada ke-4 metode. Klik tombol berulang kali dengan password yang sama untuk membuktikan bahwa <b>Salt</b> membuat hasil hash selalu berubah.
            </p>
            <form method="POST" action="">
                <input type="hidden" name="aksi" value="simpan_akun">
                <label for="username">Username</label>
                <input type="text" id="username" name="username" value="<?= htmlspecialchars($akun['username']); ?>" required>

                <label for="password_baru">Password Asli (Plaintext)</label>
                <input type="text" id="password_baru" name="password_baru" value="<?= htmlspecialchars($akun['plaintext']); ?>" required>

                <button type="submit" class="btn btn-blue">Simpan &amp; Generate Hash + Salt Baru</button>
            </form>

            <?php if ($pesan_registrasi !== ""): ?>
                <div class="alert alert-ok"><?= $pesan_registrasi; ?></div>
            <?php endif; ?>
        </div>

        <!-- Kolom Kanan: Halaman Login -->
        <div class="card" style="margin-bottom: 0;">
            <h2 class="card-header">2. Halaman Login User (Pengecekan Salting)</h2>
            <p class="desc">
                Halaman login ini memverifikasi user menggunakan metode <b>Password + Salting</b>. Sistem mengambil <code>salt</code> dari database, menggabungkannya dengan input login, lalu mencocokkan hash-nya.
            </p>
            <form method="POST" action="">
                <input type="hidden" name="aksi" value="login">
                <label for="login_username">Username</label>
                <input type="text" id="login_username" name="login_username" value="<?= htmlspecialchars($akun['username']); ?>" required>

                <label for="login_password">Password Login</label>
                <input type="password" id="login_password" name="login_password" placeholder="Coba ketik: <?= htmlspecialchars($akun['plaintext']); ?> atau password salah" required>

                <button type="submit" class="btn btn-emerald">Login &amp; Tampilkan Proses Pencocokan</button>
            </form>

            <?php if ($hasil_login !== null): ?>
                <?php if ($hasil_login['sukses']): ?>
                    <div class="alert alert-ok">
                        <b>LOGIN BERHASIL!</b> Hash dari <code>input_password + salt</code> cocok dengan hash yang tersimpan di database.
                    </div>
                <?php else: ?>
                    <div class="alert alert-err">
                        <b>LOGIN DITOLAK!</b> Username atau hasil perhitungan <code>SHA256(input_password + salt)</code> tidak cocok.
                    </div>
                <?php endif; ?>
            <?php endif; ?>
        </div>
    </div>

    <!-- Hasil Rincian Alur Pencocokan Saat Login Diklik -->
    <?php if ($hasil_login !== null): ?>
    <div class="card">
        <h2 class="card-header">Hasil Pengecekan Alur Login (Metode Password + Salting)</h2>
        <div class="verify-box">
            <b>Tahap 1 &mdash; Membaca Input Login User:</b><br>
            Username: <code><?= htmlspecialchars($hasil_login['input_user']); ?></code> &nbsp;|&nbsp;
            Password yang diketik: <code><?= htmlspecialchars($hasil_login['input_pass']); ?></code>
        </div>
        <div class="verify-box">
            <b>Tahap 2 &mdash; Mengambil Data <code>Salt</code> &amp; <code>Hash</code> Milik User dari Database:</b><br>
            Salt di Database: <code><?= htmlspecialchars($hasil_login['stored_salt']); ?></code><br>
            Hash + Salt di Database: <code><?= htmlspecialchars($hasil_login['stored_hash']); ?></code>
        </div>
        <div class="verify-box">
            <b>Tahap 3 &mdash; Menggabungkan Password Input + Salt Database, Lalu Menghitung Hash:</b><br>
            Gabungan String (<code>password_input + salt_db</code>): <code><?= htmlspecialchars($hasil_login['string_gabungan']); ?></code><br>
            Hasil <code>SHA256("<?= htmlspecialchars($hasil_login['string_gabungan']); ?>")</code>: <code><?= htmlspecialchars($hasil_login['hash_input_login']); ?></code>
        </div>
        <div class="verify-box" style="border-left-color: <?= $hasil_login['sukses'] ? '#059669' : '#dc2626'; ?>;">
            <b>Tahap 4 &mdash; Pencocokan Akhir (<code>hash_equals</code>):</b><br>
            Hash Perhitungan Login : <code><?= htmlspecialchars($hasil_login['hash_input_login']); ?></code><br>
            Hash Tersimpan di DB &nbsp;&nbsp;: <code><?= htmlspecialchars($hasil_login['stored_hash']); ?></code><br>
            Kesimpulan: <b><?= $hasil_login['sukses'] ? 'IDENTIK / COCOK &rarr; User Diizinkan Masuk' : 'BERBEDA / TIDAK COCOK &rarr; Akses Ditolak'; ?></b>
        </div>
    </div>
    <?php endif; ?>

    <!-- Tabel Perbandingan 4 Metode Sesuai Soal -->
    <div class="card">
        <h2 class="card-header">3. Tabel Perbandingan 4 Metode Penyimpanan Password</h2>
        <div class="table-wrap">
            <table>
                <thead>
                    <tr>
                        <th style="width: 20%;">Metode</th>
                        <th style="width: 24%;">Rumus Pembentukan</th>
                        <th style="width: 36%;">Data yang Tersimpan di Database</th>
                        <th style="width: 20%;">Analisis Keamanan</th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <td><b>1. Password Biasa</b><br><small>(Plaintext)</small></td>
                        <td><code>password</code></td>
                        <td><code><?= htmlspecialchars($akun['plaintext']); ?></code></td>
                        <td>
                            <span class="badge badge-danger">Tidak Aman</span><br>
                            <small>Teks asli langsung terlihat jika tabel database bocor.</small>
                        </td>
                    </tr>
                    <tr>
                        <td><b>2. Hash Saja</b><br><small>(Tanpa Salt)</small></td>
                        <td><code>SHA256(password)</code></td>
                        <td><code><?= htmlspecialchars($akun['hash_only']); ?></code></td>
                        <td>
                            <span class="badge badge-warn">Rentan Rainbow Table</span><br>
                            <small>Jika 2 user memakai password yang sama, nilai hash-nya pasti sama persis.</small>
                        </td>
                    </tr>
                    <tr>
                        <td><b>3. Password + Hash</b><br><small>(Kombinasi Statis)</small></td>
                        <td><code>SHA256(password + SHA256(password))</code></td>
                        <td><code><?= htmlspecialchars($akun['pass_plus_hash']); ?></code></td>
                        <td>
                            <span class="badge badge-warn">Masih Deterministik</span><br>
                            <small>Menghindari kamus SHA-256 biasa, tetapi password yang sama tetap menghasilkan hash akhir yang sama.</small>
                        </td>
                    </tr>
                    <tr class="highlight-row">
                        <td><b>4. Password + Salting</b><br><small>(Dipakai Saat Login)</small></td>
                        <td><code>SHA256(password + salt_acak)</code></td>
                        <td>
                            <b>Salt:</b> <code><?= htmlspecialchars($akun['salt']); ?></code><br>
                            <b>Hash:</b> <code><?= htmlspecialchars($akun['salted_hash']); ?></code>
                        </td>
                        <td>
                            <span class="badge badge-safe">Aman &amp; Dipakai Login</span><br>
                            <small>Setiap user punya <code>salt</code> acak berbeda, sehingga hasil hash selalu unik dan kebal <i>Rainbow Table</i>.</small>
                        </td>
                    </tr>
                </tbody>
            </table>
        </div>
    </div>

    <!-- Penjelasan Alur Konseptual -->
    <div class="card" style="margin-bottom: 0;">
        <h2 class="card-header">4. Penjelasan Alur: Bagaimana Sistem Mencocokkan Password + Salt Saat Login?</h2>
        <p class="desc">
            Karena fungsi <i>Hash</i> bersifat satu arah (tidak bisa dikembalikan/didekripsi menjadi password asli), sistem memverifikasi login menggunakan 4 langkah berikut:
        </p>
        <div class="flow-grid">
            <div class="flow-step">
                <strong>1. Saat Registrasi</strong>
                Sistem membuat <code>salt</code> acak, menggabungkan <code>password + salt</code>, lalu menyimpan <code>salt</code> beserta hasil <code>hash</code>-nya di database.
            </div>
            <div class="flow-step">
                <strong>2. Saat User Login</strong>
                User memasukkan username &amp; password. Sistem mencari username tersebut lalu mengambil nilai <code>salt</code> yang tersimpan di database.
            </div>
            <div class="flow-step">
                <strong>3. Hitung Ulang Hash</strong>
                Password yang baru diketik saat login digabungkan dengan <code>salt</code> lama dari database, lalu di-hash dengan rumus <code>SHA256(input + salt)</code>.
            </div>
            <div class="flow-step">
                <strong>4. Pencocokan Hash</strong>
                Jika hasil hash perhitungan baru sama persis dengan <code>salted_hash</code> di database, maka password terbukti benar tanpa perlu mendekripsi hash.
            </div>
        </div>
    </div>
</div>

</body>
</html>