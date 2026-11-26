# Recon Pro

Authorized bug-bounty recon pipeline for one apex domain: passive subdomain
enumeration, DNS validation, HTTP probing, TLS inventory, URL and parameter
collection, and confirmation stages (takeover, CORS, exposures, open redirect,
GraphQL, JavaScript secrets) on top of nuclei, dalfox, x8, ffuf, naabu and nmap.

**Only test assets you are explicitly authorized to test.** The pipeline asks for
an `AUTHORIZED` confirmation and only ever looks at the apex you give it, minus
the hosts in the exclusion file.

## Quick start (setup sekali, lalu satu perintah per kebutuhan)

```bash
bash setup.sh                 # sekali: pasang semua, termasuk toolkit Python
bash recon.sh --web           # dashboard lokal; token dibuat dan disimpan otomatis
bash recon.sh example.com     # scan aktif + toolkit pasif sekaligus
```

`recon.sh example.com` menjalankan dua hal dalam satu perintah:

1. **pipeline aktif** (`recon_pro.sh`) — subdomain, DNS, TLS, port, URL, nuclei,
   dalfox, ffuf, takeover, CORS, exposures, GraphQL, JS secrets;
2. **toolkit pasif** (`bugbounty-toolkit/`) — crt.sh, DNS, RDAP, analisis header,
   deteksi teknologi, diff antar run, laporan Markdown dengan penjelasan.

Kalau tool atau toolkit belum siap, `recon.sh` memanggil `setup.sh` dulu. Semua
perintah aman dijalankan berulang.

Perintah lain:

```bash
bash recon.sh example.com -y          # tanpa konfirmasi (otomasi/cron)
bash recon.sh --passive example.com   # hanya toolkit pasif (OSINT, tanpa scan aktif)
bash recon.sh --no-passive example.com  # scan aktif saja
bash recon.sh --report example.com    # detail bug dari kedua laporan
bash recon.sh --report                # domain terakhir
bash recon.sh --log example.com       # ringkasan stage + 80 baris log + error per stage
bash recon.sh --failures example.com  # hanya tool/stage yang gagal atau di-skip
bash recon.sh --tools                 # tool + versi + status toolkit Python
bash recon.sh --status                # ringkasan: target, tool, proxy, bot, laporan
bash recon.sh --update                # git pull + cek sintaks + saran restart bot
bash recon.sh --self-test             # cek sintaks semua skrip
bash recon.sh --install-service       # bot sebagai service systemd (bertahan reboot)
bash recon.sh --setup                 # pasang/rapikan semua kebutuhan
bash recon.sh --no-setup example.com  # jangan pasang apa pun, langsung scan
bash recon.sh                         # menu interaktif (scan bertahap, settings, proxy)
```

Setup terpisah, kalau diperlukan:

```bash
bash setup.sh --minimal              # tool inti saja (lebih cepat)
bash setup.sh --with-x8              # sekalian pasang x8 (cargo, lama)
bash setup.sh --web-audit-only       # sqlmap, wafw00f, whatweb, nikto saja
bash setup.sh --with-web-audit       # tambahkan tool audit web ke setup biasa
bash setup.sh --with-arsenal         # tambah skipfish, gobuster, dirsearch, feroxbuster, arjun, wpscan, commix
bash setup.sh --arsenal-only         # hanya paket arsenal di atas
bash setup.sh --python-only          # hanya venv + dependensi toolkit Python
bash setup.sh --no-python            # tanpa toolkit Python
```

### Paket arsenal opsional

`--with-arsenal` menambah tool pendamping di luar pipeline inti: **Skipfish**
(crawler + pemetaan direktori), **Gobuster**, **Feroxbuster**, **dirsearch**
(content discovery), **Arjun** (parameter), **WPScan** (WordPress), dan
**Commix** (command injection). Prasyaratnya dipasang sendiri bila belum ada —
`pipx` untuk Arjun/dirsearch, `unzip` untuk binary Feroxbuster, `ruby` +
`ruby-dev` + `build-essential` untuk WPScan, dan `git` untuk Commix. Feroxbuster
memakai binary resmi rilis terbaru dan baru jatuh ke `cargo` bila unduhan gagal.
Tool yang tetap gagal dipasang hanya diberi peringatan (tidak menghentikan
setup), dan baris terakhir mencetak `Arsenal terpasang: n/7` beserta daftar tool
yang belum ada dan lokasi log. Tool hasil pipx ditautkan ke `/usr/local/bin`
supaya terlihat dari shell mana pun, dan dashboard juga mencari `~/.local/bin`
saat mendeteksi tool.

**Skipfish** sudah tidak ada di arsip Ubuntu, jadi bila apt tidak
menyediakannya setup membangun sumber resmi 2.10b ke `/opt/skipfish` (butuh
`libssl-dev`, `zlib1g-dev`, libidn, dan `libpcre3-dev`) lalu menautkan binary ke
`/usr/local/bin/skipfish` serta dictionary-nya ke
`/usr/local/share/skipfish/dictionaries`. Bila kompilasi atau `gem install`
wpscan gagal, setup mencetak enam baris terakhir penyebabnya langsung di
terminal dan menyimpan log penuh di `state/skipfish-build.log` atau
`state/wpscan-gem.log`. Recon Pro **tidak** menjalankan tool
arsenal secara otomatis — semuanya dipicu manual dari dashboard atau terminal.

Daftar yang sama terlihat di tab **Arsenal** dashboard, lengkap dengan status
terpasang, perintah pemasangan, dan perintah uji ber-volume rendah per tool.

### Paket audit web opsional

Paket ini berisi SQLMap (uji SQL injection), WAFW00F (identifikasi WAF), WhatWeb (fingerprinting teknologi), dan Nikto (pemeriksaan web server). Paket hanya dipasang bila opsi di atas dipilih; Recon Pro tidak menjalankan SQLMap atau Nikto otomatis. Gunakan hanya pada aset yang tercantum in-scope dan dengan izin tertulis. Jangan gunakan opsi SQLMap untuk dump database, shell, atau mengubah data.

Contoh uji terbatas pada parameter yang diizinkan:

```bash
sqlmap -u 'https://in-scope.example/item?id=1' --batch --risk=1 --level=1 --technique=BE --threads=1 --timeout=10 --retries=1
```

Hasil:

| Laporan | Lokasi |
| --- | --- |
| aktif | `~/recon_pro/reports/<domain>/latest-report.md` |
| pasif | `bugbounty-toolkit/reports/<domain>-<timestamp>.md` |

### Profil run & pengukuran durasi

Setiap stage sekarang mencatat berapa lama ia berjalan: kolom keempat
`logs/stages.tsv` berisi durasi dalam detik, kolom kelima jam selesainya. Angka
itu muncul di tab **Log** dashboard, di ringkasan console, dan di tabel metode
pada laporan Markdown — jadi tuning tidak lagi menebak.

```bash
bash recon.sh --fast example.com     # cap kecil, timeout 10 menit, tanpa autocalibrate
bash recon.sh example.com            # pakai angka dari state/recon_pro.conf
bash recon.sh --deep example.com     # cap 2x, timeout 1 jam, autocalibrate
bash recon.sh --max example.com      # cap maksimum, threads 80, rate 150/s
bash recon.sh --timings example.com  # stage diurutkan dari yang paling lama
```

Profil hanya berlaku untuk run itu (`RECON_PRO_PROFILE`), file konfigurasi tidak
diubah. `--max` menaikkan laju request — pastikan masih di dalam batas yang
diizinkan program bounty; kalau tidak, hasilnya WAF block dan temuan palsu
negatif. Run lama yang dibuat sebelum perubahan ini tetap terbaca, hanya kolom
durasinya kosong.

### Kalau semua sudah terpasang

```bash
bash recon_pro.sh -c              # cek tool, tanpa network
bash recon_pro.sh -y example.com  # pipeline penuh non-interaktif
bash recon_pro.sh                 # menu interaktif
```

Requirements: bash 4 atau lebih baru, `curl`, dan `jq` (sangat disarankan).
Setiap scanner opsional: tool yang tidak ada hanya melewati stage-nya, dan
laporan mencatat tool mana yang benar-benar jalan. Toolkit pasif butuh Python 3.9+
(`setup.sh` membuat virtualenv dan memasang dependensinya).

The Telegram control bot is documented in [TELEGRAM_BOT.md](TELEGRAM_BOT.md);
it runs the same combined flow (`/scan`) and can run the passive toolkit alone
with `/passive`. The passive toolkit itself is documented in
[bugbounty-toolkit](bugbounty-toolkit/README.md).

## Routing your traffic through proxies

Put one proxy per line in `~/recon_pro/state/proxies.txt` (created as a commented
template on the first run):

```
http://user:pass@203.0.113.10:3128
socks5://203.0.113.11:1080
```

* **Rotation** — a new proxy is picked for every stage and every `curl` request.
* **Coverage** — `curl` requests and every scanner whose installed build
  advertises a proxy flag (`subfinder`, `httpx`, `tlsx`, `katana`, `nuclei`,
  `dalfox`, `ffuf`, `naabu`, `whatweb`). Support is detected from the tool's own
  `-h` output, so an older build is never broken by an unknown flag.
* **Not covered** — `dnsx` and `nmap`. DNS queries and raw TCP connects cannot go
  through an HTTP/SOCKS proxy, so the resolver and the target still see this
  host's IP for those stages. Every run's `scan_info.txt`, console summary and
  report metadata states this explicitly.
* **Guard** — set `PROXY_REQUIRED=1` (Settings, option 7) and the run refuses to
  start when no usable proxy is configured, instead of quietly using your IP.
* **Check** — menu option `9` sends one request per proxy to a neutral endpoint
  and prints its exit IP, so a dead entry is found before a scan burns budget.

Untuk daftar yang panjang (ratusan entri), saring dulu:

```bash
bash recon.sh --proxy-check    # uji semua, tulis <file>.good
bash recon.sh --proxy-clean     # uji lalu ganti file dengan yang hidup
```

`--proxy-check` menguji 10 proxy sekaligus (timeout 8 detik) lewat
`https://api.ipify.org`, dan menyimpan yang benar-benar menjawab.

> **Jangan pakai daftar proxy gratis publik** untuk ini. Selain hampir semuanya
> mati, proxy gratis bisa membaca traffic (termasuk cookie/session milikmu ke
> target) dan sering dipakai untuk hal ilegal. Untuk bug bounty, pakai layanan
> proxy berbayar yang punya endpoint rotating (satu gateway yang berganti IP tiap
> request — cukup satu baris di file, lebih andal daripada ribuan proxy mati),
> atau VPS sendiri.

Configure it in Settings (option 7) or directly in `state/recon_pro.conf`:

```
PROXY_FILE|/home/you/recon_pro/state/proxies.txt
PROXY_ROTATE|1
PROXY_REQUIRED|0
```

## Reading the bug report

Every run writes two reports inside its workspace:

| File | For |
| --- | --- |
| `final/report.md` | the human report: executive summary, scope proof, methodology, one explained block per finding, changes since the last run, risk rating, recommendations |
| `final/bugs_found.txt` | the full console report with every observation section |

Each finding in `final/report.md` answers four questions: **what it is**, **why it
matters**, **what the impact is**, and **how to verify it by hand** — followed by
the recommended fix. The same explanation is printed in the console when a run
finishes (first ten findings), and the Telegram summary points to the file.

`reports/<domain>/latest-report.md` is a copy you can open without hunting for
the run folder.


## Where everything is saved

One root folder, `~/recon_pro`, holds every file the tool writes (move it with
`RECON_PRO_HOME`):

| Path | Contents |
| --- | --- |
| `runs/<domain>/recon_<domain>_<timestamp>/` | one scan workspace (`subs/`, `alive/`, `urls/`, `nuclei/`, `tls/`, `web/`, `final/`, `logs/`, ...) |
| `runs/<domain>/latest` | link to that domain's newest workspace |
| `reports/<domain>/latest-bugs_found.txt` | newest full report, short stable path |
| `reports/<domain>/latest-report.md` | newest explained Markdown report |
| `reports/<domain>/latest-telegram_report.txt` | newest chat summary |
| `state/recon_pro.conf` | settings |
| `state/exclusions.txt` | out-of-scope hostnames |
| `state/scope.txt` | apex domains approved for the Telegram bot |
| `state/bot/` | bot lock, scan status and logs |
| `bugbounty-toolkit/reports/<domain>-<timestamp>.md` | passive toolkit report |
| `bugbounty-toolkit/data/extra_scope.txt` | domains added by `recon.sh` / `/passive` |
| `bugbounty-toolkit/logs/toolkit.log` | passive toolkit log |

Earlier versions dropped a `recon_<domain>_<timestamp>` folder straight into the
home directory and kept the config, exclusions, scope list and bot state as
hidden files in `$HOME`. Those files are moved into the tree on the first start;
old run folders are left where they are, so nothing is lost.

`KEEP_RUNS=n` (settings, option 7) keeps only the newest n runs per domain and is
off by default (`0` = keep every run).

## How the scan keeps itself accurate

- Collection stages only produce candidates; a finding is recorded as
  `confirmed` only when a second, independent signal proves it. The report leads
  with confirmed findings, ranked by score, and lists observations separately.
- Passive collection merges subfinder, assetfinder, amass, findomain, chaos,
  crt.sh, CertSpotter, HackerTarget, Anubis and the apex certificate's own SANs,
  then DNS-validates the result before anything is probed.
- Wildcard DNS is detected explicitly, and `dnsx -auto-wildcard` drops the names
  that only answer through the wildcard record.
- Hosts named only by a certificate are probed and merged into the host and URL
  lists instead of being left out of URL collection, nuclei and dalfox.
- `httpx` runs with retries, and `nuclei` selects templates from the detected
  technology stack (`-as`) without the update check (`-duc`).
- Security-header observations cover 2xx/3xx responses only: the header set of a
  401, 403, 404 or 5xx page is not the application's.
- Parameter candidates drop analytics-only URLs and static assets, so dalfox and
  x8 spend their budget on real endpoints.

## Dashboard web lokal (VPS & Termux)

Dashboard berjalan pada mesin yang sama dengan scanner. Tidak ada scan yang dijalankan dari cloud preview: Python server lokal mengontrol `recon.sh` langsung di VPS atau perangkat Termux.

### Jalankan di VPS Linux

Setelah repository tersedia, cukup jalankan:

```bash
bash setup.sh                 # sekali saja, bila tool Recon Pro belum dipasang
bash recon.sh --web
```

Buka `http://127.0.0.1:8765`. Launcher membuat token aman otomatis, menyimpannya di `state/web_token` dengan izin privat, lalu menampilkan token untuk login. Hentikan dengan `Ctrl-C`. Untuk akses dari laptop/ponsel, biarkan server bind lokal dan gunakan SSH tunnel:

```bash
ssh -L 8765:127.0.0.1:8765 user@alamat-vps
```

Lalu buka `http://127.0.0.1:8765` pada perangkat yang membuat tunnel.

### Jalankan di Termux / Android

Pastikan Bash dan Python tersedia, lalu jalankan launcher yang sama:

```bash
pkg install bash python
bash recon.sh --web
```

Buka `http://127.0.0.1:8765` di browser Android. Scanner dan seluruh file hasil tetap berjalan/tersimpan di Termux. Dashboard tidak memerlukan instalasi dependensi Python tambahan.

Alias `bash recon.sh --dashboard` dan launcher langsung `bash web_ui/start.sh` juga tersedia. Opsi `RECON_WEB_PORT` dapat mengganti port default 8765.

### Penggunaan & keamanan

- Masukkan token yang ditampilkan launcher. Token server disimpan di `state/web_token` dengan izin owner-only agar tidak perlu dibuat ulang; token sesi browser hanya berada di `sessionStorage`, dan API meminta autentikasi pada setiap panggilan.
- Dashboard bind ke `127.0.0.1` secara default. Gunakan SSH tunnel untuk akses VPS. Jangan membuka port server langsung ke internet.
- Bila harus memasang reverse proxy, batasi firewall dan pakai TLS. Bind non-local memerlukan `RECON_WEB_ALLOW_REMOTE=1` serta `RECON_WEB_ALLOWED_HOSTS` yang berisi hostname persis; server dashboard sendiri tidak menyediakan TLS.
- Tambahkan hanya apex yang eksplisit diizinkan program bounty ke Scope & Proxy. Daftar disimpan pada `~/recon_pro/state/scope.txt`; setiap pemindaian memerlukan konfirmasi operator dan server memeriksa ulang allowlist serta `state/exclusions.txt`.
- Pipeline lengkap dapat melakukan pemeriksaan aktif. Passive saja membatasi kerja ke toolkit OSINT dan pemeriksaan header. Scan web selalu memakai `--no-setup`, sehingga instalasi tool tidak dijalankan dari UI.
- Proxy dapat dikelola dari halaman Scope & Proxy. Kredensial tidak dikembalikan pada daftar ringkas, file disimpan dengan izin owner-only, dan log yang ditampilkan menyamarkan pola kredensial yang dikenal. DNS dan nmap tetap tidak melalui proxy.
- Server memakai Python standard library saja. Kebutuhan Recon Pro (Bash, scanner dan dependensi toolkit pasif) tetap harus dipasang di host terlebih dahulu.
- Halaman **Terminal VPS** menjalankan perintah Bash yang diketik operator dan menampilkan output live; direktori kerja dapat dipilih (default `/`, seluruh filesystem dapat diakses sesuai hak akun dashboard). Aktifkan secara eksplisit dengan `RECON_WEB_ENABLE_SHELL=1 bash recon.sh --web`. Terminal hanya tersedia saat bind ke loopback, memakai token dashboard, hanya menjalankan satu perintah sekaligus, dan tidak menerima stdin/TTY interaktif; pilihan direktori berlaku pada sesi browser, sedangkan `cd` di dalam command hanya berlaku untuk command itu. Shell memiliki hak akun Linux dashboard (termasuk root) serta melewati allowlist scope UI; jangan pernah mengekspos dashboard ke internet dan gunakan hanya pada aset yang berizin. Scan dashboard dan command shell saling mengunci agar tidak berjalan bersamaan.
- Tab **Arsenal** memuat katalog tool beserta status terpasang, perintah pemasangan, dan perintah uji ber-volume rendah: skipfish, gobuster, feroxbuster, dirsearch, ffuf, nuclei, nikto, whatweb, wafw00f, sqlmap, wpscan, commix, dalfox, arjun, x8, subfinder, amass, chaos, dnsx, httpx, katana, gau, tlsx, naabu, dan nmap. Domain scope terpilih disisipkan ke placeholder `{{TARGET}}`. Tombol **Kirim ke terminal** hanya mengisi kolom perintah pada tab Terminal VPS — operator tetap meninjau dan mengonfirmasi sebelum menjalankan. Katalog bersifat baca-saja melalui `GET /api/arsenal`. Antarmuka memakai tema terminal gelap (scanline CRT, matrix rain, judul glitch, jam operasi) yang animasinya otomatis berhenti bila sistem meminta `prefers-reduced-motion`.
- Tab **Laporan** memungkinkan pemilihan target, riwayat run, lalu setiap file laporan final; laporan pasif Markdown/JSON historis juga tersedia. Tab **Log aktivitas** menampilkan file pipeline dan semua error per stage pada run terpilih. `toolkit.log` beserta rotasinya adalah log global toolkit pasif, bukan log per-run.
- Opsional: koneksi MCP updater VPS hanya menyediakan satu aksi tetap untuk `git pull` dan self-test; tidak menyediakan shell. Lihat [panduan MCP updater](vps_mcp/README.md) untuk Cloudflare named tunnel yang persisten atau Quick Tunnel sementara.
- Isi dan unduhan file disamarkan untuk pola kredensial yang dikenali. Demi batas memori, isi per file dibatasi 16 MiB; file lebih besar ditandai terpotong.
- Riwayat mengikuti pengaturan `OUTPUT_BASE` pada `state/recon_pro.conf`, termasuk jika folder run dipindahkan. Run lama yang sudah dihapus oleh `KEEP_RUNS` tidak dapat dipulihkan dari dashboard.
- Tombol Run FreeMilk hanya menampilkan UI statis dan tidak dapat mengakses scanner lokal. Untuk pemindaian, buka alamat lokal VPS/Termux sesuai langkah di atas.

Konfigurasi opsional: `RECON_PRO_HOME` memindahkan folder data yang sama dengan pipeline; `RECON_WEB_HOST`, `RECON_WEB_PORT`, `BUGBOUNTY_SCOPE_FILE`, dan `RECON_WEB_ALLOWED_HOSTS` dapat diatur sesuai lingkungan.
