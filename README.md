# RSA From Scratch (Python)

## Deskripsi
Proyek ini merupakan implementasi sederhana algoritma **RSA (Rivest–Shamir–Adleman)** menggunakan bahasa Python yang dibuat dari awal tanpa menggunakan library kriptografi eksternal. Program ini dibuat untuk tujuan pembelajaran agar pengguna dapat memahami bagaimana proses kriptografi RSA bekerja secara **step-by-step**, mulai dari pembuatan kunci hingga proses enkripsi dan dekripsi pesan.

Program akan menampilkan beberapa tahapan utama yaitu:
* Key Generation (pembuatan kunci publik dan privat)
* Encoding plaintext
* Proses enkripsi pesan
* Proses dekripsi ciphertext
* Hasil akhir plaintext yang berhasil dipulihkan
---

# Persyaratan Sistem
Sebelum menjalankan program, pastikan perangkat telah memiliki:
* Python versi 3.x
* Terminal / Command Prompt / PowerShell

Untuk mengecek versi Python jalankan:
```
python --version
```
atau
```
python3 --version
```
---

# Struktur Folder
Contoh struktur folder proyek:
```
coding
 └── DKI
      └── rsa_from_scratch.py
```
---

# Cara Menjalankan Program
## 1. Buka Terminal
Buka terminal pada folder tempat file `rsa_from_scratch.py` berada.
Contoh menggunakan PowerShell:
```
cd D:\coding\DKI
```
---
## 2. Menjalankan Program Dasar
Jalankan program dengan perintah berikut:
```
python rsa_from_scratch.py
```
Program akan otomatis melakukan proses:
* pembuatan kunci RSA
* enkripsi pesan
* dekripsi pesan
---
## 3. Menjalankan dengan Pesan Tertentu
Untuk mengenkripsi pesan tertentu gunakan parameter `-m` atau `--message`.
Contoh:
```
python rsa_from_scratch.py -m "Halo RSA"
```
---

## 4. Mengatur Ukuran Kunci RSA
Ukuran kunci dapat diatur menggunakan parameter `-b` atau `--bits`.
Contoh:
```
python rsa_from_scratch.py -m "Pesan Rahasia" -b 512
```
Semakin besar ukuran bit, semakin kuat keamanan RSA namun proses komputasi juga akan lebih lama.
---

## 5. Mengatur Jumlah Pengujian Bilangan Prima
Parameter `-r` atau `--rounds` digunakan untuk menentukan jumlah iterasi pengujian bilangan prima menggunakan metode Miller-Rabin.
Contoh:
```
python rsa_from_scratch.py -m "Pesan Rahasia" -r 20
```
---
## 6. Menjalankan Tanpa Menampilkan Proses Detail
Jika ingin menjalankan program tanpa menampilkan proses langkah demi langkah, gunakan opsi:
```
python rsa_from_scratch.py --quiet
```
---
# Contoh Perintah Lengkap
```
python rsa_from_scratch.py -m "Ini adalah pesan rahasia" -b 512 -r 20
```
Program akan menghasilkan:
* Public Key
* Private Key
* Ciphertext hasil enkripsi
* Plaintext hasil dekripsi
---
# Tujuan Proyek
Proyek ini dibuat sebagai media pembelajaran untuk memahami konsep dasar kriptografi RSA seperti:
* Bilangan prima
* Modular arithmetic
* Modular exponentiation
* Public key cryptography

Implementasi ini ditujukan untuk keperluan edukasi dan demonstrasi algoritma kriptografi.
---
SCRENSHOOT OUTPUT PROGRAM
<img width="1396" height="579" alt="Screenshot 2026-03-05 211942" src="https://github.com/user-attachments/assets/92aca433-951b-42d4-8a2d-cd1a928ac46e" />

