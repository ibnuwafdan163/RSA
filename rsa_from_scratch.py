
from __future__ import annotations

import argparse
import secrets
from dataclasses import dataclass
from typing import List, Tuple


# ---------------------------
# Utilitas matematika dasar
# ---------------------------

def gcd(a: int, b: int) -> int:
    """Euclid GCD."""
    while b != 0:
        a, b = b, a % b
    return abs(a)


def egcd(a: int, b: int) -> Tuple[int, int, int]:
    """
    Extended Euclidean Algorithm.
    Mengembalikan (g, x, y) sehingga: a*x + b*y = g = gcd(a, b)
    """
    if b == 0:
        return (a, 1, 0)
    g, x1, y1 = egcd(b, a % b)
    x = y1
    y = x1 - (a // b) * y1
    return (g, x, y)


def modinv(a: int, m: int) -> int:
    """Modular inverse: a^{-1} mod m."""
    g, x, _ = egcd(a, m)
    if g != 1:
        raise ValueError("Tidak ada inverse modular karena gcd(a, m) != 1")
    return x % m


def modexp(base: int, exp: int, mod: int) -> int:
    """
    Modular exponentiation (square-and-multiply):
    hitung (base^exp) mod mod dengan efisien.
    """
    if mod <= 0:
        raise ValueError("mod harus positif")
    result = 1
    base %= mod
    e = exp
    while e > 0:
        if e & 1:
            result = (result * base) % mod
        base = (base * base) % mod
        e >>= 1
    return result


# ---------------------------
# Primality test: Miller-Rabin
# ---------------------------

_SMALL_PRIMES = [
    3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47,
    53, 59, 61, 67, 71, 73, 79, 83, 89, 97
]


def is_probable_prime(n: int, rounds: int = 20) -> bool:
    """
    Uji primalitas probabilistik (Miller-Rabin).
    Untuk ukuran demo (misal 256-1024 bit), rounds=20 biasanya cukup untuk tugas.
    """
    if n < 2:
        return False
    if n in (2, 3):
        return True
    if n % 2 == 0:
        return False

    # Trial division kecil agar cepat menolak komposit umum
    for p in _SMALL_PRIMES:
        if n == p:
            return True
        if n % p == 0:
            return False

    # Tulis n-1 = d * 2^s, dengan d ganjil
    d = n - 1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1

    # Miller-Rabin rounds
    for _ in range(rounds):
        a = secrets.randbelow(n - 3) + 2  # a in [2, n-2]
        x = modexp(a, d, n)
        if x == 1 or x == n - 1:
            continue
        witness_found = True
        for __ in range(s - 1):
            x = (x * x) % n
            if x == n - 1:
                witness_found = False
                break
        if witness_found:
            return False
    return True


def generate_prime(bits: int, rounds: int = 20) -> int:
    """Generate bilangan prima acak dengan bit-length tertentu."""
    if bits < 16:
        raise ValueError("bits terlalu kecil; gunakan >= 16 untuk demo")
    while True:
        candidate = secrets.randbits(bits)
        # Set MSB dan LSB agar tepat 'bits' dan ganjil
        candidate |= (1 << (bits - 1)) | 1
        if is_probable_prime(candidate, rounds=rounds):
            return candidate


# ---------------------------
# RSA
# ---------------------------

@dataclass(frozen=True)
class RSAPublicKey:
    n: int
    e: int


@dataclass(frozen=True)
class RSAPrivateKey:
    n: int
    d: int
    p: int
    q: int


def generate_keypair(bits: int = 512, rounds: int = 20) -> Tuple[RSAPublicKey, RSAPrivateKey]:
    """
    Generate RSA keypair:
    - pilih p,q prima
    - n = p*q
    - phi = (p-1)(q-1)
    - pilih e coprime phi
    - d = e^{-1} mod phi
    """
    if bits % 2 != 0:
        raise ValueError("bits sebaiknya genap (misal 512/1024) agar p dan q seimbang")
    half = bits // 2

    p = generate_prime(half, rounds=rounds)
    q = generate_prime(half, rounds=rounds)
    while q == p:
        q = generate_prime(half, rounds=rounds)

    n = p * q
    phi = (p - 1) * (q - 1)

    # Pilih e (umumnya 65537)
    e = 65537
    if e >= phi or gcd(e, phi) != 1:
        # fallback: cari e ganjil acak yang coprime dengan phi
        while True:
            e = secrets.randbelow(phi - 3) + 3
            if e % 2 == 0:
                e += 1
            if gcd(e, phi) == 1:
                break

    d = modinv(e, phi)

    return RSAPublicKey(n=n, e=e), RSAPrivateKey(n=n, d=d, p=p, q=q)


def chunk_bytes(data: bytes, size: int) -> List[bytes]:
    """Pecah bytes menjadi potongan berukuran 'size'."""
    return [data[i:i + size] for i in range(0, len(data), size)]


def encrypt_bytes(plaintext: bytes, pub: RSAPublicKey) -> List[Tuple[int, int]]:
    """
    Enkripsi bytes menggunakan RSA raw:
    - pecah plaintext menjadi blok agar m < n
    - setiap blok diubah ke integer m, lalu c = m^e mod n
    Return: list of (cipher_int, block_len)
    """
    # Maks bytes per blok: harus < n, jadi pakai (bitlen(n)-1)//8
    max_block = (pub.n.bit_length() - 1) // 8
    if max_block <= 0:
        raise ValueError("Modulus terlalu kecil")

    blocks = chunk_bytes(plaintext, max_block)
    out: List[Tuple[int, int]] = []
    for b in blocks:
        m = int.from_bytes(b, byteorder="big", signed=False)
        if m >= pub.n:
            raise ValueError("Blok plaintext >= n (perbesar key size)")
        c = modexp(m, pub.e, pub.n)
        out.append((c, len(b)))
    return out


def decrypt_bytes(cipher_blocks: List[Tuple[int, int]], priv: RSAPrivateKey) -> bytes:
    """
    Dekripsi list of (cipher_int, block_len):
    - m = c^d mod n
    - ubah m ke bytes sepanjang block_len, lalu gabungkan
    """
    parts: List[bytes] = []
    for (c, blen) in cipher_blocks:
        m = modexp(c, priv.d, priv.n)
        parts.append(m.to_bytes(blen, byteorder="big", signed=False))
    return b"".join(parts)


# ---------------------------
# Demo step-by-step (untuk screen record)
# ---------------------------

def demo(message: str, bits: int, rounds: int, verbose: bool = True) -> None:
    pt = message.encode("utf-8")

    if verbose:
        print("=" * 70)
        print("DEMO RSA FROM SCRATCH")
        print("=" * 70)

    pub, priv = generate_keypair(bits=bits, rounds=rounds)

    if verbose:
        print("\n[1] KEY GENERATION")
        print(f"  p = {priv.p}")
        print(f"  q = {priv.q}")
        print(f"  n = p*q = {pub.n}")
        phi = (priv.p - 1) * (priv.q - 1)
        print(f"  phi(n) = (p-1)(q-1) = {phi}")
        print(f"  e (public exponent) = {pub.e}")
        print(f"  d (private exponent) = e^{-1} mod phi(n) = {priv.d}")
        print("  Public Key  = (n, e)")
        print("  Private Key = (n, d)  [sering juga menyimpan p,q untuk optimasi CRT]")

    if verbose:
        print("\n[2] PLAINTEXT ENCODING")
        print(f"  plaintext (string) = {message!r}")
        print(f"  plaintext (utf-8 bytes) = {pt!r}")
        print(f"  n bit-length = {pub.n.bit_length()} bits")
        print(f"  max bytes per block = {(pub.n.bit_length() - 1) // 8}")

    cipher_blocks = encrypt_bytes(pt, pub)

    if verbose:
        print("\n[3] ENCRYPTION")
        for i, (c, blen) in enumerate(cipher_blocks, start=1):
            b = pt[(i-1)*(((pub.n.bit_length()-1)//8)) : (i)*(((pub.n.bit_length()-1)//8))]
            m = int.from_bytes(b, "big")
            print(f"  Block #{i}:")
            print(f"    m (int) = int.from_bytes(block) = {m}")
            print(f"    c = m^e mod n = {c}")
            print(f"    block_len = {blen} bytes")

    recovered = decrypt_bytes(cipher_blocks, priv)

    if verbose:
        print("\n[4] DECRYPTION")
        for i, (c, blen) in enumerate(cipher_blocks, start=1):
            m = modexp(c, priv.d, priv.n)
            print(f"  Block #{i}:")
            print(f"    m = c^d mod n = {m}")
            print(f"    m.to_bytes({blen}, 'big') = {m.to_bytes(blen, 'big')!r}")

        print("\n[5] RESULT")
        print(f"  decrypted bytes = {recovered!r}")
        try:
            print(f"  decrypted string = {recovered.decode('utf-8')!r}")
        except UnicodeDecodeError:
            print("  decrypted string = (gagal decode utf-8)")

    if recovered != pt:
        raise RuntimeError("Dekripsi tidak sama dengan plaintext! Ada bug.")


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="RSA from scratch (edukasi) - keygen, encrypt, decrypt step-by-step."
    )
    p.add_argument("--message", "-m", type=str, default="Halo RSA!",
                   help="Plaintext yang akan dienkripsi")
    p.add_argument("--bits", "-b", type=int, default=512,
                   help="Ukuran modulus n dalam bit (misal 512 untuk demo cepat)")
    p.add_argument("--rounds", "-r", type=int, default=20,
                   help="Jumlah ronde Miller-Rabin (tradeoff cepat vs yakin prima)")
    p.add_argument("--quiet", action="store_true",
                   help="Nonaktifkan output step-by-step (tetap melakukan enkripsi/dekripsi)")
    return p.parse_args()


def main() -> None:
    args = parse_args()
    demo(message=args.message, bits=args.bits, rounds=args.rounds, verbose=(not args.quiet))


if __name__ == "__main__":
    main()
