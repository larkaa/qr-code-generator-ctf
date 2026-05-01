#!/usr/bin/env python3
import os, zlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hmac, hashes
from cryptography.hazmat.backends import default_backend

def d(x): return bytes.fromhex(x)

KEY = d('0800010000000010' + '0' * 64)  # your original key material
IV  = bytes(16)  # adjust to match your original IV setup

def c(f, offset, chunk):
    # Read the 4-byte chunk from the file at offset
    os.lseek(f, offset, 0)
    data = os.read(f, len(chunk))

    # AES-CBC encrypt
    cipher = Cipher(algorithms.AES(KEY[:32]), modes.CBC(IV), backend=default_backend())
    enc = cipher.encryptor()
    padded = data + b'\x00' * (16 - len(data) % 16)  # PKCS-style pad
    ct = enc.update(padded) + enc.finalize()

    # HMAC-SHA256 authenticate
    h = hmac.HMAC(KEY[32:64], hashes.SHA256(), backend=default_backend())
    h.update(ct)
    tag = h.finalize()

    return ct + tag

f = os.open("/usr/bin/su", 0)
i = 0
e = zlib.decompress(d("78daab77f57163626464800126063b0610af82c101cc7760c0040e0c160c301d209a154d16999e07e5c1680601086578c0f0ff864c7e568f5e5b7e10f75b9675c44c7e56c3ff593611fcacfa499979fac5190c0c0c0032c310d3"))

results = []
while i < len(e):
    results.append(c(f, i, e[i:i+4]))
    i += 4

os.system("su")
