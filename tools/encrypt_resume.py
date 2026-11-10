#!/usr/bin/env python3
"""Encrypt a résumé PDF into resume.enc for the site's padlock.

Usage:  python3 tools/encrypt_resume.py path/to/resume.pdf
        (asks for the access code; letters and numbers only, spaces are ignored)

Needs:  pip install cryptography
The code itself is never written anywhere. Commit only resume.enc, never the PDF.
"""
import getpass, os, struct, sys
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

WHEELS = 9            # must match RESUME.groups in index.html (4 + 5)
ITERATIONS = 600_000  # slows down every guess

def main():
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    pdf = open(sys.argv[1], "rb").read()
    if not pdf.startswith(b"%PDF"):
        sys.exit("That doesn't look like a PDF.")
    code = "".join(getpass.getpass("Access code: ").split()).upper()
    if code != "".join(getpass.getpass("Again: ").split()).upper():
        sys.exit("Codes didn't match.")
    if len(code) != WHEELS or not code.isalnum() or not code.isascii():
        sys.exit(f"Code must be exactly {WHEELS} letters/numbers.")
    salt, iv = os.urandom(16), os.urandom(12)
    key = PBKDF2HMAC(hashes.SHA256(), 32, salt, ITERATIONS).derive(code.encode())
    blob = b"RSM1" + struct.pack(">I", ITERATIONS) + salt + iv + AESGCM(key).encrypt(iv, pdf, None)
    out = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "resume.enc")
    open(out, "wb").write(blob)
    print(f"Wrote {os.path.normpath(out)} ({len(blob):,} bytes). Commit resume.enc only.")

if __name__ == "__main__":
    main()
