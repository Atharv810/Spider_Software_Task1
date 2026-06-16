#!/usr/bin/env python3
"""
CryptoVault — A command-line file encryption tool.
Stages: Caesar Lock → Hash Guard → AES Upgrade → RSA Key Exchange
"""

import argparse
import hashlib
import json
import os
import sys
import string
from collections import Counter

# ==============================================================================
# STAGE 1: Caesar Cipher
# ==============================================================================

def caesar_encrypt(text, shift):
    """Encrypt text using Caesar cipher with given shift."""
    result = []
    for ch in text:
        if ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')
            result.append(chr((ord(ch) - base + shift) % 26 + base))
        else:
            result.append(ch)
    return ''.join(result)


def caesar_decrypt(text, shift):
    """Decrypt text using Caesar cipher with given shift."""
    return caesar_encrypt(text, -shift)


def frequency_analysis(ciphertext):
    """
    Crack Caesar cipher using frequency analysis.
    Returns top 3 most likely (shift, plaintext) pairs.
    """
    # English letter frequency order (most common first)
    english_freq = "etaoinshrdlcumwfgypbvkjxqz"

    # Count only alphabetic characters in ciphertext
    letters = [ch.lower() for ch in ciphertext if ch.isalpha()]
    if not letters:
        return []

    freq = Counter(letters)
    most_common_cipher = freq.most_common(1)[0][0]

    # Try each possible shift (0-25) and score by frequency match
    scores = []
    for shift in range(26):
        decrypted = caesar_decrypt(ciphertext, shift)
        dec_letters = [ch.lower() for ch in decrypted if ch.isalpha()]
        dec_freq = Counter(dec_letters)
        total = sum(dec_freq.values())

        # Score based on how well letter frequencies match English
        score = 0
        for i, letter in enumerate(english_freq[:6]):  # top 6 letters
            score += dec_freq.get(letter, 0) * (6 - i)

        scores.append((score, shift, decrypted))

    # Sort by score descending, return top 3
    scores.sort(key=lambda x: x[0], reverse=True)
    return [(s[1], s[2]) for s in scores[:3]]


# ==============================================================================
# STAGE 2: Hash Guard (SHA-256 integrity)
# ==============================================================================

def compute_sha256(data):
    """Compute SHA-256 hash of data (bytes or str)."""
    if isinstance(data, str):
        data = data.encode('utf-8')
    return hashlib.sha256(data).hexdigest()


# ==============================================================================
# STAGE 3: AES-256-CBC Encryption
# ==============================================================================

def aes_encrypt(plaintext_bytes, password):
    """
    Encrypt bytes using AES-256-CBC.
    Returns: salt (16 bytes) + iv (16 bytes) + ciphertext
    """
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives import padding as sym_padding
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.backends import default_backend

    # Generate random salt and IV
    salt = os.urandom(16)
    iv = os.urandom(16)

    # Derive AES-256 key from password using PBKDF2
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # 256 bits
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode('utf-8'))

    # Pad plaintext to block size
    padder = sym_padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext_bytes) + padder.finalize()

    # Encrypt
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    return salt + iv + ciphertext


def aes_decrypt(enc_data, password):
    """
    Decrypt AES-256-CBC encrypted data.
    Input format: salt (16 bytes) + iv (16 bytes) + ciphertext
    Returns: plaintext bytes
    """
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives import padding as sym_padding
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.backends import default_backend

    salt = enc_data[:16]
    iv = enc_data[16:32]
    ciphertext = enc_data[32:]

    # Derive key from password
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode('utf-8'))

    # Decrypt
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()

    # Unpad
    unpadder = sym_padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_data) + unpadder.finalize()

    return plaintext


# ==============================================================================
# STAGE 4: RSA Key Exchange (Hybrid Encryption)
# ==============================================================================

def generate_rsa_keypair(output_dir="."):
    """Generate a 2048-bit RSA keypair and save as PEM files."""
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.backends import default_backend

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    # Save private key
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    private_path = os.path.join(output_dir, "private.pem")
    with open(private_path, 'wb') as f:
        f.write(private_pem)

    # Save public key
    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    public_path = os.path.join(output_dir, "public.pem")
    with open(public_path, 'wb') as f:
        f.write(public_pem)

    print(f"RSA keypair generated:")
    print(f"  Private key: {private_path}")
    print(f"  Public key:  {public_path}")


def hybrid_encrypt(plaintext_bytes, public_key_path):
    """
    Hybrid encryption: AES-256-CBC for data, RSA-OAEP for AES key.
    Output format: [4 bytes: RSA-encrypted key length][RSA-encrypted AES key][salt][iv][ciphertext]
    """
    from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives import padding as sym_padding
    from cryptography.hazmat.backends import default_backend

    # Load public key
    with open(public_key_path, 'rb') as f:
        public_key = serialization.load_pem_public_key(f.read(), backend=default_backend())

    # Generate random AES key, salt, and IV
    aes_key = os.urandom(32)  # 256 bits
    salt = os.urandom(16)
    iv = os.urandom(16)

    # Encrypt AES key with RSA public key (OAEP padding)
    encrypted_aes_key = public_key.encrypt(
        aes_key,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Pad and encrypt data with AES
    padder = sym_padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext_bytes) + padder.finalize()

    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    # Pack: [key_len (4 bytes)][encrypted_aes_key][salt (16)][iv (16)][ciphertext]
    key_len = len(encrypted_aes_key).to_bytes(4, 'big')
    return key_len + encrypted_aes_key + salt + iv + ciphertext


def hybrid_decrypt(enc_data, private_key_path):
    """
    Hybrid decryption: RSA-OAEP to recover AES key, then AES-CBC to decrypt data.
    """
    from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives import padding as sym_padding
    from cryptography.hazmat.backends import default_backend

    # Load private key
    with open(private_key_path, 'rb') as f:
        private_key = serialization.load_pem_private_key(
            f.read(), password=None, backend=default_backend()
        )

    # Parse header
    key_len = int.from_bytes(enc_data[:4], 'big')
    encrypted_aes_key = enc_data[4:4 + key_len]
    salt = enc_data[4 + key_len:4 + key_len + 16]
    iv = enc_data[4 + key_len + 16:4 + key_len + 32]
    ciphertext = enc_data[4 + key_len + 32:]

    # Decrypt AES key with RSA private key
    try:
        aes_key = private_key.decrypt(
            encrypted_aes_key,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    except Exception as e:
        print(f"ERROR: RSA decryption failed. Wrong private key? ({e})")
        sys.exit(1)

    # Decrypt data with AES
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()

    # Unpad
    unpadder = sym_padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_data) + unpadder.finalize()

    return plaintext


# ==============================================================================
# FILE FORMAT (with hash verification):
#
# For Caesar mode:
#   JSON: {"method": "caesar", "shift": N, "hash": "<sha256>", "ciphertext": "..."}
#
# For AES mode:
#   Binary: [MAGIC 8 bytes: CVAULT01][hash 32 bytes][salt 16][iv 16][ciphertext...]
#
# For RSA hybrid mode:
#   Binary: [MAGIC 8 bytes: CVAULT02][hash 32 bytes][key_len 4][enc_key][salt 16][iv 16][ciphertext...]
# ==============================================================================

MAGIC_AES = b'CVAULT01'
MAGIC_RSA = b'CVAULT02'


def cmd_encrypt(args):
    """Handle the encrypt command."""
    input_file = args.file

    if not os.path.exists(input_file):
        print(f"ERROR: File '{input_file}' not found.")
        sys.exit(1)

    # Read input file
    with open(input_file, 'rb') as f:
        file_data = f.read()

    # Compute integrity hash of original data
    file_hash = compute_sha256(file_data)

    output_file = args.output if args.output else input_file + '.enc'

    # Determine encryption mode
    if args.pubkey:
        # Stage 4: RSA hybrid encryption
        print(f"Encrypting with RSA hybrid (AES-256-CBC + RSA-OAEP)...")
        encrypted = hybrid_encrypt(file_data, args.pubkey)
        # Write: MAGIC + hash (32 bytes hex as bytes) + encrypted
        with open(output_file, 'wb') as f:
            f.write(MAGIC_RSA)
            f.write(file_hash.encode('utf-8'))  # 64 hex chars
            f.write(encrypted)
        print(f"Encrypted (RSA hybrid): {output_file}")

    elif args.password:
        # Stage 3: AES-256-CBC encryption
        print(f"Encrypting with AES-256-CBC...")
        encrypted = aes_encrypt(file_data, args.password)
        # Write: MAGIC + hash (64 hex chars) + encrypted
        with open(output_file, 'wb') as f:
            f.write(MAGIC_AES)
            f.write(file_hash.encode('utf-8'))  # 64 hex chars
            f.write(encrypted)
        print(f"Encrypted (AES-256-CBC): {output_file}")

    else:
        # Stage 1 & 2: Caesar cipher
        shift = args.shift if args.shift is not None else 3
        text = file_data.decode('utf-8')
        ciphertext = caesar_encrypt(text, shift)

        # Store as JSON with hash
        output_data = {
            "method": "caesar",
            "shift": shift,
            "hash": file_hash,
            "ciphertext": ciphertext
        }
        with open(output_file, 'w') as f:
            json.dump(output_data, f, indent=2)
        print(f"Encrypted (Caesar, shift={shift}): {output_file}")

    if args.verify:
        print(f"SHA-256 hash stored for integrity verification: {file_hash}")


def cmd_decrypt(args):
    """Handle the decrypt command."""
    input_file = args.file

    if not os.path.exists(input_file):
        print(f"ERROR: File '{input_file}' not found.")
        sys.exit(1)

    # Read file header to determine format
    with open(input_file, 'rb') as f:
        header = f.read(8)
        f.seek(0)
        raw_data = f.read()

    output_file = args.output if args.output else input_file.replace('.enc', '.dec')

    if header == MAGIC_RSA:
        # Stage 4: RSA hybrid decryption
        if not args.privkey:
            print("ERROR: --privkey required for RSA hybrid decryption.")
            sys.exit(1)
        print("Decrypting with RSA hybrid...")
        stored_hash = raw_data[8:72].decode('utf-8')
        enc_data = raw_data[72:]
        plaintext = hybrid_decrypt(enc_data, args.privkey)

        # Verify integrity
        computed_hash = compute_sha256(plaintext)
        if args.verify or True:  # Always verify
            if computed_hash == stored_hash:
                print("INTEGRITY CHECK: PASSED - File has not been tampered with.")
            else:
                print("WARNING: INTEGRITY CHECK FAILED! File may have been tampered with!")
                print(f"  Expected:  {stored_hash}")
                print(f"  Computed:  {computed_hash}")

        with open(output_file, 'wb') as f:
            f.write(plaintext)
        print(f"Decrypted: {output_file}")

    elif header == MAGIC_AES:
        # Stage 3: AES decryption
        if not args.password:
            print("ERROR: --password required for AES decryption.")
            sys.exit(1)
        print("Decrypting with AES-256-CBC...")
        stored_hash = raw_data[8:72].decode('utf-8')
        enc_data = raw_data[72:]

        try:
            plaintext = aes_decrypt(enc_data, args.password)
        except Exception as e:
            print(f"ERROR: Decryption failed. Wrong password? ({e})")
            sys.exit(1)

        # Verify integrity
        computed_hash = compute_sha256(plaintext)
        if computed_hash == stored_hash:
            print("INTEGRITY CHECK: PASSED - File has not been tampered with.")
        else:
            print("WARNING: INTEGRITY CHECK FAILED! File may have been tampered with!")
            print(f"  Expected:  {stored_hash}")
            print(f"  Computed:  {computed_hash}")

        with open(output_file, 'wb') as f:
            f.write(plaintext)
        print(f"Decrypted: {output_file}")

    else:
        # Try Caesar (JSON format)
        try:
            with open(input_file, 'r') as f:
                data = json.load(f)
        except (json.JSONDecodeError, UnicodeDecodeError):
            print("ERROR: Unrecognized file format.")
            sys.exit(1)

        if data.get("method") == "caesar":
            shift = data["shift"]
            ciphertext = data["ciphertext"]
            stored_hash = data.get("hash", "")
            plaintext = caesar_decrypt(ciphertext, shift)

            # Verify integrity
            if stored_hash:
                computed_hash = compute_sha256(plaintext)
                if computed_hash == stored_hash:
                    print("INTEGRITY CHECK: PASSED - File has not been tampered with.")
                else:
                    print("WARNING: INTEGRITY CHECK FAILED! File may have been tampered with!")
                    print(f"  Expected:  {stored_hash}")
                    print(f"  Computed:  {computed_hash}")

            with open(output_file, 'w') as f:
                f.write(plaintext)
            print(f"Decrypted (Caesar, shift={shift}): {output_file}")
        else:
            print("ERROR: Unrecognized encryption method.")
            sys.exit(1)


def cmd_crack(args):
    """Crack Caesar cipher using frequency analysis."""
    if args.file:
        with open(args.file, 'r') as f:
            ciphertext = f.read()
    elif args.text:
        ciphertext = args.text
    else:
        print("ERROR: Provide --file or --text to crack.")
        sys.exit(1)

    print("=" * 60)
    print("FREQUENCY ANALYSIS - Caesar Cipher Cracker")
    print("=" * 60)
    print(f"\nCiphertext: {ciphertext[:80]}{'...' if len(ciphertext) > 80 else ''}\n")

    results = frequency_analysis(ciphertext)

    print("Top 3 most likely plaintexts:\n")
    for i, (shift, plaintext) in enumerate(results, 1):
        print(f"  #{i} (shift = {shift}):")
        print(f"      {plaintext[:100]}{'...' if len(plaintext) > 100 else ''}")
        print()

    print("=" * 60)


def cmd_keygen(args):
    """Generate RSA keypair."""
    output_dir = args.output_dir if args.output_dir else "."
    generate_rsa_keypair(output_dir)


def main():
    parser = argparse.ArgumentParser(
        description="CryptoVault — Command-line file encryption tool",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    subparsers = parser.add_subparsers(dest='command', help='Available commands')

    # Encrypt command
    enc_parser = subparsers.add_parser('encrypt', help='Encrypt a file')
    enc_parser.add_argument('file', help='Input file to encrypt')
    enc_parser.add_argument('--shift', type=int, help='Caesar cipher shift (Stage 1)')
    enc_parser.add_argument('--password', type=str, help='Password for AES encryption (Stage 3)')
    enc_parser.add_argument('--pubkey', type=str, help='RSA public key file for hybrid encryption (Stage 4)')
    enc_parser.add_argument('--output', '-o', type=str, help='Output file path')
    enc_parser.add_argument('--verify', action='store_true', help='Show integrity hash (Stage 2)')

    # Decrypt command
    dec_parser = subparsers.add_parser('decrypt', help='Decrypt a file')
    dec_parser.add_argument('file', help='Encrypted file to decrypt')
    dec_parser.add_argument('--password', type=str, help='Password for AES decryption (Stage 3)')
    dec_parser.add_argument('--privkey', type=str, help='RSA private key file for hybrid decryption (Stage 4)')
    dec_parser.add_argument('--output', '-o', type=str, help='Output file path')
    dec_parser.add_argument('--verify', action='store_true', help='Verify integrity hash (Stage 2)')

    # Crack command
    crack_parser = subparsers.add_parser('crack', help='Crack Caesar cipher via frequency analysis')
    crack_parser.add_argument('--file', type=str, help='File containing ciphertext')
    crack_parser.add_argument('--text', type=str, help='Ciphertext string to crack')

    # Keygen command (Stage 4)
    keygen_parser = subparsers.add_parser('keygen', help='Generate RSA keypair (Stage 4)')
    keygen_parser.add_argument('--output-dir', type=str, default='.', help='Directory to save keys')

    args = parser.parse_args()

    if args.command == 'encrypt':
        cmd_encrypt(args)
    elif args.command == 'decrypt':
        cmd_decrypt(args)
    elif args.command == 'crack':
        cmd_crack(args)
    elif args.command == 'keygen':
        cmd_keygen(args)
    else:
        parser.print_help()


if __name__ == '__main__':
    main()
