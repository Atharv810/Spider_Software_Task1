# CryptoVault Write-Up

## Stage 1: Caesar Lock

### Why is Caesar trivially breakable?

Caesar cipher has only **25 possible keys** (shifts 1-25). An attacker can brute-force all of them in milliseconds. Furthermore, it is a simple substitution cipher — each letter always maps to the same letter — which preserves the statistical patterns of the original language.

### What property of language makes frequency analysis work?

**Non-uniform letter distribution.** In English, letters like 'e', 't', 'a', 'o', 'i', 'n' appear far more frequently than 'z', 'q', 'x'. Since Caesar cipher preserves these relative frequencies (just shifted), an attacker can compare the frequency distribution of ciphertext letters against the known English distribution to deduce the shift. This works for any monoalphabetic substitution cipher, not just Caesar.

### Cracked Ciphertext Result

The ciphertext `"Wkh txlfn eurzq ira mxpsv ryhu wkh odcb grj..."` was encrypted with **shift = 3**.

Decrypted plaintext: **"The quick brown fox jumps over the lazy dog. Cryptography is the art of writing and solving codes."**

---

## Stage 2: Hash Guard

### Why do you need both encryption (confidentiality) and hashing (integrity)?

- **Encryption** prevents unauthorized reading of data (confidentiality), but an attacker can still **modify** the ciphertext. The decryption will succeed but produce garbage — and you won't know it was tampered with.

- **Hashing** detects modifications (integrity). By storing a SHA-256 hash of the original plaintext inside the encrypted output, we can verify after decryption that the data is intact.

Without integrity checking, an attacker could flip bits in the ciphertext (a "bit-flipping attack" in CBC mode) to strategically alter the plaintext without the recipient knowing. The hash acts as a checksum that catches any corruption or tampering.

**Real-world note:** In production systems, HMAC (keyed hash) or authenticated encryption modes (GCM, ChaCha20-Poly1305) are preferred over a plain hash, because they prevent an attacker from recomputing the hash after modification.

---

## Stage 3: AES Upgrade

### What goes wrong if the IV is reused?

In CBC mode, the IV is XORed with the first block of plaintext before encryption. If the same IV and key encrypt two different messages:

1. **Identical first blocks** produce identical first ciphertext blocks, leaking that the messages share a prefix.
2. An attacker can XOR the two ciphertexts to obtain the XOR of the two plaintexts, enabling known-plaintext attacks.
3. Patterns emerge that break the semantic security guarantee — the attacker can distinguish between encryptions of different messages.

A **fresh random IV per encryption** ensures that even identical plaintexts produce different ciphertexts every time.

### What does PBKDF2 add that a plain hash doesn't?

PBKDF2 (Password-Based Key Derivation Function 2) provides three critical protections:

1. **Salt** — A random salt means the same password produces different keys each time, defeating rainbow table attacks.
2. **Iteration count** (100,000 in our implementation) — Deliberately slow computation makes brute-force password guessing expensive. A plain SHA-256 hash can be computed billions of times per second; PBKDF2 with 100K iterations reduces this by 5 orders of magnitude.
3. **Fixed output length** — Produces exactly the key size needed (256 bits) regardless of password length.

A plain `SHA-256(password)` would be vulnerable to dictionary attacks and GPU-accelerated brute force.

---

## Stage 4: RSA Key Exchange

### Why can't we encrypt the whole file with RSA directly?

1. **Size limitation:** RSA-2048 with OAEP padding can only encrypt at most 190 bytes per operation. A file larger than this would need to be split into blocks, which is extremely slow and complex.
2. **Performance:** RSA encryption is ~1000x slower than AES for bulk data. A 1 MB file would take seconds with RSA vs. microseconds with AES.
3. **Security concerns:** Using RSA for large data directly (with ECB-like block-by-block processing) introduces pattern leakage and other vulnerabilities.

### How does this hybrid approach relate to how HTTPS works?

Our hybrid scheme mirrors the TLS/HTTPS handshake:

| CryptoVault (Stage 4)               | HTTPS/TLS                              |
|--------------------------------------|----------------------------------------|
| Generate random AES key              | Client generates session key           |
| Encrypt AES key with RSA public key  | Client encrypts session key with server's public key (or uses Diffie-Hellman) |
| Encrypt file data with AES           | Bulk data encrypted with session key (AES-GCM) |
| Decrypt AES key with RSA private key | Server recovers session key with its private key |

This gives us:
- **Efficiency**: Bulk data uses fast symmetric encryption (AES)
- **Key distribution**: Only the small AES key needs asymmetric encryption (RSA)
- **Forward secrecy** (in modern TLS): Each session gets a unique key, so compromising the long-term key doesn't expose past sessions

---

## Usage Reference

```bash
# Stage 1: Caesar cipher
python cryptovault.py encrypt message.txt --shift 7
python cryptovault.py decrypt message.txt.enc
python cryptovault.py crack --text "Wkh txlfn..."

# Stage 2: Verify integrity
python cryptovault.py encrypt message.txt --shift 7 --verify
python cryptovault.py decrypt message.txt.enc --verify

# Stage 3: AES-256-CBC
python cryptovault.py encrypt secret.pdf --password "MyPassword123"
python cryptovault.py decrypt secret.pdf.enc --password "MyPassword123"

# Stage 4: RSA Hybrid
python cryptovault.py keygen
python cryptovault.py encrypt secret.pdf --pubkey public.pem
python cryptovault.py decrypt secret.pdf.enc --privkey private.pem
```

## Dependencies

- Python 3.8+
- `cryptography` library (for Stages 3 & 4): `pip install cryptography`
