# cybersecurity-tasks

Here's a summary of what was built in /Users/aditi/CryptoVault/:
CryptoVault — Complete <br> 

Files created: <br> 
- cryptovault.py — The full tool implementing all 4 stages <br> 
- WRITEUP.md — Documentation answering all the write-up questions <br> 
- venv/ — Python virtual environment with the cryptography library <br> 

<br> ****
All stages tested and verified:

<br> 
Stage	Feature	Status
<br> 
1	Caesar encrypt/decrypt + frequency analysis cracker	Passed
<br> 
2	SHA-256 integrity verification (tamper detection)	Passed
<br> 
3	AES-256-CBC with PBKDF2 key derivation + random IV	Passed
<br> 
4 RSA-2048 hybrid encryption (OAEP) + wrong-key rejection	Passed
<br> 
Cracked ciphertext: Shift = 3 → "The quick brown fox jumps over the lazy dog. Cryptography is the art of writing and solving codes."

<br>  <br> 

Quick start:
cd ~/CryptoVault <br> 
source venv/bin/activate <br> 
python cryptovault.py encrypt file.txt --shift 7          # Caesar <br> 
python cryptovault.py encrypt file.txt --password "pass"  # AES <br> 
python cryptovault.py keygen && python cryptovault.py encrypt file.txt --pubkey public.pem  # RSA hybrid <br> 
