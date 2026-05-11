"""
encryption.py — All cryptographic operations live here.
==========================================================

WHY THIS FILE EXISTS SEPARATELY:
  Good security practice is "separation of concerns" — the crypto
  logic should be isolated from the web logic so it can be audited,
  tested, and reasoned about independently.

SECURITY ARCHITECTURE (Zero-Knowledge):
  The server NEVER stores your master password or your encryption key.
  Here is the full chain:

                    Your Master Password
                           │
               ┌───────────┴───────────┐
               │ PBKDF2 (600k rounds)  │ PBKDF2 (600k rounds)
               │ + auth_salt           │ + enc_salt
               │                       │
               ▼                       ▼
          Auth Hash               Encryption Key
      (stored in DB,              (NOT stored anywhere
       as bcrypt hash)             only lives in RAM
               │                   during your session)
               ▼                       │
    Server verifies login              ▼
    by comparing hashes        AES-256-GCM encrypt/decrypt
                               all vault items

  If the database is stolen, the attacker gets:
    - Encrypted blobs  → useless without the key
    - Auth hash        → useless for decryption (mathematically separate)
    - Salts            → useless without the password + PBKDF2 computation

LIBRARIES USED:
  - hashlib         → PBKDF2 (Python standard library)
  - cryptography    → AES-256-GCM (pip install cryptography)
  - secrets         → Cryptographically secure random numbers
"""

import os
import base64
import hashlib
import hmac
import secrets
import string
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# ─── CONSTANTS ────────────────────────────────────────────────────────────────

PBKDF2_ITERATIONS = 600_000   # OWASP recommended minimum for PBKDF2-SHA256
KEY_LENGTH        = 32        # 256 bits → AES-256
SALT_LENGTH       = 32        # 256 bits of randomness per salt
NONCE_LENGTH      = 12        # 96 bits → standard for AES-GCM


# ─── SALT GENERATION ─────────────────────────────────────────────────────────

def generate_salt() -> bytes:
    """
    Generate a cryptographically random 32-byte salt.

    A salt is random data added to the password before hashing.
    Purpose: two users with the same password get DIFFERENT hashes.
    This defeats pre-computed "rainbow table" attacks.

    IMPORTANT: We generate TWO different salts per user at registration:
      - auth_salt  → used to derive the auth hash (for login verification)
      - enc_salt   → used to derive the encryption key (for vault items)

    Having two separate salts means knowing the auth hash gives
    an attacker ZERO information about the encryption key.
    """
    return os.urandom(SALT_LENGTH)


# ─── KEY DERIVATION ───────────────────────────────────────────────────────────

def derive_auth_hash(password: str, salt: bytes) -> bytes:
    """
    Derive the authentication hash from the master password.

    This is the value we compare at login time to verify the password.
    We store this in the database (alongside its salt).

    PBKDF2-HMAC-SHA256 works like this:
      Round 1: HMAC-SHA256(password, salt || 1) → block_1
      Round 2: HMAC-SHA256(password, block_1)   → block_2
      ...
      Round 600,000: → final_hash

    Each round is chained, forcing sequential computation.
    A GPU cannot parallelize this to speed up brute-force attacks.

    Result: 32 bytes (256 bits) that look like random noise.
    """
    return hashlib.pbkdf2_hmac(
        hash_name  = 'sha256',
        password   = password.encode('utf-8'),
        salt       = salt,
        iterations = PBKDF2_ITERATIONS,
        dklen      = KEY_LENGTH
    )


def derive_enc_key(password: str, salt: bytes) -> bytes:
    """
    Derive the AES-256 encryption key from the master password.

    Identical algorithm to derive_auth_hash but with a DIFFERENT salt.
    The two outputs are mathematically independent.

    CRITICAL: This key is NEVER stored anywhere persistent.
    It lives only in server RAM for the duration of the user's session.
    When the user logs out (or the server restarts), it's gone.

    Returns: 32 raw bytes suitable for use as an AES-256 key.
    """
    return hashlib.pbkdf2_hmac(
        hash_name  = 'sha256',
        password   = password.encode('utf-8'),
        salt       = salt,
        iterations = PBKDF2_ITERATIONS,
        dklen      = KEY_LENGTH
    )


def verify_password(password: str, salt: bytes, stored_hash: bytes) -> bool:
    """
    Safely compare a candidate password against the stored hash.

    We use hmac.compare_digest() instead of == to prevent timing attacks.

    TIMING ATTACK: If we used ==, Python returns False the moment it
    finds the first mismatched byte. An attacker measuring response time
    could determine how many bytes matched, gradually narrowing the search.
    hmac.compare_digest() always takes the same time regardless of where
    the mismatch occurs.
    """
    candidate = derive_auth_hash(password, salt)
    return hmac.compare_digest(candidate, stored_hash)


# ─── AES-256-GCM ENCRYPTION ───────────────────────────────────────────────────

def encrypt(plaintext: str, key: bytes) -> str:
    """
    Encrypt a string using AES-256-GCM.

    AES-GCM is "authenticated encryption" — it does TWO things at once:
      1. CONFIDENTIALITY: scrambles the data so only someone with the
         key can read it (AES in counter mode)
      2. INTEGRITY: appends a 16-byte authentication tag so any
         tampering with the ciphertext is detected on decryption

    THE NONCE (Number Used Once):
      AES-GCM requires a 12-byte random value called a nonce.
      RULE: Never reuse the same nonce with the same key.
      Reusing a nonce completely breaks AES-GCM security.
      We generate a fresh random nonce for EVERY encryption call.

    OUTPUT FORMAT: base64( nonce[12 bytes] + ciphertext + auth_tag[16 bytes] )
      The nonce is prepended to the ciphertext so we can extract it
      at decryption time. It doesn't need to be secret.

    Args:
        plaintext: The string to encrypt (e.g., "MyPassword123!")
        key:       32-byte encryption key from derive_enc_key()

    Returns:
        A base64-encoded string safe to store in the database.
    """
    aesgcm = AESGCM(key)
    nonce  = os.urandom(NONCE_LENGTH)

    # Encrypt: returns ciphertext + 16-byte auth tag appended automatically
    ciphertext = aesgcm.encrypt(
        nonce,
        plaintext.encode('utf-8'),
        None   # No additional authenticated data (AAD) for this MVP
    )

    # Pack: nonce + ciphertext, then base64-encode for safe DB storage
    return base64.b64encode(nonce + ciphertext).decode('utf-8')


def decrypt(encrypted_b64: str, key: bytes) -> str:
    """
    Decrypt an AES-256-GCM encrypted string.

    AES-GCM automatically verifies the authentication tag during decryption.
    If the ciphertext was tampered with, it raises InvalidTag — we never
    get partial or corrupted plaintext back.

    Args:
        encrypted_b64: The base64 string from the database
        key:           The same 32-byte key used for encryption

    Returns:
        The original plaintext string.

    Raises:
        ValueError if decryption fails (wrong key or tampered data)
        cryptography.exceptions.InvalidTag if authentication fails
    """
    raw_bytes  = base64.b64decode(encrypted_b64)
    nonce      = raw_bytes[:NONCE_LENGTH]        # First 12 bytes
    ciphertext = raw_bytes[NONCE_LENGTH:]        # Everything after

    aesgcm = AESGCM(key)
    try:
        plaintext_bytes = aesgcm.decrypt(nonce, ciphertext, None)
        return plaintext_bytes.decode('utf-8')
    except Exception:
        raise ValueError("Decryption failed — wrong key or corrupted data.")


# ─── PASSWORD GENERATOR ───────────────────────────────────────────────────────

def generate_strong_password(
    length:    int  = 20,
    uppercase: bool = True,
    lowercase: bool = True,
    digits:    bool = True,
    symbols:   bool = True
) -> str:
    """
    Generate a cryptographically random password.

    Uses secrets.choice() which is backed by os.urandom() — the OS's
    entropy pool (hardware noise, timing jitter, etc.).

    DO NOT use random.choice() for passwords — the standard random
    module is a deterministic PRNG, not suitable for security use.

    We also enforce that at least one character from each enabled
    category appears (avoids passwords like "aaaaabbbbb").
    """
    if not any([uppercase, lowercase, digits, symbols]):
        raise ValueError("Select at least one character type")

    pool = ''
    required_chars = []

    if uppercase:
        pool += string.ascii_uppercase
        required_chars.append(secrets.choice(string.ascii_uppercase))
    if lowercase:
        pool += string.ascii_lowercase
        required_chars.append(secrets.choice(string.ascii_lowercase))
    if digits:
        pool += string.digits
        required_chars.append(secrets.choice(string.digits))
    if symbols:
        sym = '!@#$%^&*()_+-=[]{}|;:,.<>?'
        pool += sym
        required_chars.append(secrets.choice(sym))

    # Fill remaining length with random pool characters
    remaining = length - len(required_chars)
    rest = [secrets.choice(pool) for _ in range(remaining)]

    # Shuffle so required chars aren't always at the start
    password_chars = required_chars + rest
    secrets.SystemRandom().shuffle(password_chars)

    return ''.join(password_chars)


def estimate_entropy(password: str) -> dict:
    """
    Estimate password entropy in bits and return a strength rating.

    Entropy formula: E = L × log₂(N)
      L = password length
      N = size of the character pool used

    The result tells you how many guesses an attacker needs on average:
      50 bits → ~1 quadrillion guesses
      70 bits → ~1 sextillion guesses
    """
    pool = 0
    if any(c in string.ascii_uppercase for c in password): pool += 26
    if any(c in string.ascii_lowercase for c in password): pool += 26
    if any(c in string.digits           for c in password): pool += 10
    if any(c not in string.ascii_letters + string.digits for c in password): pool += 32

    import math
    entropy = round(len(password) * math.log2(pool)) if pool else 0

    if entropy < 40:   strength, color = 'Weak',   'red'
    elif entropy < 60: strength, color = 'Fair',   'yellow'
    elif entropy < 80: strength, color = 'Good',   'blue'
    else:              strength, color = 'Strong', 'green'

    return {'bits': entropy, 'strength': strength, 'color': color}