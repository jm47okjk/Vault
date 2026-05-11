# VaultLock — Complete Project Explanation
### "How does every single line actually work?"

This document explains the **entire project from the ground up** — the theory, the Python, and the HTML. Read it like a book, in order.

---

## Table of Contents

1. [The Big Picture — What Actually Happens](#1-the-big-picture)
2. [Project Structure — Why Files Are Separated](#2-project-structure)
3. [encryption.py — The Security Engine](#3-encryptionpy)
4. [database.py — How Data is Stored](#4-databasepy)
5. [app.py — The Web Server (The Brain)](#5-apppy)
6. [login.html — The Frontend Auth Page](#6-loginhtml)
7. [dashboard.html — The Vault Interface](#7-dashboardhtml)
8. [Full Walkthroughs — What Happens Step by Step](#8-full-walkthroughs)
9. [How the Files Talk to Each Other](#9-how-the-files-connect)
10. [Security Summary — What You Can Say at Your Internship](#10-security-summary)

---

## 1. The Big Picture

Before touching any code, you need to understand the **one central promise** this app makes:

> **The database only ever stores scrambled data. Even if someone steals the database file, they cannot read any passwords.**

How? Through a chain:

```
Your Master Password
       │
       ▼  (PBKDF2 — a very slow hashing function, run 600,000 times)
       │
  ┌────┴────────────────────┐
  │                         │
  ▼                         ▼
Auth Hash               Encryption Key
  │                         │
  │ stored in DB            │ NEVER stored — lives only in RAM
  │ (hashed again)          │ while you're logged in
  ▼                         ▼
Server checks          Used to encrypt/decrypt
login attempts         every item in your vault
```

The two arrows are independent. Knowing one does not help you calculate the other, because they use different random salts (explained in section 3).

---

## 2. Project Structure

```
vault/
│
├── encryption.py     ← Pure Python. No web stuff. Just crypto math.
├── database.py       ← Pure Python. No web stuff. Just SQLite reads/writes.
├── app.py            ← Flask web server. Imports the two above. Handles HTTP.
│
└── templates/
    ├── login.html    ← The registration and login UI.
    └── dashboard.html ← The main vault UI.
```

**Why three separate Python files instead of one?**

This pattern is called "separation of concerns." Each file has one job:

- `encryption.py` can be tested in isolation. You could import it into a script and encrypt something without starting a web server.
- `database.py` can be tested in isolation. You could call `get_credentials(user_id)` without any web requests.
- `app.py` just coordinates — it calls the other two and returns HTML responses.

This also makes security auditing easier. If someone is reviewing the cryptography, they only need to read `encryption.py`.

---

## 3. encryption.py

### 3.1 — What a "salt" is and why we need TWO of them

At the top of the file:

```python
PBKDF2_ITERATIONS = 600_000
KEY_LENGTH        = 32        # 256 bits
SALT_LENGTH       = 32        # 256 bits
NONCE_LENGTH      = 12        # 96 bits
```

These are configuration constants. Separating them at the top means if OWASP raises the recommended iterations to 800,000 next year, you change one line.

A **salt** is a random blob of bytes added to the password before hashing. The function that generates one:

```python
def generate_salt() -> bytes:
    return os.urandom(SALT_LENGTH)
```

`os.urandom()` asks the **operating system** for random bytes. The OS gathers entropy from hardware events (CPU timing jitter, disk activity, network packets). This is cryptographically random — not predictable like `random.random()`.

**Why two salts?** We generate `auth_salt` and `enc_salt` separately at registration. This means:

```
PBKDF2("mypassword", auth_salt, 600_000) → auth_hash   (one value)
PBKDF2("mypassword", enc_salt,  600_000) → enc_key     (completely different value)
```

Even though the password is the same, the two outputs are completely unrelated because the salts differ. This matters because:
- The `auth_hash` is stored in the database. It could leak.
- If both hashes shared a salt, an attacker could derive `enc_key` from `auth_hash`.
- With separate salts, they cannot. `auth_hash` gives zero information about `enc_key`.

---

### 3.2 — derive_auth_hash() — for login verification

```python
def derive_auth_hash(password: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac(
        hash_name  = 'sha256',
        password   = password.encode('utf-8'),
        salt       = salt,
        iterations = PBKDF2_ITERATIONS,
        dklen      = KEY_LENGTH
    )
```

Line by line:

- `hashlib.pbkdf2_hmac` — built into Python's standard library. No installation needed.
- `hash_name = 'sha256'` — the underlying hash function used in each round.
- `password.encode('utf-8')` — converts the Python string `"mypassword"` into raw bytes `b"mypassword"`. Hashing functions operate on bytes, not strings.
- `salt = salt` — the random bytes mixed in so two users with the same password get different hashes.
- `iterations = 600_000` — runs the hash 600,000 times in a chain. Each round feeds into the next.
- `dklen = KEY_LENGTH` — the output length: 32 bytes = 256 bits.

**Why 600,000 iterations?** Each iteration is one SHA-256 computation. A modern GPU can compute ~1 billion SHA-256 hashes per second. With 600,000 iterations, checking ONE password guess requires 600,000 operations, limiting that GPU to about 1,666 guesses per second. A random 12-character password has ~60 trillion possible values — that's ~40 million years to brute-force.

---

### 3.3 — derive_enc_key() — for encrypting your vault

```python
def derive_enc_key(password: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac(
        hash_name  = 'sha256',
        password   = password.encode('utf-8'),
        salt       = salt,
        iterations = PBKDF2_ITERATIONS,
        dklen      = KEY_LENGTH
    )
```

This function looks identical to `derive_auth_hash` — and it is. The difference is **which salt you pass in**. At registration, we call it with `enc_salt`. At login, we call it with the same `enc_salt` fetched from the database, and we always get the same 32 bytes back because PBKDF2 is deterministic: same inputs → same output, always.

**This key is never stored anywhere.** It lives in Python RAM in the `_sessions` dictionary in `app.py` and disappears when the server restarts or the user logs out.

---

### 3.4 — verify_password() — safe comparison

```python
def verify_password(password: str, salt: bytes, stored_hash: bytes) -> bool:
    candidate = derive_auth_hash(password, salt)
    return hmac.compare_digest(candidate, stored_hash)
```

`hmac.compare_digest()` instead of `==` — this is a subtle but important security detail.

If you use `==`, Python compares bytes one at a time and returns `False` the instant it finds a mismatch. If an attacker can measure response time with nanosecond precision, they can tell how many leading bytes matched: more matches → slightly longer comparison → slightly slower response. By guessing one byte at a time, they could reconstruct the hash in 32 × 256 = 8,192 guesses instead of 2^256. This is called a **timing attack**.

`hmac.compare_digest()` always takes the same time regardless of where the mismatch is. The execution time leaks no information.

---

### 3.5 — encrypt() — AES-256-GCM

```python
def encrypt(plaintext: str, key: bytes) -> str:
    aesgcm = AESGCM(key)
    nonce  = os.urandom(NONCE_LENGTH)

    ciphertext = aesgcm.encrypt(
        nonce,
        plaintext.encode('utf-8'),
        None
    )

    return base64.b64encode(nonce + ciphertext).decode('utf-8')
```

**What AES-256-GCM actually does:**

AES stands for Advanced Encryption Standard — the encryption algorithm used by governments, banks, and militaries worldwide. "256" means the key is 256 bits. "GCM" is the mode of operation, which adds authentication on top of encryption.

Two things happen at once in GCM:
1. **Confidentiality**: the plaintext is scrambled using AES in counter mode. Without the key, it looks like random noise.
2. **Integrity**: a 16-byte authentication tag is appended. On decryption, AES-GCM recomputes the tag. If a single bit of the ciphertext was changed by anyone, the tags won't match and decryption fails with an error. You never get corrupted or partially decrypted data.

**The nonce (Number Used Once):**

```python
nonce = os.urandom(NONCE_LENGTH)  # 12 random bytes
```

AES-GCM requires a 12-byte random value for each encryption call. The critical rule: **never use the same nonce twice with the same key**. If you do, AES-GCM's mathematical security guarantee breaks entirely — an attacker could recover the key. By generating a fresh random nonce on every call with `os.urandom()`, this is never a problem.

**The output format:**

```python
return base64.b64encode(nonce + ciphertext).decode('utf-8')
```

We concatenate the nonce (12 bytes) + ciphertext + auth tag (16 bytes automatically appended by the library), then base64-encode it. Base64 converts binary bytes into printable ASCII text so it can be stored in a text column in SQLite.

At decryption, the first 12 bytes are the nonce. We know this because nonces are always exactly 12 bytes. Everything after is the ciphertext + tag.

---

### 3.6 — decrypt() — reversing the process

```python
def decrypt(encrypted_b64: str, key: bytes) -> str:
    raw_bytes  = base64.b64decode(encrypted_b64)
    nonce      = raw_bytes[:NONCE_LENGTH]
    ciphertext = raw_bytes[NONCE_LENGTH:]

    aesgcm = AESGCM(key)
    try:
        plaintext_bytes = aesgcm.decrypt(nonce, ciphertext, None)
        return plaintext_bytes.decode('utf-8')
    except Exception:
        raise ValueError("Decryption failed — wrong key or corrupted data.")
```

- `base64.b64decode()` reverses the base64 encoding back to raw bytes.
- `raw_bytes[:12]` — Python slice syntax. `:12` means "from the start up to (not including) index 12." This extracts the 12-byte nonce.
- `raw_bytes[12:]` — "from index 12 to the end." This is the ciphertext.
- `aesgcm.decrypt()` — decrypts and simultaneously verifies the authentication tag. If the tag is wrong (tampered data or wrong key), it raises an exception before returning anything.
- The `try/except` catches that exception and raises a cleaner error message.

---

### 3.7 — generate_strong_password()

```python
def generate_strong_password(length=20, uppercase=True, lowercase=True, digits=True, symbols=True):
    pool = ''
    required_chars = []

    if uppercase:
        pool += string.ascii_uppercase
        required_chars.append(secrets.choice(string.ascii_uppercase))
    ...

    remaining = length - len(required_chars)
    rest = [secrets.choice(pool) for _ in range(remaining)]

    password_chars = required_chars + rest
    secrets.SystemRandom().shuffle(password_chars)
    return ''.join(password_chars)
```

**`secrets.choice()` vs `random.choice()`:**

Python's `random` module uses the Mersenne Twister algorithm — a pseudo-random number generator whose output is deterministic given the seed. If someone knows or can guess the seed, they can reproduce the sequence.

`secrets` module uses `os.urandom()` — the OS entropy pool. Truly unpredictable. `secrets` is specifically designed for generating passwords, tokens, and cryptographic material.

**The `required_chars` logic:**

If you just filled all 20 characters randomly from the full pool, you might occasionally get a password with no uppercase, no symbols, etc. (unlikely but possible). The code first picks one character from each enabled category, then fills the rest randomly, then shuffles. This guarantees all selected categories are always present.

---

### 3.8 — estimate_entropy()

```python
def estimate_entropy(password: str) -> dict:
    pool = 0
    if any(c in string.ascii_uppercase for c in password): pool += 26
    if any(c in string.ascii_lowercase for c in password): pool += 26
    if any(c in string.digits           for c in password): pool += 10
    if any(c not in string.ascii_letters + string.digits for c in password): pool += 32

    import math
    entropy = round(len(password) * math.log2(pool)) if pool else 0
    ...
```

**Entropy formula: E = L × log₂(N)**

Where:
- `L` = password length
- `N` = size of the character pool used
- The result is in bits

Example: a 20-character password using all four categories (N = 26+26+10+32 = 94):
`E = 20 × log₂(94) = 20 × 6.55 ≈ 131 bits`

This represents the number of binary guesses needed: 2^131 ≈ 2.7 octillion. Uncrackable.

`any(c in string.ascii_uppercase for c in password)` — this is a Python generator expression. It loops over every character `c` in the password and returns `True` if any character is an uppercase letter. If even one uppercase is present, we add 26 to the pool size.

---

## 4. database.py

### 4.1 — SQLite and the DB file

```python
DB_PATH = Path(__file__).parent / 'vault.db'
```

`__file__` is a Python built-in that contains the path of the current file (`database.py`). `.parent` gets its folder. So `DB_PATH` is always `vault.db` in the same folder as the script, regardless of where you run Python from.

SQLite creates the file automatically if it doesn't exist. The entire database is one file. You can email it, copy it, open it in DB Browser for SQLite, and see exactly what it stores.

### 4.2 — init_db() — creating the tables

```python
def init_db() -> None:
    with _connect() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                id          TEXT PRIMARY KEY,
                email       TEXT UNIQUE NOT NULL,
                auth_hash   BLOB NOT NULL,
                auth_salt   BLOB NOT NULL,
                enc_salt    BLOB NOT NULL,
                created_at  TEXT NOT NULL DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS credentials (
                id           TEXT PRIMARY KEY,
                user_id      TEXT NOT NULL,
                site_name    TEXT NOT NULL,
                username     TEXT NOT NULL,
                password_enc TEXT NOT NULL,
                created_at   TEXT NOT NULL DEFAULT (datetime('now')),
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );
        """)
```

`CREATE TABLE IF NOT EXISTS` — safe to call multiple times. If the table exists, it does nothing. If it doesn't exist, it creates it.

**Column types in SQLite:**
- `TEXT` — a string. Used for IDs, emails, encrypted blobs (base64 is ASCII text).
- `BLOB` — raw binary bytes. Used for `auth_hash`, `auth_salt`, `enc_salt` (which are raw bytes, not base64).
- `PRIMARY KEY` — uniquely identifies each row. Two rows can't have the same id.
- `UNIQUE NOT NULL` — the email column can't be repeated and can't be empty.

**FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE** — this means if a user is deleted, all their credentials are automatically deleted too. `ON DELETE CASCADE` handles cleanup.

### 4.3 — Why credentials stores only encrypted data

Look at the credentials table columns: `site_name TEXT`, `username TEXT`, `password_enc TEXT`. All three are **encrypted blobs** stored as base64 strings. The database does not know these are websites, usernames, or passwords. To the database they look like:

```
site_name:    "3k+mX8fA...:YzPqR9lBc..."
username:     "aB7nQw2M...:KpLx4RvT..."
password_enc: "nJf8Yt6H...:WqMs3Ck1..."
```

Random-looking text. Completely unreadable without the encryption key.

### 4.4 — get_credential_by_id() — the security check

```python
def get_credential_by_id(cred_id: str, user_id: str) -> sqlite3.Row | None:
    with _connect() as conn:
        return conn.execute(
            "SELECT * FROM credentials WHERE id = ? AND user_id = ?",
            (cred_id, user_id)
        ).fetchone()
```

The `AND user_id = ?` part is critical. Without it, a logged-in user could call `/api/reveal/SOME_OTHER_USERS_CREDENTIAL_ID` and get back someone else's password. This attack is called **IDOR** (Insecure Direct Object Reference). The two-condition WHERE clause means you can only fetch a credential if the id belongs to you.

The `?` placeholders and the tuple `(cred_id, user_id)` are **parameterized queries** — they prevent SQL injection. Never do `f"WHERE id = '{cred_id}'"`. If `cred_id` was `'; DROP TABLE credentials; --`, you'd delete your whole database.

---

## 5. app.py

### 5.1 — Flask basics

Flask is a "micro web framework." A web framework handles the boring parts of web servers: receiving HTTP requests, parsing headers, sending responses. You write the logic; Flask handles the plumbing.

```python
from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))
```

- `Flask(__name__)` — creates the app. `__name__` tells Flask where to look for templates.
- `app.secret_key` — used to sign the browser cookie. Without a secret key, Flask sessions don't work.
- `os.environ.get('SECRET_KEY', ...)` — in production, you set `SECRET_KEY` as an environment variable. In development, it falls back to a random token.

### 5.2 — The session system

This is the most important design in `app.py`. There are two layers:

**Layer 1 — The browser cookie (Flask's `session` dict):**

```python
session['token'] = token
```

Flask signs this cookie with `secret_key` using HMAC. The browser stores it and sends it on every request. The content is just a random token string — nothing sensitive.

**Layer 2 — The server-side store (`_sessions` dict):**

```python
_sessions: dict[str, dict] = {}

_sessions[token] = {
    'user_id': user_id,
    'email':   email,
    'enc_key': enc_key,   # the 32-byte encryption key
}
```

This is a plain Python dictionary in RAM. The encryption key lives here — it never goes to the browser. When you call `_get_sess()`, it reads the token from the cookie, looks it up in `_sessions`, and returns the associated data (including `enc_key`).

**Why not store the key in the cookie?** Cookies are sent to the server on every request. If an attacker intercepts one (via a man-in-the-middle attack, XSS, or logging), they'd get the encryption key directly. By keeping the key server-side, a stolen cookie only grants access to the session — not the raw encryption key.

### 5.3 — The login_required decorator

```python
def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not _get_sess():
            flash('Please log in to access your vault.', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return wrapper
```

A **decorator** is a function that wraps another function to add behaviour. When you write:

```python
@login_required
def dashboard():
    ...
```

Python translates this to `dashboard = login_required(dashboard)`. Now every time the `/dashboard` route is called, `login_required`'s wrapper runs first. If `_get_sess()` returns `None` (no valid session), the wrapper redirects to login and never calls the real `dashboard` function. If the session is valid, it calls `f(*args, **kwargs)` — the original function with its original arguments.

`@wraps(f)` preserves the original function's name and docstring, which Flask uses internally.

### 5.4 — The register route

```python
@app.route('/register', methods=['POST'])
def register():
    email    = request.form.get('email', '').strip().lower()
    password = request.form.get('password', '')
    confirm  = request.form.get('confirm', '')
```

`@app.route('/register', methods=['POST'])` — this registers the function as the handler for `POST /register`. The `methods=['POST']` means it only handles POST requests (form submissions), not GET.

`request.form.get('email', '')` — `request.form` is a dictionary of the data sent by the HTML form. `.get('email', '')` returns the value of the `email` field, or an empty string if it's missing.

`.strip()` removes leading/trailing whitespace. `.lower()` normalises to lowercase so `Alice@Gmail.COM` and `alice@gmail.com` are treated as the same email.

```python
    auth_salt = generate_salt()   # random 32 bytes
    enc_salt  = generate_salt()   # different random 32 bytes

    auth_hash = derive_auth_hash(password, auth_salt)
    enc_key   = derive_enc_key(password, enc_salt)

    user_id = create_user(email, auth_hash, auth_salt, enc_salt)
```

Notice that `enc_key` is **not** passed to `create_user`. It is never stored in the database.

### 5.5 — The login route

```python
@app.route('/login', methods=['GET', 'POST'])
def login():
    if _get_sess():
        return redirect(url_for('dashboard'))

    if request.method == 'GET':
        return render_template('login.html')
    
    ...
    if not verify_password(password, bytes(user['auth_salt']), bytes(user['auth_hash'])):
        flash('Invalid email or master password.', 'error')
        return render_template('login.html', tab='login')

    enc_key = derive_enc_key(password, bytes(user['enc_salt']))
```

`bytes(user['auth_salt'])` — SQLite returns BLOB columns as a `memoryview` object in Python. `bytes()` converts it to a regular `bytes` object that our functions can work with.

`request.method` — Flask tells you whether the request was a GET (loading the page) or a POST (submitting the form). This pattern handles both from one function.

After login, the encryption key is re-derived. The password and enc_salt always produce the same key, so even though the key was never stored, it can always be recovered from the password.

### 5.6 — The dashboard route

```python
@app.route('/dashboard')
@login_required
def dashboard():
    sess    = _get_sess()
    enc_key = sess['enc_key']
    raw     = get_credentials(sess['user_id'])

    credentials = []
    for row in raw:
        try:
            credentials.append({
                'id':        row['id'],
                'site_name': decrypt(row['site_name'], enc_key),
                'username':  decrypt(row['username'],  enc_key),
                'created_at': row['created_at'][:10],
            })
        except Exception:
            continue
```

For each encrypted row from the database, we decrypt the `site_name` and `username` to display them in the cards. Notice the **password is not decrypted here**. The decrypted password never appears in the initial HTML. It's only fetched when you click the eye icon.

`row['created_at'][:10]` — slices the datetime string `"2024-03-15 14:23:01"` to just `"2024-03-15"`. The `[:10]` means "characters at indices 0 through 9."

### 5.7 — The /api/reveal route

```python
@app.route('/api/reveal/<cred_id>')
@login_required
def api_reveal(cred_id):
    sess = _get_sess()
    row  = get_credential_by_id(cred_id, sess['user_id'])

    if not row:
        return jsonify({'error': 'Not found'}), 404

    plaintext = decrypt(row['password_enc'], sess['enc_key'])
    return jsonify({'password': plaintext})
```

`<cred_id>` in the route — Flask extracts this from the URL. If the request is `GET /api/reveal/abc-123`, then `cred_id = "abc-123"` inside the function.

`jsonify({'password': plaintext})` — returns a JSON HTTP response, like `{"password": "MySecretPw!"}`. The browser's JavaScript receives this as a JavaScript object.

### 5.8 — flash() — user messages

Throughout the routes you see:

```python
flash('Account created! Welcome.', 'success')
flash('Invalid email or master password.', 'error')
```

`flash()` stores a message in the session to be displayed on the next page load. In the HTML templates, `get_flashed_messages(with_categories=true)` retrieves them. After they're read, they're removed. This is how the green "success" and red "error" banners work.

---

## 6. login.html

### 6.1 — Tailwind CSS

```html
<script src="https://cdn.tailwindcss.com"></script>
```

Tailwind is a "utility-first" CSS framework. Instead of writing custom CSS classes, you apply pre-built classes directly to HTML elements. Every class does exactly one thing:

```html
<div class="bg-slate-900 border border-slate-800 rounded-2xl shadow-2xl">
```

- `bg-slate-900` — background colour: a very dark slate
- `border` — adds a 1px border
- `border-slate-800` — colours that border slightly lighter than the background
- `rounded-2xl` — rounds the corners (16px radius)
- `shadow-2xl` — adds a large drop shadow

You build the entire visual design by combining these small classes. There's no separate CSS file to write.

### 6.2 — The tab system

The page has two forms: Login and Register. Only one is visible at a time. The switching is done with JavaScript:

```html
<div id="pane-login" class="p-6">
    <!-- login form here -->
</div>

<div id="pane-register" class="p-6 hidden">
    <!-- register form here -->
</div>
```

The `hidden` class is a Tailwind utility that sets `display: none`.

```javascript
function switchTab(tab) {
    const isLogin = tab === 'login';
    document.getElementById('pane-login').classList.toggle('hidden', !isLogin);
    document.getElementById('pane-register').classList.toggle('hidden', isLogin);
    ...
}
```

`document.getElementById('pane-login')` — finds the HTML element whose `id` is `"pane-login"`.
`.classList.toggle('hidden', !isLogin)` — adds or removes the `hidden` class. The second argument is a boolean: `true` means add the class, `false` means remove it.

So when `isLogin` is `true`: login pane has `hidden` removed (visible), register pane has `hidden` added (invisible).

### 6.3 — The strength meter in registration

```javascript
function calcEntropy(pw) {
    let pool = 0;
    if (/[A-Z]/.test(pw)) pool += 26;
    if (/[a-z]/.test(pw)) pool += 26;
    if (/[0-9]/.test(pw)) pool += 10;
    if (/[^A-Za-z0-9]/.test(pw)) pool += 32;
    return pool ? Math.floor(pw.length * Math.log2(pool)) : 0;
}
```

This is the same formula as Python's `estimate_entropy()` — just rewritten in JavaScript. `/[A-Z]/` is a **regular expression** (regex). `.test(pw)` returns `true` if the password contains at least one uppercase letter. `Math.log2()` is JavaScript's logarithm base 2 function.

The strength bar is updated on every keystroke:

```html
<input ... oninput="updateRegStrength(this.value)" />
```

`oninput` fires every time the input changes. `this.value` is the current text in the field.

```javascript
function updateRegStrength(pw) {
    const bits = calcEntropy(pw);
    bar.style.width = pct + '%';
    bar.style.background = color;
    text.textContent = `Strong — ${bits} bits ✓`;
}
```

`element.style.width` — directly sets the CSS `width` property.
`element.style.background` — sets the CSS `background` colour.
`textContent` — sets the visible text inside an element.
Template literals (backtick strings with `${}`) inject variables: `` `Strong — ${bits} bits` `` produces `"Strong — 131 bits"`.

### 6.4 — Flask Jinja2 template syntax

```html
{% with messages = get_flashed_messages(with_categories=true) %}
  {% if messages %}
    {% for category, message in messages %}
      <div class="... {% if category == 'error' %} bg-red-500/10 {% else %} bg-emerald-500/10 {% endif %}">
        {{ message }}
      </div>
    {% endfor %}
  {% endif %}
{% endwith %}
```

- `{% ... %}` — template logic (conditions, loops, variable assignment)
- `{{ ... }}` — outputs a value to the HTML
- `{% for x in y %}` / `{% endfor %}` — a loop
- `{% if %}` / `{% else %}` / `{% endif %}` — a conditional

Flask processes this on the server before sending the HTML to the browser. The browser never sees the `{% %}` tags — it sees the final HTML.

`bg-red-500/10` — Tailwind shorthand: red colour at 10% opacity. The `/10` is the opacity modifier.

---

## 7. dashboard.html

### 7.1 — Jinja2 loops for the credential cards

```html
{% for cred in credentials %}
  <div class="card credential-card"
       data-site="{{ cred.site_name|lower }}"
       data-user="{{ cred.username|lower }}">

    <div class="..." style="background:{{ ['#312e81','#1e3a5f',...][loop.index0 % 8] }}">
      {{ cred.site_name[0].upper() }}
    </div>

    <p class="font-semibold text-white">{{ cred.site_name }}</p>
    <p class="text-slate-400">{{ cred.username }}</p>
```

- `{% for cred in credentials %}` — loops over the list passed from `app.py`'s `dashboard()` function. One card is rendered per credential.
- `{{ cred.site_name|lower }}` — the `|lower` is a Jinja2 **filter**. It calls `.lower()` on the value.
- `data-site` and `data-user` — HTML `data-*` attributes store arbitrary data on an element. JavaScript can read them with `card.dataset.site`. Used for the search filter.
- `loop.index0` — Jinja2 built-in: the current iteration number starting from 0. `% 8` gets the remainder when divided by 8 (0 through 7), used to cycle through 8 colours.
- `cred.site_name[0].upper()` — gets the first character of the site name and capitalises it. This creates the letter avatar.

### 7.2 — Password reveal with fetch()

```javascript
async function revealPw(credId) {
    const pwEl = document.getElementById('pw-' + credId);

    if (pwEl.textContent !== '••••••••') {
        pwEl.textContent = '••••••••';  // hide if already visible
        return;
    }

    if (!revealedPws[credId]) {
        const res  = await fetch('/api/reveal/' + credId);
        const data = await res.json();
        revealedPws[credId] = data.password;
    }

    pwEl.textContent = revealedPws[credId];
}
```

`async function` / `await` — JavaScript handles web requests asynchronously. When you call `fetch()`, the browser sends an HTTP request and your code pauses at `await` until the response arrives. Other things on the page still work during this wait. Without `await`, you'd have to use nested callbacks.

`fetch('/api/reveal/' + credId)` — makes an HTTP GET request to the Flask server.

`await res.json()` — parses the response body as JSON into a JavaScript object. If the server returns `{"password": "Hunter2!"}`, then `data.password` is `"Hunter2!"`.

`revealedPws[credId]` — a plain JavaScript object used as a cache. After the first reveal, the password is stored here. Clicking reveal again uses the cached value instead of another server request. This saves network round-trips.

`document.getElementById('pw-' + credId)` — the ID on each password span is `"pw-"` plus the credential's UUID. For credential `abc-123`, the element is `<span id="pw-abc-123">`. This pattern lets JavaScript target any card's password element uniquely.

### 7.3 — The search filter

```javascript
function filterCards() {
    const q = document.getElementById('search-input').value.toLowerCase();
    document.querySelectorAll('.credential-card').forEach(card => {
        const match = card.dataset.site.includes(q) || card.dataset.user.includes(q);
        card.style.display = match ? '' : 'none';
    });
}
```

`document.querySelectorAll('.credential-card')` — returns all elements with the class `credential-card` as a list. We added this class to every card in the Jinja2 loop.

`card.dataset.site` — reads the `data-site` attribute (which holds the lowercase site name, set in the Jinja2 template).

`.includes(q)` — returns `true` if the string contains the search query.

`card.style.display = ''` — an empty string removes any inline style, restoring the default display. `'none'` hides the card. This filters the visible cards instantly without reloading the page.

### 7.4 — The password generator

```javascript
async function runGenerator() {
    const length  = document.getElementById('gen-length').value;
    const upper   = document.getElementById('gen-upper').checked;
    ...
    const params = new URLSearchParams({ length, upper, lower, digits, symbols });

    const res  = await fetch('/api/generate?' + params);
    const data = await res.json();

    document.getElementById('gen-output').textContent = data.password;
}
```

`URLSearchParams` builds a query string like `length=20&upper=true&lower=true...`.

`/api/generate?` + the params makes a request like `/api/generate?length=20&upper=true&lower=true&digits=true&symbols=true`.

In `app.py`, `request.args.get('length', 20)` reads these URL parameters. The server generates a password and returns `{"password": "Xm3!kPw...", "entropy": {"bits": 131, "strength": "Strong", "color": "green"}}`.

The `useGenerated()` function copies this password into the form's password field:

```javascript
function useGenerated() {
    const pw = document.getElementById('gen-output').textContent.trim();
    document.getElementById('new-pw').value = pw;
    updateAddStrength(pw);  // immediately shows the strength meter
}
```

---

## 8. Full Walkthroughs

### 8.1 — What happens when you Register

```
Browser                              Flask (app.py)              database.py            encryption.py
  │                                       │                           │                      │
  │  POST /register                       │                           │                      │
  │  {email, password, confirm}  ────────►│                           │                      │
  │                                       │                           │                      │
  │                                       │  generate_salt() × 2 ───────────────────────────►│
  │                                       │  ◄── auth_salt, enc_salt ──────────────────────── │
  │                                       │                           │                      │
  │                                       │  derive_auth_hash() ────────────────────────────►│
  │                                       │  ◄── auth_hash (32 bytes) ──────────────────────  │
  │                                       │                           │                      │
  │                                       │  derive_enc_key() ──────────────────────────────►│
  │                                       │  ◄── enc_key (32 bytes, NOT stored) ────────────  │
  │                                       │                           │                      │
  │                                       │  create_user() ──────────►│                      │
  │                                       │  (stores email,           │ INSERT INTO users     │
  │                                       │   auth_hash, auth_salt,   │ (NO enc_key!)         │
  │                                       │   enc_salt)               │                      │
  │                                       │                           │                      │
  │                                       │  (enc_key stored in _sessions RAM only)           │
  │  302 redirect to /dashboard ◄─────────│                           │                      │
```

### 8.2 — What happens when you Add a credential

```
Browser                        app.py                    encryption.py        database.py
  │                               │                            │                    │
  │  POST /add                    │                            │                    │
  │  {site="GitHub",   ──────────►│                            │                    │
  │   username="alice",           │                            │                    │
  │   password="Sup3r!"}          │                            │                    │
  │                               │                            │                    │
  │                               │  encrypt("GitHub", enc_key) ──────────────────►│
  │                               │  ◄── "a3f9:bc12..." ────────────────────────── │
  │                               │                            │                    │
  │                               │  encrypt("alice", enc_key) ───────────────────►│
  │                               │  ◄── "7f2e:9a4c..." ────────────────────────── │
  │                               │                            │                    │
  │                               │  encrypt("Sup3r!", enc_key) ──────────────────►│
  │                               │  ◄── "1b8d:5e7f..." ────────────────────────── │
  │                               │                            │                    │
  │                               │  add_credential() ──────────────────────────►  │
  │                               │  (3 encrypted blobs stored,      INSERT INTO   │
  │                               │   never plaintext)               credentials   │
  │                               │                                                │
  │  302 redirect to /dashboard ◄─│                                                │
```

### 8.3 — What happens when you Reveal a password

```
Browser (JavaScript)              Flask /api/reveal/<id>     database.py       encryption.py
  │                                       │                       │                  │
  │  GET /api/reveal/abc-123  ───────────►│                       │                  │
  │                                       │                       │                  │
  │                                       │  get_credential_by_id('abc-123', user_id)│
  │                                       │ ──────────────────────►                  │
  │                                       │ ◄── row with encrypted blob ─────────── │
  │                                       │                       │                  │
  │                                       │  decrypt(row['password_enc'], enc_key) ─►│
  │                                       │ ◄── "Sup3r!" ──────────────────────────  │
  │                                       │                                          │
  │  {"password": "Sup3r!"}  ◄───────────│                                          │
  │                                       │                                          │
  │  pwEl.textContent = "Sup3r!"          │                                          │
  │  (password appears in browser)        │                                          │
```

---

## 9. How the Files Connect

Here is a complete map of every function call between files:

```
app.py
  │
  ├── imports from encryption.py:
  │     generate_salt()          ← used in /register
  │     derive_auth_hash()       ← used in /register
  │     derive_enc_key()         ← used in /register, /login
  │     verify_password()        ← used in /login
  │     encrypt()                ← used in /add
  │     decrypt()                ← used in /dashboard, /api/reveal
  │     generate_strong_password() ← used in /api/generate
  │     estimate_entropy()       ← used in /api/generate, /api/strength
  │
  ├── imports from database.py:
  │     init_db()                ← called at startup
  │     create_user()            ← used in /register
  │     get_user_by_email()      ← used in /register, /login
  │     add_credential()         ← used in /add
  │     get_credentials()        ← used in /dashboard
  │     get_credential_by_id()   ← used in /api/reveal
  │     delete_credential()      ← used in /delete/<id>
  │
  └── renders templates:
        render_template('login.html')      ← GET /login
        render_template('dashboard.html',  ← GET /dashboard
          credentials=..., email=..., count=...)
```

```
login.html / dashboard.html
  │
  ├── POST /login          → app.py login()
  ├── POST /register       → app.py register()
  ├── GET /logout          → app.py logout()
  ├── POST /add            → app.py add()
  ├── POST /delete/<id>    → app.py delete()
  ├── GET /api/reveal/<id> → app.py api_reveal()   [JavaScript fetch]
  ├── GET /api/generate    → app.py api_generate() [JavaScript fetch]
  └── GET /api/strength    → app.py api_strength() [JavaScript fetch]
```

---

## 10. Security Summary

Here is what you can confidently explain to anyone reviewing your project:

### What the database stores — and what it cannot reveal

| Column | What's stored | Can it reveal the password? |
|--------|--------------|----------------------------|
| `auth_hash` | PBKDF2 output, 32 bytes | No. Cannot be reversed. |
| `auth_salt` | Random bytes | No. Useless without the password. |
| `enc_salt` | Random bytes | No. Useless without the password. |
| `site_name` | AES-256-GCM ciphertext | No. Requires enc_key. |
| `username` | AES-256-GCM ciphertext | No. Requires enc_key. |
| `password_enc` | AES-256-GCM ciphertext | No. Requires enc_key. |

The `enc_key` is never in the database. It only exists in Python RAM while logged in.

### Attack scenarios and how they're mitigated

**Someone steals vault.db:**
They get encrypted blobs and PBKDF2 hashes. To crack a password: run PBKDF2 600,000 times per guess. Against a 12-character random password: ~trillions of years.

**Someone intercepts network traffic:**
All routes use HTTP in development. In production on a real server, you'd add HTTPS (TLS). The assignment requirement says "zero-knowledge storage" — that's what's implemented.

**SQL injection attempt (`'; DROP TABLE users; --`):**
All queries use `?` parameterized placeholders. SQLite treats the user input as data, never as SQL code.

**IDOR — accessing another user's credential:**
All `get_credential_by_id()` and `delete_credential()` calls include `user_id` in the WHERE clause. You can only access rows you own.

**Timing attack on password comparison:**
`hmac.compare_digest()` is used instead of `==`. Response time reveals nothing about how many bytes matched.

**Brute-force login:**
600,000 PBKDF2 iterations means at most ~1,600 guesses per second per attacker CPU/GPU. A 12-character random password has over 60 trillion combinations.

---

*Project complete. Stack: Python 3.11 · Flask 3.0 · cryptography 42 · SQLite · Tailwind CSS 3 (CDN)*
