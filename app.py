"""
app.py — Main Flask Application
================================

This file is the "brain" of the web application. It connects:
  - The browser (HTTP requests/responses)
  - encryption.py (all cryptographic operations)
  - database.py (SQLite storage)

HOW SESSIONS WORK IN THIS APP:
  Flask's built-in session uses a signed browser cookie to store
  a random token. The ACTUAL sensitive data (enc_key, user_id) is
  stored server-side in the `_sessions` dictionary in RAM.

  Browser cookie:  { "token": "a3f9b2..." }   ← just a random ID
  Server RAM:      { "a3f9b2...": { "user_id": ..., "enc_key": ... } }

  This way the encryption key NEVER touches the browser.

IMPORTANT NOTE ON ZERO-KNOWLEDGE (Flask vs Browser-Side Crypto):
  In this Flask version, the master password travels over HTTPS to
  the server, which derives the keys. The database never stores it,
  but the server does see it momentarily in RAM. For FULL zero-knowledge
  (where the server never sees the password), all crypto would need to
  run in the browser (JavaScript). For an MVP/internship project, this
  server-side approach is standard and still very secure.
"""

import os
import secrets
from functools import wraps
from flask import (
    Flask, render_template, request,
    redirect, url_for, session, jsonify, flash
)

from encryption import (
    generate_salt, derive_auth_hash, derive_enc_key,
    verify_password, encrypt, decrypt,
    generate_strong_password, estimate_entropy
)
from database import (
    init_db, create_user, get_user_by_email,
    add_credential, get_credentials,
    get_credential_by_id, delete_credential
)

# ─── APP SETUP ────────────────────────────────────────────────────────────────

app = Flask(__name__)

# SECRET_KEY signs the browser cookie so it can't be forged.
# In production: set this via environment variable, never hardcode it.
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))

# ─── IN-MEMORY SESSION STORE ─────────────────────────────────────────────────
# Maps  session_token (str)  →  { user_id, email, enc_key (bytes) }
# The enc_key lives only here — never in the DB, never in the cookie.
# ⚠️  This resets on server restart. For production, use Redis.
_sessions: dict[str, dict] = {}


def _get_sess() -> dict | None:
    """Look up the current session data from the in-memory store."""
    token = session.get('token')
    return _sessions.get(token) if token else None


# ─── AUTH DECORATOR ───────────────────────────────────────────────────────────

def login_required(f):
    """
    Decorator that protects routes from unauthenticated access.
    Usage:  @login_required above a route function.
    If no valid session exists, redirects to the login page.
    """
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not _get_sess():
            flash('Please log in to access your vault.', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return wrapper


# ─── INITIALISE DB ────────────────────────────────────────────────────────────

with app.app_context():
    init_db()


# ─── ROUTES: AUTH ─────────────────────────────────────────────────────────────

@app.route('/')
def index():
    """Landing page — bounce to dashboard if logged in, else to login."""
    return redirect(url_for('dashboard') if _get_sess() else url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    """Render the login/register page (GET) or process login (POST)."""
    if _get_sess():
        return redirect(url_for('dashboard'))

    if request.method == 'GET':
        return render_template('login.html')

    email    = request.form.get('email', '').strip().lower()
    password = request.form.get('password', '')

    if not email or not password:
        flash('Email and password are required.', 'error')
        return render_template('login.html', tab='login')

    user = get_user_by_email(email)
    if not user:
        # Same error for "user not found" and "wrong password"
        # (prevents user enumeration attacks)
        flash('Invalid email or master password.', 'error')
        return render_template('login.html', tab='login')

    # Verify the master password against the stored PBKDF2 hash
    if not verify_password(password, bytes(user['auth_salt']), bytes(user['auth_hash'])):
        flash('Invalid email or master password.', 'error')
        return render_template('login.html', tab='login')

    # Re-derive the encryption key (same inputs → same output, deterministically)
    enc_key = derive_enc_key(password, bytes(user['enc_salt']))

    # Store everything in the server-side session store
    token = secrets.token_urlsafe(32)
    _sessions[token] = {
        'user_id': user['id'],
        'email':   email,
        'enc_key': enc_key,   # bytes, lives only in server RAM
    }
    session['token'] = token  # only the token goes to the browser cookie
    session.permanent = False # session expires when browser closes

    return redirect(url_for('dashboard'))


@app.route('/register', methods=['POST'])
def register():
    """Handle new account registration."""
    email    = request.form.get('email', '').strip().lower()
    password = request.form.get('password', '')
    confirm  = request.form.get('confirm', '')

    # ── Validation ────────────────────────────────────────────────────────────
    if not email or not password:
        flash('All fields are required.', 'error')
        return render_template('login.html', tab='register')

    if password != confirm:
        flash('Passwords do not match.', 'error')
        return render_template('login.html', tab='register')

    if len(password) < 12:
        flash('Master password must be at least 12 characters.', 'error')
        return render_template('login.html', tab='register')

    if get_user_by_email(email):
        flash('An account with that email already exists.', 'error')
        return render_template('login.html', tab='register')

    # ── Key Derivation ────────────────────────────────────────────────────────
    # Two separate salts → two independent derived values
    auth_salt = generate_salt()   # for login verification hash
    enc_salt  = generate_salt()   # for the encryption key

    # auth_hash: stored in DB, used to verify future logins
    auth_hash = derive_auth_hash(password, auth_salt)

    # enc_key: NOT stored in DB, re-derived on every login
    enc_key = derive_enc_key(password, enc_salt)

    # ── Store User ────────────────────────────────────────────────────────────
    user_id = create_user(email, auth_hash, auth_salt, enc_salt)

    # ── Auto-login ────────────────────────────────────────────────────────────
    token = secrets.token_urlsafe(32)
    _sessions[token] = {'user_id': user_id, 'email': email, 'enc_key': enc_key}
    session['token'] = token

    flash('Account created! Welcome to your vault.', 'success')
    return redirect(url_for('dashboard'))


@app.route('/logout')
def logout():
    """Clear the session and redirect to login."""
    token = session.pop('token', None)
    if token and token in _sessions:
        del _sessions[token]  # wipe enc_key from RAM
    return redirect(url_for('login'))


# ─── ROUTES: DASHBOARD ────────────────────────────────────────────────────────

@app.route('/dashboard')
@login_required
def dashboard():
    """
    Main vault view.

    Fetches all encrypted credentials from the DB, decrypts site_name
    and username for display. Passwords are NOT decrypted here —
    they are fetched on demand via the /api/reveal/<id> endpoint.
    """
    sess = _get_sess()
    enc_key = sess['enc_key']
    raw     = get_credentials(sess['user_id'])

    credentials = []
    for row in raw:
        try:
            credentials.append({
                'id':         row['id'],
                'site_name':  decrypt(row['site_name'],  enc_key),
                'username':   decrypt(row['username'],   enc_key),
                'created_at': row['created_at'][:10],  # just the date part
            })
        except Exception:
            # If a single row fails to decrypt, skip it gracefully
            # (shouldn't happen unless DB was tampered with)
            continue

    return render_template(
        'dashboard.html',
        credentials=credentials,
        email=sess['email'],
        count=len(credentials)
    )


# ─── ROUTES: VAULT ACTIONS ────────────────────────────────────────────────────

@app.route('/add', methods=['POST'])
@login_required
def add():
    """Encrypt and store a new credential."""
    sess     = _get_sess()
    enc_key  = sess['enc_key']
    site     = request.form.get('site_name', '').strip()
    username = request.form.get('username', '').strip()
    password = request.form.get('password', '')

    if not site or not username or not password:
        flash('All fields (site, username, password) are required.', 'error')
        return redirect(url_for('dashboard'))

    # Encrypt all three fields independently
    # Each call uses a fresh random nonce — the ciphertexts look different
    # even if the plaintext is identical
    add_credential(
        user_id      = sess['user_id'],
        site_name_enc = encrypt(site, enc_key),
        username_enc  = encrypt(username, enc_key),
        password_enc  = encrypt(password, enc_key),
    )

    flash(f'"{site}" added to your vault.', 'success')
    return redirect(url_for('dashboard'))


@app.route('/delete/<cred_id>', methods=['POST'])
@login_required
def delete(cred_id):
    """Delete a credential. The user_id check in delete_credential prevents IDOR."""
    sess = _get_sess()
    deleted = delete_credential(cred_id, sess['user_id'])
    if deleted:
        flash('Item deleted.', 'success')
    else:
        flash('Item not found or already deleted.', 'error')
    return redirect(url_for('dashboard'))


# ─── ROUTES: JSON API ─────────────────────────────────────────────────────────

@app.route('/api/reveal/<cred_id>')
@login_required
def api_reveal(cred_id):
    """
    Return the decrypted password for a single credential.

    Called by the dashboard's "reveal" button via JavaScript fetch().
    Password is only sent when explicitly requested — it never appears
    in the initial HTML page load.
    """
    sess = _get_sess()
    row  = get_credential_by_id(cred_id, sess['user_id'])

    if not row:
        return jsonify({'error': 'Not found'}), 404

    try:
        plaintext = decrypt(row['password_enc'], sess['enc_key'])
        return jsonify({'password': plaintext})
    except Exception:
        return jsonify({'error': 'Decryption failed'}), 500


@app.route('/api/generate')
def api_generate():
    """
    Generate a strong random password.

    Accepts query parameters:
      length   (int,  default 20)
      upper    (bool, default true)
      lower    (bool, default true)
      digits   (bool, default true)
      symbols  (bool, default true)

    Also returns entropy data to feed the strength meter.
    """
    try:
        length  = min(max(int(request.args.get('length', 20)), 8), 64)
        upper   = request.args.get('upper',   'true').lower() == 'true'
        lower   = request.args.get('lower',   'true').lower() == 'true'
        digits  = request.args.get('digits',  'true').lower() == 'true'
        symbols = request.args.get('symbols', 'true').lower() == 'true'

        password = generate_strong_password(length, upper, lower, digits, symbols)
        entropy  = estimate_entropy(password)
        return jsonify({'password': password, 'entropy': entropy})
    except ValueError as e:
        return jsonify({'error': str(e)}), 400


@app.route('/api/strength')
def api_strength():
    """Return entropy data for any given password (used by the strength meter)."""
    pw = request.args.get('pw', '')
    return jsonify(estimate_entropy(pw))


# ─── ENTRY POINT ──────────────────────────────────────────────────────────────

if __name__ == '__main__':
    # debug=True enables auto-reload and detailed error pages.
    # NEVER use debug=True in production.
    app.run(debug=True, port=5000)