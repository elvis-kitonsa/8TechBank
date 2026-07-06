import sqlite3
import os
from datetime import timedelta
from flask import Flask, render_template, request, redirect, session, url_for, g, abort
from flask_wtf import CSRFProtect
from markupsafe import escape
import bcrypt
import jwt as pyjwt
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from marshmallow import Schema, fields, ValidationError
from functools import wraps

app = Flask(__name__)

# -------------------------------------------------------
# FIX 2 (part) + FIX 6: Secure Flask configuration
# Load secret key from environment variable - no hardcoding
# -------------------------------------------------------
app.secret_key = os.environ.get('SECRET_KEY', os.urandom(32))

# FIX 6: Secure session cookie configuration
app.config['SESSION_COOKIE_HTTPONLY'] = True      # JS cannot read cookie
app.config['SESSION_COOKIE_SAMESITE'] = 'Strict'  # Blocks CSRF
app.config['SESSION_COOKIE_SECURE'] = False        # Set True in production (requires HTTPS)
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=15)  # 15-min timeout
app.config['WTF_CSRF_ENABLED'] = True
app.config['WTF_CSRF_SECRET_KEY'] = os.environ.get('CSRF_SECRET', os.urandom(32))

# FIX 3: Initialize CSRF protection globally
csrf = CSRFProtect(app)

# Task 4: Rate limiter for API endpoints
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=[]
)

DATABASE = 'techbank_secure.db'

# ---------- DATABASE HELPERS ----------

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def init_db():
    db = sqlite3.connect(DATABASE)
    db.row_factory = sqlite3.Row
    cursor = db.cursor()
    cursor.executescript('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            role TEXT DEFAULT 'user',
            email TEXT
        );
        CREATE TABLE IF NOT EXISTS accounts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            account_number TEXT NOT NULL UNIQUE,
            balance REAL DEFAULT 0.0,
            FOREIGN KEY (user_id) REFERENCES users(id)
        );
        CREATE TABLE IF NOT EXISTS transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            from_acct INTEGER,
            to_acct INTEGER,
            amount REAL,
            note TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        );
    ''')

    cursor.execute("SELECT COUNT(*) FROM users")
    if cursor.fetchone()[0] == 0:
        # FIX 5: Passwords hashed with bcrypt (12 rounds) at seed time
        for uname, pwd, role, email in [
            ('alice', 'password123', 'user', 'alice@techbank.com'),
            ('bob',   'qwerty456',   'user', 'bob@techbank.com'),
            ('admin', 'admin123',    'admin','admin@techbank.com'),
        ]:
            hashed = bcrypt.hashpw(pwd.encode(), bcrypt.gensalt(rounds=12))
            cursor.execute(
                "INSERT INTO users (username, password, role, email) VALUES (?,?,?,?)",
                (uname, hashed.decode(), role, email)
            )
        cursor.execute("INSERT INTO accounts (user_id, account_number, balance) VALUES (1,'ACC-001',5000.00)")
        cursor.execute("INSERT INTO accounts (user_id, account_number, balance) VALUES (2,'ACC-002',3000.00)")
        cursor.execute("INSERT INTO accounts (user_id, account_number, balance) VALUES (3,'ACC-003',99999.00)")
    db.commit()
    db.close()

# ---------- SECURITY HEADERS (FIX 6) ----------

@app.after_request
def set_security_headers(response):
    # FIX 6: Security headers applied to every response
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Referrer-Policy'] = 'no-referrer'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    # FIX 2: Content Security Policy blocks inline scripts - neutralizes XSS
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self'; "       # No inline scripts allowed
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:;"
    )
    return response

# ---------- AUTH HELPER ----------

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return redirect('/login')
        return f(*args, **kwargs)
    return decorated

# ---------- ROUTES ----------

@app.route('/')
def index():
    return redirect('/login')

# FIX 1: Parameterized queries in login - no string concatenation
# FIX 5: bcrypt password verification
@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        # FIX 1: Parameterized query - SQL injection is impossible
        user = db.execute(
            "SELECT * FROM users WHERE username=?", (username,)
        ).fetchone()
        # FIX 5: bcrypt hash comparison - no plaintext comparison
        if user and bcrypt.checkpw(password.encode(), user['password'].encode()):
            session.permanent = True
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']
            return redirect('/dashboard')
        else:
            error = 'Invalid credentials'
    return render_template('login.html', error=error)

# FIX 5: bcrypt password hashing at registration (12 rounds)
@app.route('/register', methods=['GET', 'POST'])
def register():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        # FIX 5: Hash password with bcrypt before storing
        hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12))
        db = get_db()
        try:
            db.execute(
                "INSERT INTO users (username, password, email) VALUES (?,?,?)",
                (username, hashed.decode(), email)
            )
            db.commit()
            user = db.execute(
                "SELECT id FROM users WHERE username=?", (username,)
            ).fetchone()
            import random
            acc_num = f"ACC-{random.randint(100,999)}"
            db.execute(
                "INSERT INTO accounts (user_id, account_number, balance) VALUES (?,?,?)",
                (user['id'], acc_num, 1000.00)
            )
            db.commit()
            return redirect('/login')
        except sqlite3.IntegrityError:
            error = 'Username already exists'
    return render_template('register.html', error=error)

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/login')

@app.route('/dashboard')
@login_required
def dashboard():
    db = get_db()
    account = db.execute(
        "SELECT * FROM accounts WHERE user_id=?", (session['user_id'],)
    ).fetchone()
    transactions = db.execute(
        "SELECT * FROM transactions WHERE from_acct=? OR to_acct=? ORDER BY timestamp DESC LIMIT 10",
        (account['id'], account['id']) if account else (0, 0)
    ).fetchall()
    return render_template('dashboard.html', account=account, transactions=transactions)

# FIX 2: Output encoding - query rendered via template with auto-escaping
# XSS payload is neutralized - rendered as plain text not executed
@app.route('/search')
@login_required
def search():
    # FIX 2: escape() encodes all HTML special characters
    query = escape(request.args.get('q', ''))
    return render_template('search.html', query=query)

# FIX 3: CSRF token validated automatically by Flask-WTF on all POSTs
# FIX 2: Note stored and rendered safely - no | safe filter
@app.route('/transfer', methods=['GET', 'POST'])
@login_required
def transfer():
    db = get_db()
    error = None
    success = None
    if request.method == 'POST':
        # FIX 3: Flask-WTF automatically validates CSRF token here
        # If token is missing or invalid, returns 400 Bad Request
        to_account = request.form['to_account']
        amount = float(request.form['amount'])
        # FIX 2: Sanitize note input before storing
        note = escape(request.form.get('note', ''))

        from_account = db.execute(
            "SELECT * FROM accounts WHERE user_id=?", (session['user_id'],)
        ).fetchone()
        to_acc = db.execute(
            "SELECT * FROM accounts WHERE account_number=?", (to_account,)
        ).fetchone()

        if not to_acc:
            error = 'Destination account not found'
        elif from_account['balance'] < amount:
            error = 'Insufficient funds'
        else:
            db.execute("UPDATE accounts SET balance=balance-? WHERE id=?",
                       (amount, from_account['id']))
            db.execute("UPDATE accounts SET balance=balance+? WHERE id=?",
                       (amount, to_acc['id']))
            db.execute(
                "INSERT INTO transactions (from_acct, to_acct, amount, note) VALUES (?,?,?,?)",
                (from_account['id'], to_acc['id'], amount, str(note))
            )
            db.commit()
            success = f'Transfer of UGX {amount} to {to_account} successful'

    accounts = db.execute("SELECT * FROM accounts").fetchall()
    return render_template('transfer.html', error=error,
                           success=success, accounts=accounts)

# FIX 4: Authorization check - users can only access their own account
@app.route('/account/<int:account_id>')
@login_required
def view_account(account_id):
    db = get_db()
    account = db.execute(
        "SELECT * FROM accounts WHERE id=?", (account_id,)
    ).fetchone()
    if not account:
        abort(404)
    # FIX 4: Ownership check - return 403 if not the account owner
    if account['user_id'] != session['user_id']:
        abort(403)  # Forbidden - IDOR exploit now blocked
    owner = db.execute(
        "SELECT username, email FROM users WHERE id=?", (account['user_id'],)
    ).fetchone()
    transactions = db.execute(
        "SELECT * FROM transactions WHERE from_acct=? OR to_acct=? ORDER BY timestamp DESC",
        (account_id, account_id)
    ).fetchall()
    return render_template('account.html', account=account,
                           owner=owner, transactions=transactions)

@app.route('/admin')
@login_required
def admin():
    if session.get('role') != 'admin':
        abort(403)
    db = get_db()
    users = db.execute("SELECT id, username, email, role FROM users").fetchall()
    accounts = db.execute("SELECT * FROM accounts").fetchall()
    return render_template('admin.html', users=users, accounts=accounts)

# =====================================================
# TASK 4: SECURE API LAYER WITH JWT AUTH
# =====================================================

JWT_SECRET = os.environ.get('JWT_SECRET', 'jwt-secret-change-in-production')
JWT_ALGORITHM = 'HS256'
JWT_EXPIRY_MINUTES = 15

# Task 4.2: Input validation schemas using Marshmallow
class LoginSchema(Schema):
    username = fields.Str(required=True, validate=lambda x: 0 < len(x) <= 50)
    password = fields.Str(required=True, validate=lambda x: 0 < len(x) <= 100)

class TransferSchema(Schema):
    to_account = fields.Str(required=True, validate=lambda x: 0 < len(x) <= 20)
    amount = fields.Float(required=True, validate=lambda x: x > 0)
    note = fields.Str(load_default='', validate=lambda x: len(x) <= 200)

def jwt_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get('Authorization', '')
        if not auth_header.startswith('Bearer '):
            return {'error': 'Missing or invalid token'}, 401
        token = auth_header.split(' ')[1]
        try:
            payload = pyjwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
            request.current_user = payload
        except pyjwt.ExpiredSignatureError:
            return {'error': 'Token expired'}, 401
        except pyjwt.InvalidTokenError:
            return {'error': 'Invalid token'}, 401
        return f(*args, **kwargs)
    return decorated

# Task 4.1: JWT token endpoint
# Task 4.2: Rate limited to 5 attempts per minute per IP
@app.route('/api/auth/token', methods=['POST'])
@limiter.limit("5 per minute")
@csrf.exempt
def api_token():
    schema = LoginSchema()
    try:
        data = schema.load(request.get_json() or {})
    except ValidationError as e:
        return {'error': 'Validation failed', 'details': e.messages}, 422

    db = get_db()
    user = db.execute(
        "SELECT * FROM users WHERE username=?", (data['username'],)
    ).fetchone()

    if user and bcrypt.checkpw(data['password'].encode(), user['password'].encode()):
        import datetime
        payload = {
            'user_id': user['id'],
            'username': user['username'],
            'role': user['role'],
            'exp': datetime.datetime.utcnow() + timedelta(minutes=JWT_EXPIRY_MINUTES),
            'iat': datetime.datetime.utcnow(),
        }
        token = pyjwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
        return {
            'access_token': token,
            'token_type': 'Bearer',
            'expires_in': JWT_EXPIRY_MINUTES * 60
        }
    return {'error': 'Invalid credentials'}, 401

# Task 4.1: Protected API endpoint - get account info
@app.route('/api/account', methods=['GET'])
@csrf.exempt
@jwt_required
def api_account():
    db = get_db()
    account = db.execute(
        "SELECT * FROM accounts WHERE user_id=?",
        (request.current_user['user_id'],)
    ).fetchone()
    if not account:
        return {'error': 'Account not found'}, 404
    return {
        'account_number': account['account_number'],
        'balance': account['balance']
    }

# Task 4.1: Admin-only API endpoint - role-based access control
@app.route('/api/admin/users', methods=['GET'])
@csrf.exempt
@jwt_required
def api_admin_users():
    if request.current_user.get('role') != 'admin':
        return {'error': 'Forbidden - admin access required'}, 403
    db = get_db()
    users = db.execute(
        "SELECT id, username, email, role FROM users"
    ).fetchall()
    return {'users': [dict(u) for u in users]}

# ---------- MAIN ----------

if __name__ == '__main__':
    init_db()
    # FIX 8: Debug mode disabled
    # Secure app configured to run on port 5001 to avoid conflicts with other services
    app.run(debug=False, port=5001)