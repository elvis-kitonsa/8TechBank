import sqlite3
import os
from flask import Flask, render_template, request, redirect, session, url_for, g

app = Flask(__name__)
app.secret_key = 'supersecretkey123'  # VULNERABLE: hardcoded weak secret key

DATABASE = 'techbank.db'

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

    # Seed two test users with plaintext passwords (VULNERABLE)
    # This means that if the database is compromised, attackers can easily read user passwords.
    cursor.execute("SELECT COUNT(*) FROM users")
    if cursor.fetchone()[0] == 0:
        cursor.execute("INSERT INTO users (username, password, role, email) VALUES (?,?,?,?)",
                       ('alice', 'password123', 'user', 'alice@techbank.com'))
        cursor.execute("INSERT INTO users (username, password, role, email) VALUES (?,?,?,?)",
                       ('bob', 'qwerty456', 'user', 'bob@techbank.com'))
        cursor.execute("INSERT INTO users (username, password, role, email) VALUES (?,?,?,?)",
                       ('admin', 'admin123', 'admin', 'admin@techbank.com'))

        cursor.execute("INSERT INTO accounts (user_id, account_number, balance) VALUES (1,'ACC-001',5000.00)")
        cursor.execute("INSERT INTO accounts (user_id, account_number, balance) VALUES (2,'ACC-002',3000.00)")
        cursor.execute("INSERT INTO accounts (user_id, account_number, balance) VALUES (3,'ACC-003',99999.00)")

    db.commit()
    db.close()

# ---------- ROUTES ----------

@app.route('/')
def index():
    return redirect('/login')

# VULNERABLE Pattern 1: SQL Injection in login
@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        # VULNERABLE: string concatenation in SQL query - no parameterization
        query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
        db = get_db()
        user = db.execute(query).fetchone()
        if user:
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']
            return redirect('/dashboard')
        else:
            error = 'Invalid credentials'
    return render_template('login.html', error=error)

# VULNERABLE Pattern 5: Plaintext password storage
@app.route('/register', methods=['GET', 'POST'])
def register():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']  # VULNERABLE: no hashing
        email = request.form['email']
        db = get_db()
        try:
            db.execute("INSERT INTO users (username, password, email) VALUES (?,?,?)",
                       (username, password, email))
            db.commit()
            # Create account for new user
            user = db.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone()
            import random
            acc_num = f"ACC-{random.randint(100,999)}"
            db.execute("INSERT INTO accounts (user_id, account_number, balance) VALUES (?,?,?)",
                       (user['id'], acc_num, 1000.00))
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
def dashboard():
    if 'user_id' not in session:
        return redirect('/login')
    db = get_db()
    account = db.execute("SELECT * FROM accounts WHERE user_id=?",
                         (session['user_id'],)).fetchone()
    transactions = db.execute(
        "SELECT * FROM transactions WHERE from_acct=? OR to_acct=? ORDER BY timestamp DESC LIMIT 10",
        (account['id'], account['id']) if account else (0, 0)
    ).fetchall()
    return render_template('dashboard.html', account=account, transactions=transactions)

# VULNERABLE Pattern 2: Reflected XSS in search
@app.route('/search')
def search():
    if 'user_id' not in session:
        return redirect('/login')
    # VULNERABLE: user input rendered directly without encoding
    query = request.args.get('q', '')
    return f"<h2>Search Results for: {query}</h2><p>No results found.</p><a href='/dashboard'>Back</a>"

# VULNERABLE Pattern 3: Stored XSS in transaction notes
# VULNERABLE Pattern 6: Missing CSRF protection on fund transfer
@app.route('/transfer', methods=['GET', 'POST'])
def transfer():
    if 'user_id' not in session:
        return redirect('/login')
    db = get_db()
    error = None
    success = None
    if request.method == 'POST':
        # VULNERABLE: no CSRF token validation
        to_account = request.form['to_account']
        amount = float(request.form['amount'])
        note = request.form['note']  # VULNERABLE: no sanitization of note

        from_account = db.execute("SELECT * FROM accounts WHERE user_id=?",
                                  (session['user_id'],)).fetchone()
        to_acc = db.execute("SELECT * FROM accounts WHERE account_number=?",
                            (to_account,)).fetchone()

        if not to_acc:
            error = 'Destination account not found'
        elif from_account['balance'] < amount:
            error = 'Insufficient funds'
        else:
            db.execute("UPDATE accounts SET balance=balance-? WHERE id=?",
                       (amount, from_account['id']))
            db.execute("UPDATE accounts SET balance=balance+? WHERE id=?",
                       (amount, to_acc['id']))
            # VULNERABLE: note stored raw, rendered with | safe in template
            db.execute("INSERT INTO transactions (from_acct, to_acct, amount, note) VALUES (?,?,?,?)",
                       (from_account['id'], to_acc['id'], amount, note))
            db.commit()
            success = f'Transfer of UGX {amount} to {to_account} successful'

    accounts = db.execute("SELECT * FROM accounts").fetchall()
    return render_template('transfer.html', error=error, success=success, accounts=accounts)

# VULNERABLE Pattern 4: IDOR - no authorization check
@app.route('/account/<int:account_id>')
def view_account(account_id):
    if 'user_id' not in session:
        return redirect('/login')
    # VULNERABLE: any logged-in user can view any account by changing the ID
    db = get_db()
    account = db.execute("SELECT * FROM accounts WHERE id=?", (account_id,)).fetchone()
    if not account:
        return "Account not found", 404
    owner = db.execute("SELECT username, email FROM users WHERE id=?",
                       (account['user_id'],)).fetchone()
    transactions = db.execute(
        "SELECT * FROM transactions WHERE from_acct=? OR to_acct=? ORDER BY timestamp DESC",
        (account_id, account_id)
    ).fetchall()
    return render_template('account.html', account=account, owner=owner, transactions=transactions)

# Admin panel - VULNERABLE: only checks role in session (easily forged)
@app.route('/admin')
def admin():
    if 'user_id' not in session:
        return redirect('/login')
    if session.get('role') != 'admin':
        return "Access denied", 403
    db = get_db()
    users = db.execute("SELECT * FROM users").fetchall()
    accounts = db.execute("SELECT * FROM accounts").fetchall()
    return render_template('admin.html', users=users, accounts=accounts)

# ---------- MAIN ----------

if __name__ == '__main__':
    init_db()
    app.run(debug=True)  # VULNERABLE: debug mode enabled in production