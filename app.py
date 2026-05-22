
"""
PassVault - Gestionnaire de mots de passe web
Technologies: Python Flask, SQLite, AES-256, HTML/CSS
"""

from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import sqlite3, os, base64, hashlib, secrets

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)  # Clé secrète Flask pour les sessions

DB_PATH = "passvault.db"


#  Cryptographie

def derive_key(master_password: str, salt: bytes) -> bytes:
    """Dérive une clé AES-256 depuis le mot de passe maître via PBKDF2."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000, 
    )
    return base64.urlsafe_b64encode(kdf.derive(master_password.encode()))


def encrypt_password(plain: str, master_password: str, salt: bytes) -> str:
    """Chiffre un mot de passe avec AES-256 (Fernet)."""
    key = derive_key(master_password, salt)
    f = Fernet(key)
    return f.encrypt(plain.encode()).decode()


def decrypt_password(encrypted: str, master_password: str, salt: bytes) -> str:
    """Déchiffre un mot de passe."""
    key = derive_key(master_password, salt)
    f = Fernet(key)
    return f.decrypt(encrypted.encode()).decode()


def hash_master(password: str, salt: bytes) -> str:
    """Hash le mot de passe maître pour vérification (SHA-256 + sel)."""
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 480000).hex()


#  Base de données

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with get_db() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS master (
                id       INTEGER PRIMARY KEY,
                hash     TEXT NOT NULL,
                salt     TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS passwords (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                site        TEXT NOT NULL,
                username    TEXT NOT NULL,
                password    TEXT NOT NULL,   -- chiffré AES-256
                categorie   TEXT DEFAULT 'général',
                note        TEXT DEFAULT '',
                cree_le     TEXT DEFAULT (datetime('now'))
            );
        """)
        conn.commit()


def is_configured():
    with get_db() as conn:
        return conn.execute("SELECT COUNT(*) FROM master").fetchone()[0] > 0


def get_salt():
    with get_db() as conn:
        row = conn.execute("SELECT salt FROM master").fetchone()
        return bytes.fromhex(row["salt"]) if row else None



#  Routes — Setup

@app.route("/setup", methods=["GET", "POST"])
def setup():
    if is_configured():
        return redirect(url_for("login"))
    if request.method == "POST":
        mp = request.form.get("master_password", "")
        confirm = request.form.get("confirm", "")
        if len(mp) < 8:
            flash("Le mot de passe maître doit faire au moins 8 caractères.", "error")
            return render_template("setup.html")
        if mp != confirm:
            flash("Les mots de passe ne correspondent pas.", "error")
            return render_template("setup.html")
        salt = secrets.token_bytes(32)
        h = hash_master(mp, salt)
        with get_db() as conn:
            conn.execute("INSERT INTO master (hash, salt) VALUES (?, ?)", (h, salt.hex()))
            conn.commit()
        flash("Coffre-fort créé ! Connecte-toi.", "success")
        return redirect(url_for("login"))
    return render_template("setup.html")



#  Routes — Authentification

@app.route("/", methods=["GET"])
def index():
    if not is_configured():
        return redirect(url_for("setup"))
    if "authenticated" not in session:
        return redirect(url_for("login"))
    return redirect(url_for("dashboard"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if not is_configured():
        return redirect(url_for("setup"))
    if request.method == "POST":
        mp = request.form.get("master_password", "")
        salt = get_salt()
        with get_db() as conn:
            stored = conn.execute("SELECT hash FROM master").fetchone()["hash"]
        if hash_master(mp, salt) == stored:
            session["authenticated"] = True
            session["master"] = mp  # stocké en session (mémoire serveur uniquement)
            return redirect(url_for("dashboard"))
        flash("Mot de passe maître incorrect.", "error")
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))



#  Routes — Dashboard

@app.route("/dashboard")
def dashboard():
    if "authenticated" not in session:
        return redirect(url_for("login"))
    search = request.args.get("q", "")
    cat    = request.args.get("cat", "")
    with get_db() as conn:
        query  = "SELECT id, site, username, categorie, note, cree_le FROM passwords WHERE 1=1"
        params = []
        if search:
            query += " AND (site LIKE ? OR username LIKE ?)"
            params += [f"%{search}%", f"%{search}%"]
        if cat:
            query += " AND categorie = ?"
            params.append(cat)
        query += " ORDER BY site ASC"
        entries = conn.execute(query, params).fetchall()
        cats = conn.execute("SELECT DISTINCT categorie FROM passwords ORDER BY categorie").fetchall()
        total = conn.execute("SELECT COUNT(*) FROM passwords").fetchone()[0]
    return render_template("dashboard.html", entries=entries, cats=cats,
                           total=total, search=search, cat=cat)



#  Routes — CRUD mots de passe

@app.route("/add", methods=["GET", "POST"])
def add_entry():
    if "authenticated" not in session:
        return redirect(url_for("login"))
    if request.method == "POST":
        site  = request.form["site"]
        user  = request.form["username"]
        plain = request.form["password"]
        cat   = request.form.get("categorie", "général")
        note  = request.form.get("note", "")
        salt  = get_salt()
        encrypted = encrypt_password(plain, session["master"], salt)
        with get_db() as conn:
            conn.execute(
                "INSERT INTO passwords (site, username, password, categorie, note) VALUES (?,?,?,?,?)",
                (site, user, encrypted, cat, note)
            )
            conn.commit()
        flash(f"✅ Mot de passe pour {site} ajouté.", "success")
        return redirect(url_for("dashboard"))
    return render_template("add.html")


@app.route("/reveal/<int:entry_id>")
def reveal(entry_id):
    """Déchiffre et retourne le mot de passe en JSON (appelé via JS)."""
    if "authenticated" not in session:
        return jsonify({"error": "Non autorisé"}), 401
    with get_db() as conn:
        row = conn.execute("SELECT password FROM passwords WHERE id=?", (entry_id,)).fetchone()
    if not row:
        return jsonify({"error": "Introuvable"}), 404
    salt = get_salt()
    plain = decrypt_password(row["password"], session["master"], salt)
    return jsonify({"password": plain})


@app.route("/delete/<int:entry_id>", methods=["POST"])
def delete_entry(entry_id):
    if "authenticated" not in session:
        return redirect(url_for("login"))
    with get_db() as conn:
        conn.execute("DELETE FROM passwords WHERE id=?", (entry_id,))
        conn.commit()
    flash("🗑 Entrée supprimée.", "success")
    return redirect(url_for("dashboard"))


@app.route("/edit/<int:entry_id>", methods=["GET", "POST"])
def edit_entry(entry_id):
    if "authenticated" not in session:
        return redirect(url_for("login"))
    salt = get_salt()
    with get_db() as conn:
        row = conn.execute("SELECT * FROM passwords WHERE id=?", (entry_id,)).fetchone()
    if not row:
        flash("Entrée introuvable.", "error")
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        site  = request.form["site"]
        user  = request.form["username"]
        plain = request.form["password"]
        cat   = request.form.get("categorie", "général")
        note  = request.form.get("note", "")
        encrypted = encrypt_password(plain, session["master"], salt)
        with get_db() as conn:
            conn.execute(
                "UPDATE passwords SET site=?, username=?, password=?, categorie=?, note=? WHERE id=?",
                (site, user, encrypted, cat, note, entry_id)
            )
            conn.commit()
        flash("✅ Entrée mise à jour.", "success")
        return redirect(url_for("dashboard"))
    plain = decrypt_password(row["password"], session["master"], salt)
    return render_template("edit.html", entry=row, plain=plain)



#  Générateur de mot de passe 

@app.route("/generate")
def generate_password():
    import string
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
    pwd = ''.join(secrets.choice(alphabet) for _ in range(16))
    return jsonify({"password": pwd})


if __name__ == "__main__":
    init_db()
    print("\n🔐 PassVault démarré → http://127.0.0.1:5000\n")
    app.run(debug=True)
