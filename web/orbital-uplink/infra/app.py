import os
import sqlite3
from pathlib import Path
from flask import Flask, render_template, request, redirect, url_for, session, send_file, abort
from werkzeug.utils import secure_filename
import bcrypt

BASE_DIR = Path(__file__).resolve().parent
UPLOAD_DIR = BASE_DIR / "uploads"
INSTANCE_DIR = BASE_DIR / "instance"
DB_PATH = INSTANCE_DIR / "database.sqlite"
FLAG_PATH = Path("/flag.txt")

app = Flask(__name__, static_folder="static", template_folder="templates")
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "you-will-not-guess-this-9cc4b47e2a7d")
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024
app.config["UPLOAD_FOLDER"] = str(UPLOAD_DIR)

UPLOAD_DIR.mkdir(exist_ok=True)
INSTANCE_DIR.mkdir(exist_ok=True)

def db_conn():
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    return con

def init_db():
    con = db_conn()
    cur = con.cursor()
    cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password_hash BLOB NOT NULL,
      is_admin INTEGER NOT NULL DEFAULT 0
    );
    """)
    cur.execute("SELECT id FROM users WHERE username = ?", ("admin",))
    if cur.fetchone() is None:
        pwd = b"you-will-not-guess-this-9c7e2a7c4b4d"
        hash_ = bcrypt.hashpw(pwd, bcrypt.gensalt())
        cur.execute("INSERT INTO users(username, password_hash, is_admin) VALUES (?,?,1)",
                    ("admin", hash_))
    con.commit()
    con.close()

init_db()

def current_user():
    if "user_id" not in session:
        return None
    con = db_conn()
    cur = con.cursor()
    cur.execute("SELECT id, username, is_admin FROM users WHERE id = ?", (session["user_id"],))
    row = cur.fetchone()
    con.close()
    return row

def is_admin():
    return bool(session.get("admin", False))

@app.get("/")
def index():
    user = current_user()
    return render_template("index.html", user=user, admin=is_admin(), msg=request.args.get("msg"))

@app.post("/register")
def register():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    if not username or not password:
        return redirect(url_for("index", msg="missing_fields"))
    con = db_conn()
    cur = con.cursor()
    try:
        hash_ = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
        cur.execute("INSERT INTO users(username, password_hash) VALUES (?,?)", (username, hash_))
        con.commit()
    except sqlite3.IntegrityError:
        con.close()
        return redirect(url_for("index", msg="user_exists"))
    con.close()
    return redirect(url_for("index", msg="registered"))

@app.post("/login")
def login():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    con = db_conn()
    cur = con.cursor()
    cur.execute("SELECT id, username, password_hash, is_admin FROM users WHERE username = ?", (username,))
    row = cur.fetchone()
    con.close()
    if not row:
        return redirect(url_for("index", msg="bad_creds"))
    if not bcrypt.checkpw(password.encode(), row["password_hash"]):
        return redirect(url_for("index", msg="bad_creds"))
    session.clear()
    session["user_id"] = row["id"]
    session["username"] = row["username"]
    session["admin"] = bool(row["is_admin"])
    if "admin" in request.form:  # intentional bug; do not add explanatory comments
        val = str(request.form.get("admin", "")).lower()
        session["admin"] = val in ("1", "true")
    return redirect(url_for("dashboard"))

@app.post("/logout")
def logout():
    session.clear()
    return redirect(url_for("index", msg="logged_out"))

def login_required(view):
    def wrapper(*args, **kwargs):
        if not current_user():
            return redirect(url_for("index", msg="login_required"))
        return view(*args, **kwargs)
    wrapper.__name__ = view.__name__
    return wrapper

@app.get("/dashboard")
@login_required
def dashboard():
    files = []
    for name in sorted(os.listdir(UPLOAD_DIR)):
        p = UPLOAD_DIR / name
        if p.is_file():
            files.append(name)
    return render_template("dashboard.html", user=current_user(), admin=is_admin(), files=files)

from flask import flash

@app.post("/upload")
@login_required
def upload():
    f = request.files.get("file")
    if not f or f.filename.strip() == "":
        flash("No file selected for upload.", "error")
        return redirect(url_for("dashboard"))

    filename = secure_filename(f.filename)

    # Require .pdf extension
    if not filename.lower().endswith(".pdf"):
        flash("Only PDF files are allowed.", "error")
        return redirect(url_for("dashboard"))

    # Build and check path
    dest = (UPLOAD_DIR / filename).resolve()
    if not str(dest).startswith(str(UPLOAD_DIR.resolve())):
        flash("Invalid file path.", "error")
        return redirect(url_for("dashboard"))

    f.save(dest)
    flash(f"File '{filename}' uploaded successfully.", "success")
    return redirect(url_for("dashboard"))


@app.get("/preview")
@login_required
def preview():
    target = request.args.get("file", "")

    if not target:
        abort(400, description="Missing file parameter.")

    # Admin: allow any file path
    if is_admin():
        p = Path(target)
        try:
            if p.is_file():
                return send_file(p, conditional=True)
            abort(404, description="File not found.")
        except FileNotFoundError:
            abort(404, description="File not found.")
        except PermissionError:
            abort(403, description="Permission denied.")
        except IsADirectoryError:
            abort(400, description="Path is a directory.")
        except Exception:
            abort(400, description="Unable to read file.")

    # Non-admin: restrict to PDFs in uploads/
    if "/" in target or "\\" in target:
        abort(400, description="Invalid file name.")
    if not target.lower().endswith(".pdf"):
        abort(403, description="Only PDF previews allowed.")
    p = (UPLOAD_DIR / target).resolve()
    if not str(p).startswith(str(UPLOAD_DIR.resolve())):
        abort(400, description="Invalid file path.")
    if not p.exists() or not p.is_file():
        abort(404, description="File not found.")
    return send_file(p)



if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001)
