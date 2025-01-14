import os
import sqlite3
import uuid

from flask import (
    Flask, render_template, request, redirect,
    url_for, flash, session
)
from flask_login import (
    LoginManager, UserMixin, login_user,
    logout_user, login_required, current_user
)
from werkzeug.security import (
    generate_password_hash, check_password_hash
)
from werkzeug.utils import secure_filename

import pyotp
import qrcode
import io

app = Flask(__name__)
app.secret_key = "CHANGE_ME_TO_A_RANDOM_SECRET"  # Replace with a random key

# --------------------
# Configuration
# --------------------
UPLOAD_FOLDER = os.path.join(os.getcwd(), 'static', 'uploads')
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024  # 2MB max size (example)

# --------------------
# Flask-Login setup
# --------------------
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

# --------------------
# Database setup
# --------------------
DB_NAME = "dashboard.db"

def init_db():
    """Create tables if they don't exist."""
    with sqlite3.connect(DB_NAME) as conn:
        c = conn.cursor()
        # Users table
        c.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                totp_secret TEXT DEFAULT '',
                totp_enabled INTEGER DEFAULT 0
            );
        ''')
        # Apps table
        c.execute('''
            CREATE TABLE IF NOT EXISTS apps (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                redirect_url TEXT NOT NULL,
                icon_path TEXT DEFAULT '',
                thumbnail_path TEXT DEFAULT ''
            );
        ''')
        conn.commit()

init_db()

# --------------------
# User Model
# --------------------
class User(UserMixin):
    def __init__(self, id_, username, password, totp_secret='', totp_enabled=0):
        self.id = id_
        self.username = username
        self.password = password
        self.totp_secret = totp_secret
        self.totp_enabled = totp_enabled

@login_manager.user_loader
def load_user(user_id):
    with sqlite3.connect(DB_NAME) as conn:
        c = conn.cursor()
        c.execute("""
            SELECT id, username, password, totp_secret, totp_enabled
            FROM users WHERE id=?
        """, (user_id,))
        row = c.fetchone()
        if row:
            return User(*row)
    return None

# --------------------
# Helper Functions
# --------------------
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def generate_filename(original_filename):
    """Generate a secure unique filename to avoid collisions."""
    ext = original_filename.rsplit('.', 1)[1].lower()
    return f"{uuid.uuid4()}.{ext}"

# --------------------
# Routes
# --------------------

@app.route('/')
@login_required
def index():
    # If TOTP is enabled for the user, but not verified in this session, redirect to TOTP verification
    if current_user.totp_enabled == 1 and not session.get('totp_verified', False):
        return redirect(url_for('verify_totp'))

    # Display all apps in the dashboard
    with sqlite3.connect(DB_NAME) as conn:
        c = conn.cursor()
        c.execute("""
            SELECT id, name, redirect_url, icon_path, thumbnail_path
            FROM apps
        """)
        apps = c.fetchall()
    return render_template('index.html', apps=apps)

# --------------------
# Authentication
# --------------------

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        with sqlite3.connect(DB_NAME) as conn:
            c = conn.cursor()
            c.execute("""
                SELECT id, username, password, totp_secret, totp_enabled
                FROM users
                WHERE username=?
            """, (username,))
            row = c.fetchone()
            if row and check_password_hash(row[2], password):
                user = User(*row)
                login_user(user)
                flash("Logged in successfully.", "success")

                # If user has TOTP enabled, we want them to verify TOTP
                # We'll set session['totp_verified'] to False, then redirect.
                if user.totp_enabled == 1:
                    session['totp_verified'] = False
                    return redirect(url_for('verify_totp'))

                # Otherwise, just go to index
                return redirect(url_for('index'))
            else:
                flash("Invalid username or password.", "danger")
                return redirect(url_for('login'))

    return render_template('login.html')

@app.route('/verify_totp', methods=['GET', 'POST'])
@login_required
def verify_totp():
    # If TOTP is not enabled, or already verified, go to index
    if current_user.totp_enabled == 0 or session.get('totp_verified', False):
        return redirect(url_for('index'))

    if request.method == 'POST':
        code = request.form.get('totp_code')
        # Validate TOTP code
        totp = pyotp.TOTP(current_user.totp_secret)
        if totp.verify(code, valid_window=1):
            session['totp_verified'] = True
            flash("2FA Verified!", "success")
            return redirect(url_for('index'))
        else:
            flash("Invalid 2FA code.", "danger")
            return redirect(url_for('verify_totp'))

    return render_template('verify_totp.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    session.pop('totp_verified', None)
    flash("You have been logged out.", "info")
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        hashed_pw = generate_password_hash(password)

        try:
            with sqlite3.connect(DB_NAME) as conn:
                c = conn.cursor()
                c.execute(
                    "INSERT INTO users (username, password) VALUES (?,?)",
                    (username, hashed_pw)
                )
                conn.commit()
            flash("Registration successful! You can now log in.", "success")
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash("Username already taken.", "danger")
            return redirect(url_for('register'))

    return render_template('register.html')

# --------------------
# Dashboard CRUD
# --------------------

@app.route('/add_app', methods=['GET', 'POST'])
@login_required
def add_app():
    # If TOTP is enabled for the user, verify TOTP before letting them add
    if current_user.totp_enabled == 1 and not session.get('totp_verified', False):
        return redirect(url_for('verify_totp'))

    if request.method == 'POST':
        name = request.form.get('name')
        redirect_url = request.form.get('redirect_url')
        
        # File uploads
        icon_file = request.files.get('icon_file')
        thumb_file = request.files.get('thumb_file')

        icon_path = ''
        thumbnail_path = ''

        if icon_file and allowed_file(icon_file.filename):
            filename = generate_filename(icon_file.filename)
            safe_name = secure_filename(filename)
            icon_file.save(os.path.join(app.config['UPLOAD_FOLDER'], safe_name))
            icon_path = f"static/uploads/{safe_name}"

        if thumb_file and allowed_file(thumb_file.filename):
            filename = generate_filename(thumb_file.filename)
            safe_name = secure_filename(filename)
            thumb_file.save(os.path.join(app.config['UPLOAD_FOLDER'], safe_name))
            thumbnail_path = f"static/uploads/{safe_name}"

        with sqlite3.connect(DB_NAME) as conn:
            c = conn.cursor()
            c.execute("""
                INSERT INTO apps (name, redirect_url, icon_path, thumbnail_path)
                VALUES (?,?,?,?)
            """, (name, redirect_url, icon_path, thumbnail_path))
            conn.commit()

        flash("App added to dashboard!", "success")
        return redirect(url_for('index'))

    return render_template('add_app.html')

@app.route('/edit_app/<int:app_id>', methods=['GET', 'POST'])
@login_required
def edit_app(app_id):
    if request.method == 'POST':
        # Handle form submission
        name = request.form.get('name')
        redirect_url = request.form.get('redirect_url')
        icon_file = request.files.get('icon_file')
        thumb_file = request.files.get('thumb_file')

        # Fetch existing record so we know old icon/thumbnail paths
        with sqlite3.connect(DB_NAME) as conn:
            c = conn.cursor()
            c.execute("""
                SELECT icon_path, thumbnail_path
                FROM apps
                WHERE id=?
            """, (app_id,))
            row = c.fetchone()
            old_icon_path = row[0] if row else ''
            old_thumbnail_path = row[1] if row else ''

        # If new icon uploaded, replace old icon
        new_icon_path = old_icon_path
        if icon_file and allowed_file(icon_file.filename):
            filename = secure_filename(icon_file.filename)
            # Make sure you have the full path. 
            # Possibly generate a unique name instead of using the original.
            icon_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            icon_file.save(icon_path)
            new_icon_path = f"static/uploads/{filename}"

            # (Optional) Delete old file if it exists and is different
            if old_icon_path and old_icon_path != new_icon_path:
                old_full_path = os.path.join(app.root_path, old_icon_path)
                if os.path.exists(old_full_path):
                    os.remove(old_full_path)

        # If new thumbnail uploaded, replace old thumbnail
        new_thumbnail_path = old_thumbnail_path
        if thumb_file and allowed_file(thumb_file.filename):
            filename = secure_filename(thumb_file.filename)
            thumb_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            thumb_file.save(thumb_path)
            new_thumbnail_path = f"static/uploads/{filename}"

            # (Optional) Delete old file if it exists and is different
            if old_thumbnail_path and old_thumbnail_path != new_thumbnail_path:
                old_full_path = os.path.join(app.root_path, old_thumbnail_path)
                if os.path.exists(old_full_path):
                    os.remove(old_full_path)

        # Update DB record
        with sqlite3.connect(DB_NAME) as conn:
            c = conn.cursor()
            c.execute("""
                UPDATE apps
                SET name=?, redirect_url=?, icon_path=?, thumbnail_path=?
                WHERE id=?
            """, (name, redirect_url, new_icon_path, new_thumbnail_path, app_id))
            conn.commit()

        flash("App updated successfully!", "success")
        return redirect(url_for('index'))
    else:
        # GET: Load current app info for the form
        with sqlite3.connect(DB_NAME) as conn:
            c = conn.cursor()
            c.execute("""
                SELECT id, name, redirect_url, icon_path, thumbnail_path
                FROM apps
                WHERE id=?
            """, (app_id,))
            app_data = c.fetchone()
        
        # If no record found, redirect or show error
        if not app_data:
            flash("App not found!", "danger")
            return redirect(url_for('index'))

        # Render form pre-filled with existing data
        return render_template('edit_app.html', app_data=app_data)


@app.route('/delete_app/<int:app_id>', methods=['GET'])
@login_required
def delete_app(app_id):
    # Fetch icon/thumbnail paths for potential deletion
    with sqlite3.connect(DB_NAME) as conn:
        c = conn.cursor()
        c.execute("""
            SELECT icon_path, thumbnail_path
            FROM apps
            WHERE id=?
        """, (app_id,))
        row = c.fetchone()
        if not row:
            flash("App not found!", "danger")
            return redirect(url_for('index'))

        icon_path, thumb_path = row[0], row[1]

    # Delete row from DB
    with sqlite3.connect(DB_NAME) as conn:
        c = conn.cursor()
        c.execute("DELETE FROM apps WHERE id=?", (app_id,))
        conn.commit()

    # (Optional) Delete files from disk
    if icon_path:
        full_icon_path = os.path.join(app.root_path, icon_path)
        if os.path.exists(full_icon_path):
            os.remove(full_icon_path)

    if thumb_path:
        full_thumb_path = os.path.join(app.root_path, thumb_path)
        if os.path.exists(full_thumb_path):
            os.remove(full_thumb_path)

    flash("App deleted successfully!", "info")
    return redirect(url_for('index'))
# --------------------
# Settings (Change Password & TOTP)
# --------------------

@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    """User settings: change password, enable/disable 2FA."""
    if request.method == 'POST':
        # Handle password change
        old_pass = request.form.get('old_password')
        new_pass = request.form.get('new_password')

        # Verify old password
        if check_password_hash(current_user.password, old_pass):
            hashed_pw = generate_password_hash(new_pass)
            with sqlite3.connect(DB_NAME) as conn:
                c = conn.cursor()
                c.execute("UPDATE users SET password=? WHERE id=?",
                          (hashed_pw, current_user.id))
                conn.commit()
            flash("Password updated.", "success")
        else:
            flash("Old password is incorrect.", "danger")
            return redirect(url_for('settings'))

        # Handle TOTP enable/disable
        action = request.form.get('2fa_action')
        if action == 'enable':
            # If user doesn’t already have a TOTP secret, generate one
            with sqlite3.connect(DB_NAME) as conn:
                c = conn.cursor()
                # Generate a new secret if not existing
                secret = pyotp.random_base32()
                c.execute("""
                    UPDATE users
                    SET totp_secret=?, totp_enabled=1
                    WHERE id=?
                """, (secret, current_user.id))
                conn.commit()
            flash("2FA enabled. Please scan the QR code below.", "warning")
            return redirect(url_for('setup_totp_qr'))
        elif action == 'disable':
            # Disable TOTP
            with sqlite3.connect(DB_NAME) as conn:
                c = conn.cursor()
                c.execute("""
                    UPDATE users
                    SET totp_secret='', totp_enabled=0
                    WHERE id=?
                """, (current_user.id,))
                conn.commit()
            flash("2FA disabled.", "info")

    return render_template('settings.html')

@app.route('/setup_totp_qr')
@login_required
def setup_totp_qr():
    """Generate and display the TOTP QR code for the user to scan."""
    # Refresh user from DB to get updated secret
    user = load_user(current_user.id)
    if user.totp_enabled == 0 or not user.totp_secret:
        flash("2FA is not enabled or no secret present. Enable 2FA first.", "danger")
        return redirect(url_for('settings'))

    # Generate the otpauth URL
    # Example: otpauth://totp/MyDashboard:{username}?secret={secret}&issuer=MyDashboard
    issuer_name = "MyDashboard"
    totp_uri = f"otpauth://totp/{issuer_name}:{user.username}?secret={user.totp_secret}&issuer={issuer_name}"

    # Use qrcode to generate image in memory
    qr_img = qrcode.make(totp_uri)
    img_io = io.BytesIO()
    qr_img.save(img_io, 'PNG')
    img_io.seek(0)

    # Convert to base64 to embed in HTML
    import base64
    qr_b64 = base64.b64encode(img_io.getvalue()).decode('utf-8')

    return render_template('setup_totp_qr.html', qr_b64=qr_b64, secret=user.totp_secret)

# --------------------
# Main
# --------------------
if __name__ == '__main__':
    # For dev
    # app.run(host="0.0.0.0", port=5000, debug=True)

    # For production with Gunicorn (example):
    # gunicorn -w 2 -b 0.0.0.0:8000 app:app
    app.run(host="0.0.0.0", port=5000)