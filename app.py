```python
import json
import os
import uuid
import random
import sqlite3
import secrets
import smtplib
from email.message import EmailMessage
from datetime import datetime, timedelta

from flask import (
    Flask,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
    jsonify,
)

from werkzeug.security import generate_password_hash, check_password_hash


app = Flask(__name__)

# ============================================================
# SECURITY
# ============================================================

SESSION_SECRET = (
    os.environ.get("NEWGEN_SECRET_KEY")
    or os.environ.get("SESSION_SECRET")
)

if not SESSION_SECRET:
    raise RuntimeError(
        "SESSION_SECRET or NEWGEN_SECRET_KEY must be configured."
    )

app.secret_key = SESSION_SECRET

# ============================================================
# ADMIN
# ============================================================

ADMIN_USERNAME = os.environ.get("NEWGEN_ADMIN_USER")
ADMIN_PASSWORD = os.environ.get("NEWGEN_ADMIN_PASS")

ADMIN_CREDENTIALS_CONFIGURED = bool(
    ADMIN_USERNAME and ADMIN_PASSWORD
)

# ============================================================
# EMAIL SETTINGS
# ============================================================

EMAIL_HOST = os.environ.get("EMAIL_HOST")
EMAIL_PORT = int(os.environ.get("EMAIL_PORT", "587"))
EMAIL_USERNAME = os.environ.get("EMAIL_USERNAME")
EMAIL_PASSWORD = os.environ.get("EMAIL_PASSWORD")
EMAIL_FROM = os.environ.get("EMAIL_FROM") or EMAIL_USERNAME


# ============================================================
# FILE LOCATIONS
# ============================================================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

EVENTS_FILE = os.path.join(
    BASE_DIR,
    "events.json"
)

DATABASE_FILE = os.path.join(
    BASE_DIR,
    "users.db"
)


# ============================================================
# DATABASE
# ============================================================

def get_db():
    connection = sqlite3.connect(DATABASE_FILE)
    connection.row_factory = sqlite3.Row
    return connection


def init_database():

    connection = get_db()

    connection.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            phone TEXT,
            password_hash TEXT NOT NULL,
            verified INTEGER DEFAULT 0,
            verification_code TEXT,
            verification_expires TEXT,
            reset_code TEXT,
            reset_expires TEXT,
            created_at TEXT NOT NULL
        )
    """)

    connection.commit()
    connection.close()


init_database()


# ============================================================
# EMAIL
# ============================================================

def send_email(to_email, subject, body):

    if not EMAIL_HOST or not EMAIL_USERNAME or not EMAIL_PASSWORD:
        print("EMAIL SETTINGS ARE NOT CONFIGURED.")
        print("Email would have been sent to:", to_email)
        print("Subject:", subject)
        print("Message:", body)
        return False

    message = EmailMessage()

    message["Subject"] = subject
    message["From"] = EMAIL_FROM
    message["To"] = to_email

    message.set_content(body)

    try:

        with smtplib.SMTP(
            EMAIL_HOST,
            EMAIL_PORT
        ) as server:

            server.starttls()

            server.login(
                EMAIL_USERNAME,
                EMAIL_PASSWORD
            )

            server.send_message(message)

        return True

    except Exception as error:

        print("EMAIL ERROR:", error)

        return False


# ============================================================
# OTP
# ============================================================

def generate_otp():

    return f"{random.randint(0, 999999):06d}"


def otp_expiration():

    return (
        datetime.utcnow()
        + timedelta(minutes=10)
    ).isoformat()


# ============================================================
# EVENTS
# ============================================================

def load_events():

    if not os.path.exists(EVENTS_FILE):
        return []

    with open(
        EVENTS_FILE,
        "r",
        encoding="utf-8"
    ) as file:

        try:

            data = json.load(file)

            return data if isinstance(data, list) else []

        except json.JSONDecodeError:

            return []


def save_events(events):

    with open(
        EVENTS_FILE,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            events,
            file,
            indent=2
        )


# ============================================================
# ADMIN AUTHENTICATION
# ============================================================

def is_admin_logged_in():

    return session.get(
        "admin_logged_in"
    ) is True


# ============================================================
# HOME
# ============================================================

@app.route("/")
def home():

    events = sorted(
        load_events(),
        key=lambda event: event.get("date", "")
    )[:3]

    return render_template(
        "index.html",
        events=events
    )


# ============================================================
# CLUB PAGES
# ============================================================

@app.route("/music-dance")
def music_dance():

    return render_template(
        "music_dance.html"
    )


@app.route("/art")
def art():

    return render_template(
        "art.html"
    )


@app.route("/poetry")
def poetry():

    return render_template(
        "poetry.html"
    )


@app.route("/tech")
def tech():

    return render_template(
        "tech.html"
    )


@app.route("/calendar")
def calendar():

    events = sorted(
        load_events(),
        key=lambda event: event.get("date", "")
    )

    featured_event = (
        events[0]
        if events
        else None
    )

    return render_template(
        "calendar.html",
        events=events,
        featured_event=featured_event
    )


# ============================================================
# MEMBER REGISTRATION
# ============================================================

@app.route(
    "/register",
    methods=["GET", "POST"]
)
def register():

    if session.get("user_id"):

        return redirect(
            url_for("dashboard")
        )

    if request.method == "POST":

        name = request.form.get(
            "name",
            ""
        ).strip()

        email = request.form.get(
            "email",
            ""
        ).strip().lower()

        phone = request.form.get(
            "phone",
            ""
        ).strip()

        password = request.form.get(
            "password",
            ""
        )

        if not name or not email or not password:

            flash(
                "Please complete all required fields.",
                "error"
            )

            return render_template(
                "register.html"
            )

        if "@" not in email or "." not in email:

            flash(
                "Please enter a valid email address.",
                "error"
            )

            return render_template(
                "register.html"
            )

        if len(password) < 8:

            flash(
                "Password must contain at least 8 characters.",
                "error"
            )

            return render_template(
                "register.html"
            )

        connection = get_db()

        existing = connection.execute(
            "SELECT id FROM users WHERE email = ?",
            (email,)
        ).fetchone()

        if existing:

            connection.close()

            flash(
                "An account with this email already exists.",
                "error"
            )

            return render_template(
                "register.html"
            )

        verification_code = generate_otp()

        expiration = otp_expiration()

        password_hash = generate_password_hash(
            password
        )

        connection.execute(
            """
            INSERT INTO users
            (
                name,
                email,
                phone,
                password_hash,
                verified,
                verification_code,
                verification_expires,
                created_at
            )
            VALUES (?, ?, ?, ?, 0, ?, ?, ?)
            """,
            (
                name,
                email,
                phone,
                password_hash,
                verification_code,
                expiration,
                datetime.utcnow().isoformat()
            )
        )

        connection.commit()

        user = connection.execute(
            "SELECT id FROM users WHERE email = ?",
            (email,)
        ).fetchone()

        connection.close()

        send_email(
            email,
            "Verify your New Gen account",
            f"""
Welcome to New Gen!

Your verification code is:

{verification_code}

This code expires in 10 minutes.

If you did not create this account, you can ignore this email.
"""
        )

        session["verification_user_id"] = user["id"]

        return redirect(
            url_for("verify")
        )

    return render_template(
        "register.html"
    )


# ============================================================
# EMAIL VERIFICATION
# ============================================================

@app.route(
    "/verify",
    methods=["GET", "POST"]
)
def verify():

    user_id = session.get(
        "verification_user_id"
    )

    if not user_id:

        return redirect(
            url_for("register")
        )

    connection = get_db()

    user = connection.execute(
        "SELECT * FROM users WHERE id = ?",
        (user_id,)
    ).fetchone()

    if not user:

        connection.close()

        session.pop(
            "verification_user_id",
            None
        )

        return redirect(
            url_for("register")
        )

    if request.method == "POST":

        code = request.form.get(
            "code",
            ""
        ).strip()

        if user["verification_expires"]:

            expires = datetime.fromisoformat(
                user["verification_expires"]
            )

            if datetime.utcnow() > expires:

                connection.close()

                flash(
                    "That verification code has expired.",
                    "error"
                )

                return render_template(
                    "verify.html",
                    email=user["email"]
                )

        if code != user["verification_code"]:

            connection.close()

            flash(
                "Incorrect verification code.",
                "error"
            )

            return render_template(
                "verify.html",
                email=user["email"]
            )

        connection.execute(
            """
            UPDATE users
            SET verified = 1,
                verification_code = NULL,
                verification_expires = NULL
            WHERE id = ?
            """,
            (user_id,)
        )

        connection.commit()

        connection.close()

        session.pop(
            "verification_user_id",
            None
        )

        session["user_id"] = user_id

        flash(
            "Email verified successfully!",
            "success"
        )

        return redirect(
            url_for("dashboard")
        )

    connection.close()

    return render_template(
        "verify.html",
        email=user["email"]
    )


# ============================================================
# LOGIN
# ============================================================

@app.route(
    "/login",
    methods=["GET", "POST"]
)
def login():

    if session.get("user_id"):

        return redirect(
            url_for("dashboard")
        )

    if request.method == "POST":

        email = request.form.get(
            "email",
            ""
        ).strip().lower()

        password = request.form.get(
            "password",
            ""
        )

        connection = get_db()

        user = connection.execute(
            "SELECT * FROM users WHERE email = ?",
            (email,)
        ).fetchone()

        connection.close()

        if not user:

            flash(
                "Incorrect email or password.",
                "error"
            )

            return render_template(
                "login.html"
            )

        if not check_password_hash(
            user["password_hash"],
            password
        ):

            flash(
                "Incorrect email or password.",
                "error"
            )

            return render_template(
                "login.html"
            )

        if not user["verified"]:

            session["verification_user_id"] = user["id"]

            flash(
                "Please verify your email first.",
                "error"
            )

            return redirect(
                url_for("verify")
            )

        session.clear()

        session["user_id"] = user["id"]

        return redirect(
            url_for("dashboard")
        )

    return render_template(
        "login.html"
    )


# ============================================================
# MEMBER LOGOUT
# ============================================================

@app.route("/logout")
def logout():

    session.pop(
        "user_id",
        None
    )

    flash(
        "You have been logged out.",
        "success"
    )

    return redirect(
        url_for("home")
    )


# ============================================================
# DASHBOARD
# ============================================================

@app.route("/dashboard")
def dashboard():

    user_id = session.get(
        "user_id"
    )

    if not user_id:

        return redirect(
            url_for("login")
        )

    connection = get_db()

    user = connection.execute(
        """
        SELECT id, name, email, phone, verified
        FROM users
        WHERE id = ?
        """,
        (user_id,)
    ).fetchone()

    connection.close()

    if not user:

        session.clear()

        return redirect(
            url_for("login")
        )

    return render_template(
        "dashboard.html",
        user=user
    )


# ============================================================
# CURRENT USER API
# ============================================================

@app.route("/api/me")
def api_me():

    user_id = session.get(
        "user_id"
    )

    if not user_id:

        return jsonify({
            "logged_in": False
        })

    connection = get_db()

    user = connection.execute(
        """
        SELECT id, name, email
        FROM users
        WHERE id = ?
        """,
        (user_id,)
    ).fetchone()

    connection.close()

    if not user:

        return jsonify({
            "logged_in": False
        })

    return jsonify({
        "logged_in": True,
        "id": user["id"],
        "name": user["name"],
        "email": user["email"]
    })


# ============================================================
# ADMIN LOGIN
# ============================================================

@app.route(
    "/admin/login",
    methods=["GET", "POST"]
)
def admin_login():

    if is_admin_logged_in():

        return redirect(
            url_for("admin")
        )

    if not ADMIN_CREDENTIALS_CONFIGURED:

        flash(
            "Admin access is unavailable until secure credentials are configured.",
            "error"
        )

        return render_template(
            "admin_login.html"
        ), 503

    if request.method == "POST":

        username = request.form.get(
            "username",
            ""
        ).strip()

        password = request.form.get(
            "password",
            ""
        ).strip()

        if (
            username == ADMIN_USERNAME
            and password == ADMIN_PASSWORD
        ):

            session["admin_logged_in"] = True

            flash(
                "Admin access granted.",
                "success"
            )

            return redirect(
                url_for("admin")
            )

        flash(
            "Incorrect username or password.",
            "error"
        )

    return render_template(
        "admin_login.html"
    )


# ============================================================
# ADMIN LOGOUT
# ============================================================

@app.route("/admin/logout")
def admin_logout():

    session.pop(
        "admin_logged_in",
        None
    )

    flash(
        "You have been logged out.",
        "success"
    )

    return redirect(
        url_for("admin_login")
    )


# ============================================================
# ADMIN EVENT MANAGEMENT
# ============================================================

@app.route(
    "/admin",
    methods=["GET", "POST"]
)
@app.route(
    "/admin/edit/<event_id>",
    methods=["GET", "POST"]
)
def admin(event_id=None):

    if not is_admin_logged_in():

        flash(
            "Please log in to manage events.",
            "error"
        )

        return redirect(
            url_for("admin_login")
        )

    events = sorted(
        load_events(),
        key=lambda event: event.get(
            "date",
            ""
        )
    )

    current_event = next(
        (
            event
            for event in events
            if event.get("id") == event_id
        ),
        None
    )

    if request.method == "POST":

        event_id_value = (
            request.form.get("event_id")
            or str(uuid.uuid4())
        )

        title = request.form.get(
            "title",
            ""
        ).strip()

        day = request.form.get(
            "day",
            ""
        ).strip()

        month = request.form.get(
            "month",
            ""
        ).strip()

        year = request.form.get(
            "year",
            ""
        ).strip()

        category = request.form.get(
            "category",
            ""
        ).strip()

        location = request.form.get(
            "location",
            ""
        ).strip()

        description = request.form.get(
            "description",
            ""
        ).strip()

        date_value = build_iso_date(
            day,
            month,
            year
        )

        if not title or not date_value:

            flash(
                "Title and complete date are required.",
                "error"
            )

            return render_template(
                "admin.html",
                events=events,
                event=current_event,
                mode="Create"
            )

        event_data = {
            "id": event_id_value,
            "title": title,
            "date": date_value,
            "category": category,
            "location": location,
            "description": description,
        }

        existing_events = load_events()

        if any(
            item.get("id") == event_id_value
            for item in existing_events
        ):

            updated_events = [
                (
                    event_data
                    if item.get("id") == event_id_value
                    else item
                )
                for item in existing_events
            ]

        else:

            updated_events = (
                existing_events
                + [event_data]
            )

        save_events(
            updated_events
        )

        flash(
            "Event saved successfully.",
            "success"
        )

        return redirect(
            url_for("admin")
        )

    return render_template(
        "admin.html",
        events=events,
        event=current_event,
        mode=(
            "Edit"
            if current_event
            else "Create"
        )
    )


# ============================================================
# DELETE EVENT
# ============================================================

@app.route(
    "/admin/delete/<event_id>",
    methods=["POST"]
)
def delete_event(event_id):

    if not is_admin_logged_in():

        flash(
            "Please log in to manage events.",
            "error"
        )

        return redirect(
            url_for("admin_login")
        )

    events = load_events()

    remaining = [
        event
        for event in events
        if event.get("id") != event_id
    ]

    save_events(
        remaining
    )

    flash(
        "Event deleted successfully.",
        "success"
    )

    return redirect(
        url_for("admin")
    )


# ============================================================
# DATE HELPERS
# ============================================================

def format_display_date(value):

    if not value:
        return ""

    try:

        year, month, day = value.split("-")

        return f"{day}/{month}/{year}"

    except ValueError:

        return value


def build_iso_date(
    day,
    month,
    year
):

    day = str(day).strip().zfill(2)

    month = str(month).strip().zfill(2)

    year = str(year).strip()

    if not day or not month or not year:

        return ""

    return f"{year}-{month}-{day}"


app.jinja_env.globals[
    "format_display_date"
] = format_display_date


# ============================================================
# RUN SERVER
# ============================================================

if __name__ == "__main__":

    app.run(
        debug=(
            os.environ.get(
                "FLASK_DEBUG"
            ) == "1"
        ),
        host="0.0.0.0",
        port=int(
            os.environ.get(
                "PORT",
                "5000"
            )
        ),
    )
```
