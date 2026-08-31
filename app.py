import json
import os
import uuid
import secrets
import sqlite3
from datetime import datetime, timezone

from flask import (
    Flask,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

from werkzeug.security import generate_password_hash, check_password_hash


# ============================================================
# APP SETUP
# ============================================================

app = Flask(__name__)

SESSION_SECRET = (
    os.environ.get("NEWGEN_SECRET_KEY")
    or os.environ.get("SESSION_SECRET")
)

if not SESSION_SECRET:
    raise RuntimeError(
        "SESSION_SECRET or NEWGEN_SECRET_KEY must be configured."
    )

app.secret_key = SESSION_SECRET

ADMIN_USERNAME = os.environ.get("NEWGEN_ADMIN_USER")
ADMIN_PASSWORD = os.environ.get("NEWGEN_ADMIN_PASS")

ADMIN_CREDENTIALS_CONFIGURED = bool(
    ADMIN_USERNAME and ADMIN_PASSWORD
)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

EVENTS_FILE = os.path.join(BASE_DIR, "events.json")
DATABASE_FILE = os.path.join(BASE_DIR, "users.db")


# ============================================================
# DATABASE
# ============================================================

def get_db():
    connection = sqlite3.connect(DATABASE_FILE)
    connection.row_factory = sqlite3.Row
    return connection


def init_database():
    connection = get_db()

    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,

            first_name TEXT NOT NULL,
            last_name TEXT NOT NULL,
            username TEXT NOT NULL UNIQUE,

            email TEXT NOT NULL UNIQUE,
            phone TEXT NOT NULL,

            school TEXT NOT NULL,
            class_name TEXT NOT NULL,
            group_name TEXT NOT NULL,

            password_hash TEXT NOT NULL,

            email_verified INTEGER NOT NULL DEFAULT 0,
            phone_verified INTEGER NOT NULL DEFAULT 0,

            verification_token TEXT,
            created_at TEXT NOT NULL
        )
        """
    )

    connection.commit()
    connection.close()


init_database()


# ============================================================
# EVENTS
# ============================================================

def load_events():
    if not os.path.exists(EVENTS_FILE):
        return []

    with open(EVENTS_FILE, "r", encoding="utf-8") as file:
        try:
            data = json.load(file)
            return data if isinstance(data, list) else []
        except json.JSONDecodeError:
            return []


def save_events(events):
    with open(EVENTS_FILE, "w", encoding="utf-8") as file:
        json.dump(events, file, indent=2)


# ============================================================
# ADMIN AUTHENTICATION
# ============================================================

def is_admin_logged_in():
    return session.get("admin_logged_in") is True


# ============================================================
# MEMBER AUTHENTICATION
# ============================================================

def is_member_logged_in():
    return session.get("member_logged_in") is True


def get_current_member():
    user_id = session.get("member_id")

    if not user_id:
        return None

    connection = get_db()

    user = connection.execute(
        "SELECT * FROM users WHERE id = ?",
        (user_id,),
    ).fetchone()

    connection.close()

    return user


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
        events=events,
        member=get_current_member(),
    )


# ============================================================
# CREATIVE PAGES
# ============================================================

@app.route("/music-dance")
def music_dance():
    return render_template("music_dance.html")


@app.route("/art")
def art():
    return render_template("art.html")


@app.route("/poetry")
def poetry():
    return render_template("poetry.html")


@app.route("/tech")
def tech():
    return render_template("tech.html")


# ============================================================
# CALENDAR
# ============================================================

@app.route("/calendar")
def calendar():
    events = sorted(
        load_events(),
        key=lambda event: event.get("date", "")
    )

    featured_event = events[0] if events else None

    return render_template(
        "calendar.html",
        events=events,
        featured_event=featured_event,
    )


# ============================================================
# MEMBER SIGNUP
# ============================================================

@app.route("/signup", methods=["GET", "POST"])
def signup():

    if is_member_logged_in():
        return redirect(url_for("home"))

    if request.method == "POST":

        first_name = request.form.get(
            "first_name", ""
        ).strip()

        last_name = request.form.get(
            "last_name", ""
        ).strip()

        username = request.form.get(
            "username", ""
        ).strip()

        email = request.form.get(
            "email", ""
        ).strip().lower()

        phone = request.form.get(
            "phone", ""
        ).strip()

        school = request.form.get(
            "school", ""
        ).strip()

        class_name = request.form.get(
            "class_name", ""
        ).strip()

        group_name = request.form.get(
            "group_name", ""
        ).strip()

        password = request.form.get(
            "password", ""
        )

        confirm_password = request.form.get(
            "confirm_password", ""
        )

        # ----------------------------------------------------
        # BASIC VALIDATION
        # ----------------------------------------------------

        if not all([
            first_name,
            last_name,
            username,
            email,
            phone,
            school,
            class_name,
            group_name,
            password,
            confirm_password,
        ]):
            flash(
                "Please complete every field.",
                "error"
            )

            return render_template("signup.html")

        if password != confirm_password:
            flash(
                "Passwords do not match.",
                "error"
            )

            return render_template("signup.html")

        if len(password) < 8:
            flash(
                "Password must be at least 8 characters.",
                "error"
            )

            return render_template("signup.html")

        allowed_classes = {
            "Form 1",
            "Form 2",
            "Form 3",
        }

        allowed_groups = {
            "Music & Dance",
            "Tech",
            "Art",
            "Poetry",
            "Fashion",
        }

        if class_name not in allowed_classes:
            flash(
                "Please select a valid class.",
                "error"
            )

            return render_template("signup.html")

        if group_name not in allowed_groups:
            flash(
                "Please select a valid New Gen group.",
                "error"
            )

            return render_template("signup.html")

        # ----------------------------------------------------
        # CHECK EXISTING ACCOUNT
        # ----------------------------------------------------

        connection = get_db()

        existing_user = connection.execute(
            """
            SELECT id
            FROM users
            WHERE email = ? OR username = ?
            """,
            (email, username),
        ).fetchone()

        if existing_user:
            connection.close()

            flash(
                "That email or username is already registered.",
                "error"
            )

            return render_template("signup.html")

        # ----------------------------------------------------
        # HASH PASSWORD
        # ----------------------------------------------------

        password_hash = generate_password_hash(password)

        # ----------------------------------------------------
        # EMAIL VERIFICATION TOKEN
        # ----------------------------------------------------

        verification_token = secrets.token_urlsafe(32)

        created_at = datetime.now(
            timezone.utc
        ).isoformat()

        # ----------------------------------------------------
        # SAVE MEMBER
        # ----------------------------------------------------

        connection.execute(
            """
            INSERT INTO users (
                first_name,
                last_name,
                username,
                email,
                phone,
                school,
                class_name,
                group_name,
                password_hash,
                email_verified,
                phone_verified,
                verification_token,
                created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                first_name,
                last_name,
                username,
                email,
                phone,
                school,
                class_name,
                group_name,
                password_hash,
                0,
                0,
                verification_token,
                created_at,
            ),
        )

        connection.commit()
        connection.close()

        flash(
            "Account created successfully. "
            "Email verification will be sent next.",
            "success"
        )

        return redirect(url_for("login"))

    return render_template("signup.html")


# ============================================================
# MEMBER LOGIN
# ============================================================

@app.route("/login", methods=["GET", "POST"])
def login():

    if is_member_logged_in():
        return redirect(url_for("home"))

    if request.method == "POST":

        login_value = request.form.get(
            "login", ""
        ).strip()

        password = request.form.get(
            "password", ""
        )

        connection = get_db()

        user = connection.execute(
            """
            SELECT *
            FROM users
            WHERE email = ? OR username = ?
            """,
            (login_value.lower(), login_value),
        ).fetchone()

        connection.close()

        if not user or not check_password_hash(
            user["password_hash"],
            password
        ):
            flash(
                "Incorrect username/email or password.",
                "error"
            )

            return render_template("login.html")

        session.clear()

        session["member_logged_in"] = True
        session["member_id"] = user["id"]

        flash(
            f"Welcome back, {user['first_name']}!",
            "success"
        )

        return redirect(url_for("home"))

    return render_template("login.html")


# ============================================================
# MEMBER LOGOUT
# ============================================================

@app.route("/logout")
def logout():

    session.pop("member_logged_in", None)
    session.pop("member_id", None)

    flash(
        "You have been logged out.",
        "success"
    )

    return redirect(url_for("home"))


# ============================================================
# EMAIL VERIFICATION
# ============================================================

@app.route("/verify-email/<token>")
def verify_email(token):

    connection = get_db()

    user = connection.execute(
        """
        SELECT *
        FROM users
        WHERE verification_token = ?
        """,
        (token,),
    ).fetchone()

    if not user:
        connection.close()

        return render_template(
            "verify_email.html",
            success=False,
            message="This verification link is invalid or has expired."
        )

    connection.execute(
        """
        UPDATE users
        SET email_verified = 1,
            verification_token = NULL
        WHERE id = ?
        """,
        (user["id"],),
    )

    connection.commit()
    connection.close()

    return render_template(
        "verify_email.html",
        success=True,
        message="Your email has been successfully verified!"
    )


# ============================================================
# ADMIN LOGIN
# ============================================================

@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():

    if is_admin_logged_in():
        return redirect(url_for("admin"))

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
            "username", ""
        ).strip()

        password = request.form.get(
            "password", ""
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

            return redirect(url_for("admin"))

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

    session.pop("admin_logged_in", None)

    flash(
        "You have been logged out.",
        "success"
    )

    return redirect(url_for("admin_login"))


# ============================================================
# ADMIN EVENT MANAGEMENT
# ============================================================

@app.route("/admin", methods=["GET", "POST"])
@app.route("/admin/edit/<event_id>", methods=["GET", "POST"])
def admin(event_id=None):

    if not is_admin_logged_in():

        flash(
            "Please log in to manage events.",
            "error"
        )

        return redirect(url_for("admin_login"))

    events = sorted(
        load_events(),
        key=lambda event: event.get("date", "")
    )

    current_event = next(
        (
            event for event in events
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
            "title", ""
        ).strip()

        day = request.form.get(
            "day", ""
        ).strip()

        month = request.form.get(
            "month", ""
        ).strip()

        year = request.form.get(
            "year", ""
        ).strip()

        category = request.form.get(
            "category", ""
        ).strip()

        location = request.form.get(
            "location", ""
        ).strip()

        description = request.form.get(
            "description", ""
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
                event_data
                if item.get("id") == event_id_value
                else item
                for item in existing_events
            ]

        else:
            updated_events = (
                existing_events + [event_data]
            )

        save_events(updated_events)

        flash(
            "Event saved successfully.",
            "success"
        )

        return redirect(url_for("admin"))

    return render_template(
        "admin.html",
        events=events,
        event=current_event,
        mode="Edit" if current_event else "Create"
    )


# ============================================================
# ADMIN DELETE EVENT
# ============================================================

@app.route("/admin/delete/<event_id>", methods=["POST"])
def delete_event(event_id):

    if not is_admin_logged_in():

        flash(
            "Please log in to manage events.",
            "error"
        )

        return redirect(url_for("admin_login"))

    events = load_events()

    remaining = [
        event for event in events
        if event.get("id") != event_id
    ]

    save_events(remaining)

    flash(
        "Event deleted successfully.",
        "success"
    )

    return redirect(url_for("admin"))


# ============================================================
# ADMIN MEMBER LIST
# ============================================================

@app.route("/admin/members")
def admin_members():

    if not is_admin_logged_in():

        flash(
            "Please log in as an administrator.",
            "error"
        )

        return redirect(url_for("admin_login"))

    connection = get_db()

    members = connection.execute(
        """
        SELECT
            id,
            first_name,
            last_name,
            username,
            email,
            phone,
            school,
            class_name,
            group_name,
            email_verified,
            phone_verified,
            created_at
        FROM users
        ORDER BY created_at DESC
        """
    ).fetchall()

    connection.close()

    return render_template(
        "members.html",
        members=members
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


def build_iso_date(day, month, year):

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
# RUN
# ============================================================

if __name__ == "__main__":

    app.run(
        debug=os.environ.get("FLASK_DEBUG") == "1",
        host="0.0.0.0",
        port=int(
            os.environ.get("PORT", "5000")
        ),
    )
