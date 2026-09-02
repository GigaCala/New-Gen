import json
import os
import uuid
import secrets
import sqlite3
import smtplib
from email.message import EmailMessage
from datetime import datetime, timezone, timedelta

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

# ============================================================
# LEADERSHIP RECOGNITION
# ============================================================
# Add the real leadership names and positions here later.
# Members never choose these roles during signup.
LEADERSHIP = {
    # ("first", "last"): {
    #     "role": "admin",
    #     "position": "Administrator",
    # },
    # ("first", "last"): {
    #     "role": "executive",
    #     "position": "President",
    # },
}

# ============================================================
# EMAIL CONFIGURATION
# ============================================================
# Configure these as Render Environment Variables.
SMTP_HOST = os.environ.get("NEWGEN_SMTP_HOST", "")
SMTP_PORT = int(os.environ.get("NEWGEN_SMTP_PORT", "587"))
SMTP_USERNAME = os.environ.get("NEWGEN_SMTP_USERNAME", "")
SMTP_PASSWORD = os.environ.get("NEWGEN_SMTP_PASSWORD", "")
EMAIL_FROM = os.environ.get("NEWGEN_EMAIL_FROM", SMTP_USERNAME)

EMAIL_CONFIGURED = bool(
    SMTP_HOST and SMTP_USERNAME and SMTP_PASSWORD and EMAIL_FROM
)

VERIFICATION_EXPIRY_HOURS = 24

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

    # Main members table
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

            reason_for_joining TEXT NOT NULL DEFAULT '',

            password_hash TEXT NOT NULL,

            email_verified INTEGER NOT NULL DEFAULT 0,
            phone_verified INTEGER NOT NULL DEFAULT 0,

            verification_token TEXT,
            verification_expires_at TEXT,

            role TEXT NOT NULL DEFAULT 'member',
            position TEXT NOT NULL DEFAULT '',

            created_at TEXT NOT NULL
        )
        """
    )

    # Executive applications
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS executive_applications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,

            user_id INTEGER NOT NULL,

            position TEXT NOT NULL,
            reason TEXT NOT NULL,

            status TEXT NOT NULL DEFAULT 'pending',

            created_at TEXT NOT NULL,

            FOREIGN KEY (user_id) REFERENCES users(id)
        )
        """
    )

    # --------------------------------------------------------
    # DATABASE MIGRATION
    # --------------------------------------------------------
    # This allows an older users.db to receive new columns
    # without destroying existing members.
    # --------------------------------------------------------

    columns = connection.execute(
        "PRAGMA table_info(users)"
    ).fetchall()

    existing_columns = {
        column["name"] for column in columns
    }

    if "reason_for_joining" not in existing_columns:
        connection.execute(
            """
            ALTER TABLE users
            ADD COLUMN reason_for_joining TEXT NOT NULL DEFAULT ''
            """
        )

    if "role" not in existing_columns:
        connection.execute(
            """
            ALTER TABLE users
            ADD COLUMN role TEXT NOT NULL DEFAULT 'member'
            """
        )

    if "phone_verified" not in existing_columns:
        connection.execute(
            """
            ALTER TABLE users
            ADD COLUMN phone_verified INTEGER NOT NULL DEFAULT 0
            """
        )

    if "verification_token" not in existing_columns:
        connection.execute(
            """
            ALTER TABLE users
            ADD COLUMN verification_token TEXT
            """
        )

    if "verification_expires_at" not in existing_columns:
        connection.execute(
            """
            ALTER TABLE users
            ADD COLUMN verification_expires_at TEXT
            """
        )

    if "position" not in existing_columns:
        connection.execute(
            """
            ALTER TABLE users
            ADD COLUMN position TEXT NOT NULL DEFAULT ''
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
# SESSION / AUTH HELPERS
# ============================================================

def is_admin_logged_in():
    if session.get("admin_logged_in") is True:
        return True

    admin_member_id = session.get("admin_member_id")

    if not admin_member_id:
        return False

    connection = get_db()
    user = connection.execute(
        """
        SELECT role
        FROM users
        WHERE id = ?
        """,
        (admin_member_id,),
    ).fetchone()
    connection.close()

    return bool(user and user["role"] == "admin")


def is_member_logged_in():
    return session.get("member_logged_in") is True


def get_current_member():
    user_id = session.get("member_id")

    if not user_id:
        return None

    connection = get_db()

    user = connection.execute(
        """
        SELECT *
        FROM users
        WHERE id = ?
        """,
        (user_id,),
    ).fetchone()

    connection.close()

    return user


def is_executive():
    user = get_current_member()

    if not user:
        return False

    return user["role"] == "executive"


def normalize_name(value):
    return " ".join(value.strip().lower().split())


def get_leadership_match(first_name, last_name):
    key = (
        normalize_name(first_name),
        normalize_name(last_name),
    )
    return LEADERSHIP.get(key)


def send_verification_email(recipient, first_name, verification_url):
    if not EMAIL_CONFIGURED:
        raise RuntimeError(
            "Email delivery is not configured. "
            "Set the NEWGEN_SMTP_* and NEWGEN_EMAIL_FROM environment variables."
        )

    message = EmailMessage()
    message["Subject"] = "Verify your New Gen account"
    message["From"] = EMAIL_FROM
    message["To"] = recipient

    message.set_content(
        f"""Hi {first_name},

Welcome to New Gen — African children must speak.

Your account has been created. Please verify your email address by opening this link:

{verification_url}

This verification link expires in {VERIFICATION_EXPIRY_HOURS} hours.

If you did not create a New Gen account, you can safely ignore this email.

— New Gen
"""
    )

    with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=20) as smtp:
        smtp.starttls()
        smtp.login(SMTP_USERNAME, SMTP_PASSWORD)
        smtp.send_message(message)


# ============================================================
# GLOBAL TEMPLATE DATA
# ============================================================

@app.context_processor
def inject_member():
    return {
        "member": get_current_member()
    }

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


@app.route("/fashion")
def fashion():
    return render_template("fashion.html")


# ============================================================
# CONTACT
# ============================================================

@app.route("/contact")
def contact():
    return render_template("contact.html")


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

        reason_for_joining = request.form.get(
            "reason_for_joining", ""
        ).strip()

        password = request.form.get(
            "password", ""
        )

        confirm_password = request.form.get(
            "confirm_password", ""
        )

        # ----------------------------------------------------
        # REQUIRED FIELDS
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
            reason_for_joining,
            password,
            confirm_password,
        ]):
            flash(
                "Please complete every field.",
                "error"
            )

            return render_template("signup.html")

        # ----------------------------------------------------
        # PASSWORD
        # ----------------------------------------------------

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

        # ----------------------------------------------------
        # VALID OPTIONS
        # ----------------------------------------------------

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

        verification_expires_at = (
            datetime.now(timezone.utc)
            + timedelta(hours=VERIFICATION_EXPIRY_HOURS)
        ).isoformat()

        leadership_match = get_leadership_match(
            first_name,
            last_name,
        )

        assigned_role = "member"
        assigned_position = ""

        if leadership_match:
            assigned_role = leadership_match["role"]
            assigned_position = leadership_match.get("position", "")

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
                reason_for_joining,
                password_hash,
                email_verified,
                phone_verified,
                verification_token,
                verification_expires_at,
                role,
                position,
                created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                reason_for_joining,
                password_hash,
                0,
                0,
                verification_token,
                verification_expires_at,
                assigned_role,
                assigned_position,
                created_at,
            ),
        )

        connection.commit()
        connection.close()

        verification_url = url_for(
            "verify_email",
            token=verification_token,
            _external=True,
        )

        try:
            send_verification_email(
                email,
                first_name,
                verification_url,
            )
        except Exception:
            flash(
                "Your account was created, but we could not send "
                "the verification email yet. Please use the resend "
                "verification option.",
                "error",
            )
            return redirect(url_for("verify_notice", email=email))

        flash(
            "Account created successfully. Check your email to verify your New Gen account.",
            "success"
        )

        return redirect(url_for("verify_notice", email=email))

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
            (
                login_value.lower(),
                login_value,
            ),
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

        # ----------------------------------------------------
        # EMAIL VERIFICATION CHECK
        # ----------------------------------------------------

        if not user["email_verified"]:
            flash(
                "Please verify your email before logging in.",
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

        if user["role"] == "admin":
            session["admin_member_id"] = user["id"]
            return redirect(url_for("admin"))

        if user["role"] == "executive":
            return redirect(url_for("executive_dashboard"))

        return redirect(url_for("member_dashboard"))

    return render_template("login.html")


# ============================================================
# MEMBER DASHBOARD
# ============================================================

@app.route("/dashboard")
def member_dashboard():

    if not is_member_logged_in():
        flash(
            "Please log in to access your dashboard.",
            "error"
        )

        return redirect(url_for("login"))

    member = get_current_member()

    if not member:
        session.clear()

        flash(
            "Your account could not be found.",
            "error"
        )

        return redirect(url_for("login"))

    return render_template(
        "member_dashboard.html",
        member=member,
    )


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

@app.route("/verify-notice")
def verify_notice():
    email = request.args.get("email", "").strip().lower()

    return render_template(
        "verify_email.html",
        notice=True,
        email=email,
    )


@app.route("/resend-verification", methods=["POST"])
def resend_verification():
    email = request.form.get("email", "").strip().lower()

    if not email:
        flash("Please enter your email address.", "error")
        return redirect(url_for("login"))

    connection = get_db()

    user = connection.execute(
        """
        SELECT *
        FROM users
        WHERE email = ?
        """,
        (email,),
    ).fetchone()

    if not user:
        connection.close()
        flash(
            "If that account exists, a verification email will be sent.",
            "success",
        )
        return redirect(url_for("login"))

    if user["email_verified"]:
        connection.close()
        flash("That email is already verified. You can log in.", "success")
        return redirect(url_for("login"))

    verification_token = secrets.token_urlsafe(32)
    verification_expires_at = (
        datetime.now(timezone.utc)
        + timedelta(hours=VERIFICATION_EXPIRY_HOURS)
    ).isoformat()

    connection.execute(
        """
        UPDATE users
        SET verification_token = ?,
            verification_expires_at = ?
        WHERE id = ?
        """,
        (
            verification_token,
            verification_expires_at,
            user["id"],
        ),
    )

    connection.commit()
    connection.close()

    verification_url = url_for(
        "verify_email",
        token=verification_token,
        _external=True,
    )

    try:
        send_verification_email(
            user["email"],
            user["first_name"],
            verification_url,
        )
    except Exception:
        flash(
            "We could not send the verification email right now. Please try again shortly.",
            "error",
        )
        return redirect(url_for("verify_notice", email=email))

    flash("A new verification email has been sent.", "success")
    return redirect(url_for("verify_notice", email=email))


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
            message="This verification link is invalid or has already been used.",
        )

    expires_at = user["verification_expires_at"]

    if expires_at:
        try:
            expiry = datetime.fromisoformat(expires_at)

            if expiry.tzinfo is None:
                expiry = expiry.replace(tzinfo=timezone.utc)

            if datetime.now(timezone.utc) > expiry:
                connection.close()

                return render_template(
                    "verify_email.html",
                    success=False,
                    message="This verification link has expired. Please request a new one.",
                    email=user["email"],
                    expired=True,
                )

        except ValueError:
            connection.close()

            return render_template(
                "verify_email.html",
                success=False,
                message="This verification link is invalid. Please request a new one.",
                email=user["email"],
            )

    connection.execute(
        """
        UPDATE users
        SET email_verified = 1,
            verification_token = NULL,
            verification_expires_at = NULL
        WHERE id = ?
        """,
        (user["id"],),
    )

    connection.commit()
    connection.close()

    return render_template(
        "verify_email.html",
        success=True,
        message="Your email has been successfully verified!",
    )


# ============================================================
# EXECUTIVE APPLICATION
# ============================================================

@app.route("/executive/apply", methods=["GET", "POST"])
def executive_apply():

    if not is_member_logged_in():
        flash(
            "You must have a New Gen member account before applying to become an executive.",
            "error"
        )

        return redirect(url_for("login"))

    member = get_current_member()

    if not member:
        session.clear()
        return redirect(url_for("login"))

    if member["role"] == "executive":
        return redirect(url_for("executive_dashboard"))

    if request.method == "POST":

        position = request.form.get(
            "position",
            ""
        ).strip()

        reason = request.form.get(
            "reason",
            ""
        ).strip()

        if not position or not reason:
            flash(
                "Please complete the executive application.",
                "error"
            )

            return render_template(
                "executive_apply.html",
                member=member,
            )

        connection = get_db()

        existing_application = connection.execute(
            """
            SELECT id
            FROM executive_applications
            WHERE user_id = ?
            AND status = 'pending'
            """,
            (member["id"],),
        ).fetchone()

        if existing_application:
            connection.close()

            flash(
                "You already have a pending executive application.",
                "error"
            )

            return redirect(url_for("member_dashboard"))

        created_at = datetime.now(
            timezone.utc
        ).isoformat()

        connection.execute(
            """
            INSERT INTO executive_applications (
                user_id,
                position,
                reason,
                status,
                created_at
            )
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                member["id"],
                position,
                reason,
                "pending",
                created_at,
            ),
        )

        connection.commit()
        connection.close()

        flash(
            "Your executive application has been submitted for review.",
            "success"
        )

        return redirect(url_for("member_dashboard"))

    return render_template(
        "executive_apply.html",
        member=member,
    )


# ============================================================
# EXECUTIVE DASHBOARD
# ============================================================

@app.route("/executive")
def executive_dashboard():

    if not is_member_logged_in():
        flash(
            "Please log in first.",
            "error"
        )

        return redirect(url_for("login"))

    member = get_current_member()

    if not member or member["role"] != "executive":
        flash(
            "Executive access is restricted to approved New Gen executives.",
            "error"
        )

        return redirect(url_for("member_dashboard"))

    connection = get_db()

    applications = connection.execute(
        """
        SELECT
            ea.*,
            u.first_name,
            u.last_name,
            u.username,
            u.email,
            u.school,
            u.class_name,
            u.group_name
        FROM executive_applications ea
        JOIN users u
            ON ea.user_id = u.id
        ORDER BY ea.created_at DESC
        """
    ).fetchall()

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
            reason_for_joining,
            role,
            position,
            email_verified,
            phone_verified,
            created_at
        FROM users
        ORDER BY created_at DESC
        """
    ).fetchall()

    connection.close()

    return render_template(
        "executive_dashboard.html",
        member=member,
        applications=applications,
        members=members,
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
            session.clear()

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
        event
        for event in events
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
            reason_for_joining,
            role,
            position,
            email_verified,
            phone_verified,
            created_at
        FROM users
        ORDER BY created_at DESC
        """
    ).fetchall()

    applications = connection.execute(
        """
        SELECT
            ea.id,
            ea.user_id,
            ea.position,
            ea.reason,
            ea.status,
            ea.created_at,

            u.first_name,
            u.last_name,
            u.username,
            u.email,
            u.school,
            u.class_name,
            u.group_name

        FROM executive_applications ea

        JOIN users u
            ON ea.user_id = u.id

        ORDER BY ea.created_at DESC
        """
    ).fetchall()

    connection.close()

    return render_template(
        "members.html",
        members=members,
        applications=applications,
    )


# ============================================================
# ADMIN APPROVE EXECUTIVE
# ============================================================

@app.route(
    "/admin/executive/<int:application_id>/approve",
    methods=["POST"]
)
def approve_executive(application_id):

    if not is_admin_logged_in():
        flash(
            "Administrator access required.",
            "error"
        )

        return redirect(url_for("admin_login"))

    connection = get_db()

    application = connection.execute(
        """
        SELECT *
        FROM executive_applications
        WHERE id = ?
        """,
        (application_id,),
    ).fetchone()

    if not application:
        connection.close()

        flash(
            "Executive application not found.",
            "error"
        )

        return redirect(url_for("admin_members"))

    connection.execute(
        """
        UPDATE executive_applications
        SET status = 'approved'
        WHERE id = ?
        """,
        (application_id,),
    )

    connection.execute(
        """
        UPDATE users
        SET role = 'executive'
        WHERE id = ?
        """,
        (application["user_id"],),
    )

    connection.commit()
    connection.close()

    flash(
        "Executive application approved.",
        "success"
    )

    return redirect(url_for("admin_members"))


# ============================================================
# ADMIN REJECT EXECUTIVE
# ============================================================

@app.route(
    "/admin/executive/<int:application_id>/reject",
    methods=["POST"]
)
def reject_executive(application_id):

    if not is_admin_logged_in():
        flash(
            "Administrator access required.",
            "error"
        )

        return redirect(url_for("admin_login"))

    connection = get_db()

    connection.execute(
        """
        UPDATE executive_applications
        SET status = 'rejected'
        WHERE id = ?
        """,
        (application_id,),
    )

    connection.commit()
    connection.close()

    flash(
        "Executive application rejected.",
        "success"
    )

    return redirect(url_for("admin_members"))


# ============================================================
# ADMIN CHANGE ROLE
# ============================================================

@app.route(
    "/admin/member/<int:user_id>/role",
    methods=["POST"]
)
def change_member_role(user_id):

    if not is_admin_logged_in():
        flash(
            "Administrator access required.",
            "error"
        )

        return redirect(url_for("admin_login"))

    role = request.form.get(
        "role",
        "member"
    ).strip().lower()

    allowed_roles = {
        "member",
        "executive",
        "admin",
    }

    if role not in allowed_roles:
        flash(
            "Invalid role.",
            "error"
        )

        return redirect(url_for("admin_members"))

    connection = get_db()

    connection.execute(
        """
        UPDATE users
        SET role = ?
        WHERE id = ?
        """,
        (
            role,
            user_id,
        ),
    )

    connection.commit()
    connection.close()

    flash(
        "Member role updated.",
        "success"
    )

    return redirect(url_for("admin_members"))


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
