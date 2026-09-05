import json
import os
import secrets
import sqlite3
import urllib.request
import urllib.error
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

from werkzeug.security import (
    generate_password_hash,
    check_password_hash,
)


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

# Security / session settings
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

if os.environ.get("RENDER") or os.environ.get("FLASK_ENV") == "production":
    app.config["SESSION_COOKIE_SECURE"] = True

app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024


# ============================================================
# ADMIN CONFIGURATION
# ============================================================

ADMIN_USERNAME = os.environ.get("NEWGEN_ADMIN_USER", "")
ADMIN_PASSWORD = os.environ.get("NEWGEN_ADMIN_PASS", "")

ADMIN_CREDENTIALS_CONFIGURED = bool(
    ADMIN_USERNAME and ADMIN_PASSWORD
)


# ============================================================
# OFFICIAL LEADERSHIP REGISTRY
# ============================================================
#
# IMPORTANT:
# Never put a person's name here unless that person is actually
# authorized to hold the role.
#
# Signup never gives executive privileges merely because someone
# selects "New Gen Executive".
#
# Example:
#
# LEADERSHIP = {
#     ("john", "mensah"): {
#         "role": "executive",
#         "position": "President",
#     },
# }
#

LEADERSHIP = {}


# ============================================================
# EMAIL VERIFICATION
# ============================================================

VERIFICATION_EXPIRY_HOURS = 24

MAILER_URL = os.environ.get(
    "NEWGEN_MAILER_URL",
    "",
)

MAILER_SECRET = os.environ.get(
    "NEWGEN_MAIL_SECRET",
    "",
)


# ============================================================
# FILE PATHS
# ============================================================

BASE_DIR = os.path.dirname(
    os.path.abspath(__file__)
)

DATABASE_FILE = os.path.join(
    BASE_DIR,
    "users.db",
)

EVENTS_FILE = os.path.join(
    BASE_DIR,
    "events.json",
)


# ============================================================
# DATABASE CONNECTION
# ============================================================

def get_db():
    connection = sqlite3.connect(
        DATABASE_FILE,
        timeout=20,
    )

    connection.row_factory = sqlite3.Row

    connection.execute(
        "PRAGMA foreign_keys = ON"
    )

    return connection


# ============================================================
# DATABASE INITIALIZATION
# ============================================================

def init_database():
    connection = get_db()

    # --------------------------------------------------------
    # USERS
    # --------------------------------------------------------

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
            position TEXT NOT NULL DEFAULT 'Member',

            created_at TEXT NOT NULL
        )
        """
    )

    # --------------------------------------------------------
    # EXECUTIVE APPLICATIONS
    # --------------------------------------------------------

    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS executive_applications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,

            user_id INTEGER NOT NULL,

            position TEXT NOT NULL,
            reason TEXT NOT NULL,

            status TEXT NOT NULL DEFAULT 'pending',

            created_at TEXT NOT NULL,

            FOREIGN KEY (user_id)
                REFERENCES users(id)
                ON DELETE CASCADE
        )
        """
    )

    # --------------------------------------------------------
    # EVENTS
    # --------------------------------------------------------

    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,

            event_key TEXT NOT NULL UNIQUE,

            title TEXT NOT NULL,
            event_date TEXT NOT NULL,

            category TEXT NOT NULL DEFAULT '',
            location TEXT NOT NULL DEFAULT '',
            description TEXT NOT NULL DEFAULT '',

            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
        """
    )

    # --------------------------------------------------------
    # DATABASE MIGRATION FOR OLD USERS DATABASES
    # --------------------------------------------------------

    columns = connection.execute(
        "PRAGMA table_info(users)"
    ).fetchall()

    existing_columns = {
        column["name"]
        for column in columns
    }

    migrations = {
        "reason_for_joining": """
            ALTER TABLE users
            ADD COLUMN reason_for_joining
            TEXT NOT NULL DEFAULT ''
        """,

        "role": """
            ALTER TABLE users
            ADD COLUMN role
            TEXT NOT NULL DEFAULT 'member'
        """,

        "position": """
            ALTER TABLE users
            ADD COLUMN position
            TEXT NOT NULL DEFAULT 'Member'
        """,

        "phone_verified": """
            ALTER TABLE users
            ADD COLUMN phone_verified
            INTEGER NOT NULL DEFAULT 0
        """,

        "verification_token": """
            ALTER TABLE users
            ADD COLUMN verification_token
            TEXT
        """,

        "verification_expires_at": """
            ALTER TABLE users
            ADD COLUMN verification_expires_at
            TEXT
        """,
    }

    for column_name, sql in migrations.items():
        if column_name not in existing_columns:
            connection.execute(sql)

    connection.commit()

    # --------------------------------------------------------
    # MIGRATE OLD events.json INTO DATABASE
    # --------------------------------------------------------
    #
    # This is deliberately done only when matching database
    # events do not already exist.
    #
    # The JSON file becomes an import source rather than the
    # permanent event database.
    #

    event_count = connection.execute(
        "SELECT COUNT(*) AS count FROM events"
    ).fetchone()["count"]

    if event_count == 0 and os.path.exists(EVENTS_FILE):

        try:
            with open(
                EVENTS_FILE,
                "r",
                encoding="utf-8",
            ) as file:
                old_events = json.load(file)

        except (
            json.JSONDecodeError,
            OSError,
        ):
            old_events = []

        if isinstance(old_events, list):

            now = datetime.now(
                timezone.utc
            ).isoformat()

            for old_event in old_events:

                if not isinstance(old_event, dict):
                    continue

                title = str(
                    old_event.get("title", "")
                ).strip()

                event_date = str(
                    old_event.get("date", "")
                ).strip()

                if not title or not event_date:
                    continue

                event_key = str(
                    old_event.get("id")
                    or secrets.token_urlsafe(12)
                )

                category = str(
                    old_event.get("category", "")
                ).strip()

                location = str(
                    old_event.get("location", "")
                ).strip()

                description = str(
                    old_event.get("description", "")
                ).strip()

                connection.execute(
                    """
                    INSERT OR IGNORE INTO events (
                        event_key,
                        title,
                        event_date,
                        category,
                        location,
                        description,
                        created_at,
                        updated_at
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        event_key,
                        title,
                        event_date,
                        category,
                        location,
                        description,
                        now,
                        now,
                    ),
                )

            connection.commit()

    connection.close()


init_database()


# ============================================================
# EVENT HELPERS
# ============================================================

def load_events():
    """
    Read events from SQLite.

    This replaces the old events.json-based system.
    """

    connection = get_db()

    rows = connection.execute(
        """
        SELECT
            event_key AS id,
            title,
            event_date AS date,
            category,
            location,
            description,
            created_at,
            updated_at
        FROM events
        ORDER BY event_date ASC, id ASC
        """
    ).fetchall()

    connection.close()

    return [
        dict(row)
        for row in rows
    ]


def get_event(event_id):
    connection = get_db()

    event = connection.execute(
        """
        SELECT
            event_key AS id,
            title,
            event_date AS date,
            category,
            location,
            description,
            created_at,
            updated_at
        FROM events
        WHERE event_key = ?
        """,
        (event_id,),
    ).fetchone()

    connection.close()

    return event


# ============================================================
# AUTHENTICATION HELPERS
# ============================================================

def is_member_logged_in():
    return (
        session.get("member_logged_in")
        is True
        and bool(session.get("member_id"))
    )


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


def is_admin_logged_in():

    # Direct admin session
    if session.get("admin_logged_in") is True:
        return True

    # Admin who logged in through the member system
    admin_member_id = session.get(
        "admin_member_id"
    )

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

    return bool(
        user
        and user["role"] == "admin"
    )


def is_executive():

    member = get_current_member()

    return bool(
        member
        and member["role"] == "executive"
    )


# ============================================================
# LEADERSHIP HELPERS
# ============================================================

def normalize_name(value):
    return " ".join(
        str(value).strip().lower().split()
    )


def get_leadership_match(
    first_name,
    last_name,
):
    key = (
        normalize_name(first_name),
        normalize_name(last_name),
    )

    return LEADERSHIP.get(key)


# ============================================================
# DATE HELPERS
# ============================================================

def build_iso_date(
    day,
    month,
    year,
):

    day = str(day).strip()
    month = str(month).strip()
    year = str(year).strip()

    if not day or not month or not year:
        return ""

    try:
        date_object = datetime(
            int(year),
            int(month),
            int(day),
        )

    except ValueError:
        return ""

    return date_object.strftime(
        "%Y-%m-%d"
    )


def format_display_date(value):

    if not value:
        return ""

    try:
        date_object = datetime.strptime(
            value,
            "%Y-%m-%d",
        )

        return date_object.strftime(
            "%d/%m/%Y"
        )

    except ValueError:
        return value


# ============================================================
# EMAIL DELIVERY
# ============================================================

def send_verification_email(
    recipient,
    first_name,
    verification_url,
):

    if not MAILER_URL:
        raise RuntimeError(
            "NEWGEN_MAILER_URL is not configured."
        )

    if not MAILER_SECRET:
        raise RuntimeError(
            "NEWGEN_MAIL_SECRET is not configured."
        )

    payload = {
        "recipient": recipient,
        "first_name": first_name,
        "verification_url": verification_url,
        "secret": MAILER_SECRET,
    }

    request_data = json.dumps(
        payload
    ).encode("utf-8")

    request_object = urllib.request.Request(
        MAILER_URL,
        data=request_data,
        headers={
            "Content-Type": "application/json",
        },
        method="POST",
    )

    try:

        with urllib.request.urlopen(
            request_object,
            timeout=30,
        ) as response:

            response_body = (
                response
                .read()
                .decode("utf-8")
            )

            result = json.loads(
                response_body
            )

            if not result.get("success"):

                raise RuntimeError(
                    result.get(
                        "error",
                        "Email service failed.",
                    )
                )

    except urllib.error.HTTPError as error:

        try:
            error_body = (
                error
                .read()
                .decode("utf-8")
            )
        except Exception:
            error_body = ""

        raise RuntimeError(
            "Email service HTTP error: "
            f"{error.code} {error_body}"
        )

    except urllib.error.URLError as error:

        raise RuntimeError(
            "Could not reach email service: "
            f"{error.reason}"
        )


# ============================================================
# GLOBAL TEMPLATE DATA
# ============================================================

@app.context_processor
def inject_global_data():

    return {
        "member": get_current_member(),
        "is_admin": is_admin_logged_in(),
        "is_executive": is_executive(),
    }


# ============================================================
# JINJA GLOBALS
# ============================================================

app.jinja_env.globals[
    "format_display_date"
] = format_display_date


# ============================================================
# SECURITY HEADERS
# ============================================================

@app.after_request
def add_security_headers(response):

    response.headers[
        "X-Content-Type-Options"
    ] = "nosniff"

    response.headers[
        "X-Frame-Options"
    ] = "SAMEORIGIN"

    response.headers[
        "Referrer-Policy"
    ] = "strict-origin-when-cross-origin"

    response.headers[
        "Permissions-Policy"
    ] = "camera=(), microphone=(), geolocation=()"

    return response
    # ============================================================
# HOME
# ============================================================

@app.route("/")
def home():

    events = load_events()[:3]

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


@app.route("/fashion")
def fashion():
    return render_template(
        "fashion.html"
    )


# ============================================================
# CONTACT
# ============================================================

@app.route("/contact")
def contact():
    return render_template(
        "contact.html"
    )


# ============================================================
# CALENDAR
# ============================================================

@app.route("/calendar")
def calendar():

    events = load_events()

    featured_event = (
        events[0]
        if events
        else None
    )

    return render_template(
        "calendar.html",
        events=events,
        featured_event=featured_event,
    )


# ============================================================
# MEMBER SIGNUP
# ============================================================

@app.route(
    "/signup",
    methods=["GET", "POST"],
)
def signup():

    if is_member_logged_in():
        return redirect(
            url_for("home")
        )

    errors = {}

    if request.method == "POST":

        # ----------------------------------------------------
        # FORM DATA
        # ----------------------------------------------------

        first_name = request.form.get(
            "first_name",
            "",
        ).strip()

        last_name = request.form.get(
            "last_name",
            "",
        ).strip()

        username = request.form.get(
            "username",
            "",
        ).strip()

        email = request.form.get(
            "email",
            "",
        ).strip().lower()

        phone = request.form.get(
            "phone",
            "",
        ).strip()

        school = request.form.get(
            "school",
            "",
        ).strip()

        class_name = request.form.get(
            "class_name",
            "",
        ).strip()

        group_name = request.form.get(
            "group_name",
            "",
        ).strip()

        account_type = request.form.get(
            "account_type",
            "member",
        ).strip().lower()

        reason_for_joining = request.form.get(
            "reason_for_joining",
            "",
        ).strip()

        password = request.form.get(
            "password",
            "",
        )

        confirm_password = request.form.get(
            "confirm_password",
            "",
        )

        # ----------------------------------------------------
        # INLINE REQUIRED-FIELD VALIDATION
        # ----------------------------------------------------

        required_fields = {
            "first_name": (
                first_name,
                "First name",
            ),
            "last_name": (
                last_name,
                "Last name",
            ),
            "username": (
                username,
                "Username",
            ),
            "email": (
                email,
                "Email",
            ),
            "phone": (
                phone,
                "Phone",
            ),
            "school": (
                school,
                "School",
            ),
            "class_name": (
                class_name,
                "Class",
            ),
            "group_name": (
                group_name,
                "Group",
            ),
            "account_type": (
                account_type,
                "Account type",
            ),
            "reason_for_joining": (
                reason_for_joining,
                "Reason for joining",
            ),
            "password": (
                password,
                "Password",
            ),
            "confirm_password": (
                confirm_password,
                "Password confirmation",
            ),
        }

        for field, data in required_fields.items():

            value, label = data

            if not value:
                errors[field] = (
                    f"{label} is required."
                )

        if errors:

            return render_template(
                "signup.html",
                errors=errors,
                form_error=(
                    "Please correct the highlighted fields."
                ),
            )

        # ----------------------------------------------------
        # BASIC USERNAME VALIDATION
        # ----------------------------------------------------

        if len(username) < 3:

            errors["username"] = (
                "Username must be at least 3 characters."
            )

        elif len(username) > 30:

            errors["username"] = (
                "Username must be 30 characters or fewer."
            )

        elif not all(
            character.isalnum()
            or character in "_-"
            for character in username
        ):

            errors["username"] = (
                "Username may only contain letters, numbers, "
                "underscores and hyphens."
            )

        # ----------------------------------------------------
        # EMAIL VALIDATION
        # ----------------------------------------------------

        if (
            "@" not in email
            or "." not in email.rsplit("@", 1)[-1]
        ):
            errors["email"] = (
                "Enter a valid email address."
            )

        # ----------------------------------------------------
        # PASSWORD VALIDATION
        # ----------------------------------------------------

        if len(password) < 8:

            errors["password"] = (
                "Password must be at least 8 characters."
            )

        if password != confirm_password:

            errors["confirm_password"] = (
                "Passwords do not match."
            )

        # ----------------------------------------------------
        # ALLOWED OPTIONS
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

        allowed_account_types = {
            "member",
            "executive",
        }

        if class_name not in allowed_classes:

            errors["class_name"] = (
                "Please select a valid class."
            )

        if group_name not in allowed_groups:

            errors["group_name"] = (
                "Please select a valid New Gen group."
            )

        if account_type not in allowed_account_types:

            errors["account_type"] = (
                "Please select a valid account type."
            )

        if errors:

            return render_template(
                "signup.html",
                errors=errors,
                form_error=(
                    "Please correct the highlighted fields."
                ),
            )

        # ----------------------------------------------------
        # CHECK EXISTING EMAIL / USERNAME
        # ----------------------------------------------------

        connection = get_db()

        existing_email = connection.execute(
            """
            SELECT id
            FROM users
            WHERE email = ?
            """,
            (email,),
        ).fetchone()

        existing_username = connection.execute(
            """
            SELECT id
            FROM users
            WHERE username = ?
            """,
            (username,),
        ).fetchone()

        if existing_email:

            errors["email"] = (
                "That email is already registered."
            )

        if existing_username:

            errors["username"] = (
                "That username is already taken."
            )

        if errors:

            connection.close()

            return render_template(
                "signup.html",
                errors=errors,
                form_error=(
                    "Please correct the highlighted fields."
                ),
            )

        # ----------------------------------------------------
        # PASSWORD HASH
        # ----------------------------------------------------

        password_hash = generate_password_hash(
            password
        )

        # ----------------------------------------------------
        # VERIFICATION TOKEN
        # ----------------------------------------------------

        verification_token = secrets.token_urlsafe(
            32
        )

        verification_expires_at = (
            datetime.now(timezone.utc)
            + timedelta(
                hours=VERIFICATION_EXPIRY_HOURS
            )
        ).isoformat()

        created_at = datetime.now(
            timezone.utc
        ).isoformat()

        # ----------------------------------------------------
        # ROLE
        # ----------------------------------------------------
        #
        # Executive selection NEVER grants executive access.
        #

        assigned_role = "member"
        assigned_position = "Member"

        leadership_match = get_leadership_match(
            first_name,
            last_name,
        )

        # Only an explicitly registered official leader can
        # receive a preconfigured role.
        #
        # Executive applicants still remain members until
        # an administrator approves them.

        if (
            account_type == "member"
            and leadership_match
        ):
            assigned_role = leadership_match.get(
                "role",
                "member",
            )

            assigned_position = leadership_match.get(
                "position",
                "Member",
            )

        if account_type == "executive":

            assigned_role = "member"
            assigned_position = (
                "Executive Applicant"
            )

        # ----------------------------------------------------
        # CREATE USER
        # ----------------------------------------------------

        cursor = connection.execute(
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
            VALUES (
                ?, ?, ?, ?, ?, ?, ?, ?, ?,
                ?, ?, ?, ?, ?, ?, ?, ?
            )
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

        user_id = cursor.lastrowid

        # ----------------------------------------------------
        # EXECUTIVE APPLICATION
        # ----------------------------------------------------

        if account_type == "executive":

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
                    user_id,
                    "Executive",
                    reason_for_joining,
                    "pending",
                    created_at,
                ),
            )

        connection.commit()
        connection.close()

        # ----------------------------------------------------
        # VERIFICATION URL
        # ----------------------------------------------------

        verification_url = url_for(
            "verify_email",
            token=verification_token,
            _external=True,
        )

        # ----------------------------------------------------
        # SEND VERIFICATION EMAIL
        # ----------------------------------------------------

        try:

            send_verification_email(
                email,
                first_name,
                verification_url,
            )

        except Exception as error:

            print(
                "VERIFICATION EMAIL ERROR:",
                error,
            )

            flash(
                "Your account was created, but we could "
                "not send the verification email yet. "
                "Use the resend verification option.",
                "error",
            )

            return redirect(
                url_for(
                    "verify_notice",
                    email=email,
                )
            )

        # ----------------------------------------------------
        # SUCCESS
        # ----------------------------------------------------

        flash(
            "Account created successfully. "
            "Check your email to verify your New Gen account.",
            "success",
        )

        return redirect(
            url_for(
                "verify_notice",
                email=email,
            )
        )

    return render_template(
        "signup.html",
        errors={},
        form_error=None,
    )


# ============================================================
# MEMBER LOGIN
# ============================================================

@app.route(
    "/login",
    methods=["GET", "POST"],
)
def login():

    if is_member_logged_in():

        return redirect(
            url_for("home")
        )

    errors = {}

    if request.method == "POST":

        login_value = request.form.get(
            "login",
            "",
        ).strip()

        password = request.form.get(
            "password",
            "",
        )

        # ----------------------------------------------------
        # EMPTY LOGIN
        # ----------------------------------------------------

        if not login_value:

            errors["login"] = (
                "Enter your username or email."
            )

        if not password:

            errors["password"] = (
                "Enter your password."
            )

        if errors:

            return render_template(
                "login.html",
                errors=errors,
            )

        # ----------------------------------------------------
        # FIND USER
        # ----------------------------------------------------

        connection = get_db()

        user = connection.execute(
            """
            SELECT *
            FROM users
            WHERE email = ?
               OR username = ?
            """,
            (
                login_value.lower(),
                login_value,
            ),
        ).fetchone()

        connection.close()

        # ----------------------------------------------------
        # PASSWORD CHECK
        # ----------------------------------------------------

        password_correct = bool(
            user
            and check_password_hash(
                user["password_hash"],
                password,
            )
        )

        if not password_correct:

            return render_template(
                "login.html",
                errors={
                    "login": (
                        "Incorrect username/email "
                        "or password."
                    )
                },
            )

        # ----------------------------------------------------
        # EMAIL VERIFICATION CHECK
        # ----------------------------------------------------

        if not user["email_verified"]:

            return render_template(
                "login.html",
                errors={
                    "login": (
                        "Please verify your email "
                        "before logging in."
                    )
                },
            )

        # ----------------------------------------------------
        # SESSION
        # ----------------------------------------------------

        session.clear()

        session["member_logged_in"] = True
        session["member_id"] = user["id"]

        # ----------------------------------------------------
        # ADMIN
        # ----------------------------------------------------

        if user["role"] == "admin":

            session["admin_member_id"] = user["id"]

            flash(
                f"Welcome back, {user['first_name']}!",
                "success",
            )

            return redirect(
                url_for("admin_portal")
            )

        # ----------------------------------------------------
        # EXECUTIVE
        # ----------------------------------------------------

        if user["role"] == "executive":

            flash(
                f"Welcome back, {user['first_name']}!",
                "success",
            )

            return redirect(
                url_for("executive_dashboard")
            )

        # ----------------------------------------------------
        # REGULAR MEMBER
        # ----------------------------------------------------

        flash(
            f"Welcome back, {user['first_name']}!",
            "success",
        )

        return redirect(
            url_for("member_dashboard")
        )

    return render_template(
        "login.html",
        errors={},
    )


# ============================================================
# MEMBER DASHBOARD
# ============================================================

@app.route("/dashboard")
def member_dashboard():

    if not is_member_logged_in():

        flash(
            "Please log in to access your dashboard.",
            "error",
        )

        return redirect(
            url_for("login")
        )

    member = get_current_member()

    if not member:

        session.clear()

        flash(
            "Your account could not be found.",
            "error",
        )

        return redirect(
            url_for("login")
        )

    return render_template(
        "member_dashboard.html",
        member=member,
    )


# ============================================================
# MEMBER LOGOUT
# ============================================================

@app.route("/logout")
def logout():

    session.clear()

    flash(
        "You have been logged out.",
        "success",
    )

    return redirect(
        url_for("home")
    )


# ============================================================
# EMAIL VERIFICATION NOTICE
# ============================================================

@app.route("/verify-notice")
def verify_notice():

    email = request.args.get(
        "email",
        "",
    ).strip().lower()

    return render_template(
        "verify_email.html",
        notice=True,
        email=email,
    )


# ============================================================
# RESEND VERIFICATION
# ============================================================

@app.route(
    "/resend-verification",
    methods=["POST"],
)
def resend_verification():

    email = request.form.get(
        "email",
        "",
    ).strip().lower()

    if not email:

        flash(
            "Please enter your email address.",
            "error",
        )

        return redirect(
            url_for("login")
        )

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

        # Do not reveal whether an account exists.
        flash(
            "If that account exists, a verification email "
            "will be sent.",
            "success",
        )

        return redirect(
            url_for("login")
        )

    if user["email_verified"]:

        connection.close()

        flash(
            "That email is already verified. You can log in.",
            "success",
        )

        return redirect(
            url_for("login")
        )

    verification_token = secrets.token_urlsafe(
        32
    )

    verification_expires_at = (
        datetime.now(timezone.utc)
        + timedelta(
            hours=VERIFICATION_EXPIRY_HOURS
        )
    ).isoformat()

    connection.execute(
        """
        UPDATE users
        SET
            verification_token = ?,
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

    except Exception as error:

        print(
            "RESEND EMAIL ERROR:",
            error,
        )

        flash(
            "We could not send the verification email "
            "right now. Please try again shortly.",
            "error",
        )

        return redirect(
            url_for(
                "verify_notice",
                email=email,
            )
        )

    flash(
        "A new verification email has been sent.",
        "success",
    )

    return redirect(
        url_for(
            "verify_notice",
            email=email,
        )
    )


# ============================================================
# VERIFY EMAIL
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
            message=(
                "This verification link is invalid "
                "or has already been used."
            ),
        )

    expires_at = user[
        "verification_expires_at"
    ]

    if expires_at:

        try:

            expiry = datetime.fromisoformat(
                expires_at
            )

            if expiry.tzinfo is None:

                expiry = expiry.replace(
                    tzinfo=timezone.utc
                )

            if datetime.now(
                timezone.utc
            ) > expiry:

                connection.close()

                return render_template(
                    "verify_email.html",
                    success=False,
                    message=(
                        "This verification link has expired. "
                        "Please request a new one."
                    ),
                    email=user["email"],
                    expired=True,
                )

        except ValueError:

            connection.close()

            return render_template(
                "verify_email.html",
                success=False,
                message=(
                    "This verification link is invalid. "
                    "Please request a new one."
                ),
                email=user["email"],
            )

    connection.execute(
        """
        UPDATE users
        SET
            email_verified = 1,
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
        message=(
            "Your email has been successfully verified!"
        ),
    )


# ============================================================
# EXECUTIVE APPLICATION
# ============================================================

@app.route(
    "/executive/apply",
    methods=["GET", "POST"],
)
def executive_apply():

    if not is_member_logged_in():

        flash(
            "You must have a New Gen member account "
            "before applying to become an executive.",
            "error",
        )

        return redirect(
            url_for("login")
        )

    member = get_current_member()

    if not member:

        session.clear()

        return redirect(
            url_for("login")
        )

    if member["role"] == "executive":

        return redirect(
            url_for("executive_dashboard")
        )

    errors = {}

    if request.method == "POST":

        position = request.form.get(
            "position",
            "",
        ).strip()

        reason = request.form.get(
            "reason",
            "",
        ).strip()

        if not position:

            errors["position"] = (
                "Please select a position."
            )

        if not reason:

            errors["reason"] = (
                "Please explain why you should be an executive."
            )

        if errors:

            return render_template(
                "executive_apply.html",
                member=member,
                errors=errors,
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
                "error",
            )

            return redirect(
                url_for("member_dashboard")
            )

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
            "Your executive application has been submitted "
            "for review.",
            "success",
        )

        return redirect(
            url_for("member_dashboard")
        )

    return render_template(
        "executive_apply.html",
        member=member,
        errors={},
    )


# ============================================================
# EXECUTIVE DASHBOARD
# ============================================================

@app.route("/executive")
def executive_dashboard():

    if not is_member_logged_in():

        flash(
            "Please log in first.",
            "error",
        )

        return redirect(
            url_for("login")
        )

    member = get_current_member()

    if (
        not member
        or member["role"] != "executive"
    ):

        flash(
            "Executive access is restricted to approved "
            "New Gen executives.",
            "error",
        )

        return redirect(
            url_for("member_dashboard")
        )

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

@app.route(
    "/admin/login",
    methods=["GET", "POST"],
)
def admin_login():

    if is_admin_logged_in():

        return redirect(
            url_for("admin_portal")
        )

    if not ADMIN_CREDENTIALS_CONFIGURED:

        flash(
            "Admin access is unavailable until secure "
            "admin credentials are configured.",
            "error",
        )

        return render_template(
            "admin_login.html"
        ), 503

    errors = {}

    if request.method == "POST":

        username = request.form.get(
            "username",
            "",
        ).strip()

        password = request.form.get(
            "password",
            "",
        )

        if not username:

            errors["username"] = (
                "Administrator username is required."
            )

        if not password:

            errors["password"] = (
                "Administrator password is required."
            )

        if errors:

            return render_template(
                "admin_login.html",
                errors=errors,
            )

        # Constant-time comparison prevents simple timing
        # attacks against the configured admin credentials.

        username_ok = secrets.compare_digest(
            username,
            ADMIN_USERNAME,
        )

        password_ok = secrets.compare_digest(
            password,
            ADMIN_PASSWORD,
        )

        if not (
            username_ok
            and password_ok
        ):

            return render_template(
                "admin_login.html",
                errors={
                    "username": (
                        "Incorrect administrator username "
                        "or password."
                    )
                },
            )

        session.clear()

        session["admin_logged_in"] = True

        flash(
            "Admin access granted.",
            "success",
        )

        return redirect(
            url_for("admin_portal")
        )

    return render_template(
        "admin_login.html",
        errors={},
    )


# ============================================================
# ADMIN LOGOUT
# ============================================================

@app.route("/admin/logout")
def admin_logout():

    session.pop(
        "admin_logged_in",
        None,
    )

    session.pop(
        "admin_member_id",
        None,
    )

    session.pop(
        "member_logged_in",
        None,
    )

    session.pop(
        "member_id",
        None,
    )

    flash(
        "You have been logged out of the administrator area.",
        "success",
    )

    return redirect(
        url_for("admin_login")
    )


# ============================================================
# ADMIN PORTAL
# ============================================================
#
# This becomes the central admin area.
#

@app.route("/admin/portal")
def admin_portal():

    if not is_admin_logged_in():

        flash(
            "Administrator access required.",
            "error",
        )

        return redirect(
            url_for("admin_login")
        )

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

    event_count = connection.execute(
        """
        SELECT COUNT(*) AS count
        FROM events
        """
    ).fetchone()["count"]

    member_count = connection.execute(
        """
        SELECT COUNT(*) AS count
        FROM users
        """
    ).fetchone()["count"]

    executive_count = connection.execute(
        """
        SELECT COUNT(*) AS count
        FROM users
        WHERE role = 'executive'
        """
    ).fetchone()["count"]

    pending_count = connection.execute(
        """
        SELECT COUNT(*) AS count
        FROM executive_applications
        WHERE status = 'pending'
        """
    ).fetchone()["count"]

    connection.close()

    return render_template(
        "admin.html",
        members=members,
        applications=applications,
        events=load_events(),
        event_count=event_count,
        member_count=member_count,
        executive_count=executive_count,
        pending_count=pending_count,
        mode="Create",
        event=None,
    )


# ============================================================
# OLD ADMIN ROUTE
# ============================================================
#
# Kept for compatibility with your existing calendar/admin
# buttons.
#

@app.route(
    "/admin",
    methods=["GET", "POST"],
)
@app.route(
    "/admin/edit/<event_id>",
    methods=["GET", "POST"],
)
def admin(event_id=None):

    if not is_admin_logged_in():

        flash(
            "Please log in as an administrator.",
            "error",
        )

        return redirect(
            url_for("admin_login")
        )

    current_event = (
        get_event(event_id)
        if event_id
        else None
    )

    events = load_events()

    if request.method == "POST":

        event_id_value = (
            request.form.get(
                "event_id"
            )
            or secrets.token_urlsafe(12)
        )

        title = request.form.get(
            "title",
            "",
        ).strip()

        day = request.form.get(
            "day",
            "",
        ).strip()

        month = request.form.get(
            "month",
            "",
        ).strip()

        year = request.form.get(
            "year",
            "",
        ).strip()

        category = request.form.get(
            "category",
            "",
        ).strip()

        location = request.form.get(
            "location",
            "",
        ).strip()

        description = request.form.get(
            "description",
            "",
        ).strip()

        date_value = build_iso_date(
            day,
            month,
            year,
        )

        # Also support an HTML date input if your newer form
        # sends "date" instead of day/month/year.

        if not date_value:

            date_value = request.form.get(
                "date",
                "",
            ).strip()

        errors = {}

        if not title:

            errors["title"] = (
                "Event title is required."
            )

        if not date_value:

            errors["date"] = (
                "A valid event date is required."
            )

        if errors:

            return render_template(
                "admin.html",
                events=events,
                event=current_event,
                mode=(
                    "Edit"
                    if current_event
                    else "Create"
                ),
                errors=errors,
            )

        now = datetime.now(
            timezone.utc
        ).isoformat()

        connection = get_db()

        existing = connection.execute(
            """
            SELECT id
            FROM events
            WHERE event_key = ?
            """,
            (event_id_value,),
        ).fetchone()

        if existing:

            connection.execute(
                """
                UPDATE events
                SET
                    title = ?,
                    event_date = ?,
                    category = ?,
                    location = ?,
                    description = ?,
                    updated_at = ?
                WHERE event_key = ?
                """,
                (
                    title,
                    date_value,
                    category,
                    location,
                    description,
                    now,
                    event_id_value,
                ),
            )

            message = (
                "Event updated successfully."
            )

        else:

            connection.execute(
                """
                INSERT INTO events (
                    event_key,
                    title,
                    event_date,
                    category,
                    location,
                    description,
                    created_at,
                    updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event_id_value,
                    title,
                    date_value,
                    category,
                    location,
                    description,
                    now,
                    now,
                ),
            )

            message = (
                "Event created successfully."
            )

        connection.commit()
        connection.close()

        flash(
            message,
            "success",
        )

        return redirect(
            url_for("admin_portal")
        )

    return render_template(
        "admin.html",
        events=events,
        event=current_event,
        mode=(
            "Edit"
            if current_event
            else "Create"
        ),
        errors={},
    )


# ============================================================
# DELETE EVENT
# ============================================================

@app.route(
    "/admin/delete/<event_id>",
    methods=["POST"],
)
def delete_event(event_id):

    if not is_admin_logged_in():

        flash(
            "Administrator access required.",
            "error",
        )

        return redirect(
            url_for("admin_login")
        )

    connection = get_db()

    event = connection.execute(
        """
        SELECT title
        FROM events
        WHERE event_key = ?
        """,
        (event_id,),
    ).fetchone()

    if not event:

        connection.close()

        flash(
            "Event not found.",
            "error",
        )

        return redirect(
            url_for("admin_portal")
        )

   # ============================================================
# DELETE MEMBER (CONFIRMATION)
# ============================================================

@app.route("/admin/member/<int:user_id>/delete")
def delete_member_page(user_id):

    if not is_admin_logged_in():
        flash("Administrator access required.", "error")
        return redirect(url_for("admin_login"))

    connection = get_db()

    member = connection.execute(
        "SELECT * FROM users WHERE id=?",
        (user_id,)
    ).fetchone()

    connection.close()

    if not member:
        flash("Member not found.", "error")
        return redirect(url_for("admin_members"))

    return render_template(
        "delete_confirm.html",
        person=member
    )


@app.route(
    "/admin/member/<int:user_id>/delete/confirm",
    methods=["POST"]
)
def delete_member_page(user_id):

    if not is_admin_logged_in():
        flash("Administrator access required.", "error")
        return redirect(url_for("admin_login"))

    connection = get_db()

    user = connection.execute(
        "SELECT * FROM users WHERE id=?",
        (user_id,)
    ).fetchone()

    if not user:
        connection.close()
        flash("Member not found.", "error")
        return redirect(url_for("admin_members"))

    if user["role"] == "admin":
        connection.close()
        flash("Admin accounts cannot be deleted.", "error")
        return redirect(url_for("admin_members"))

    connection.execute(
        "DELETE FROM executive_applications WHERE user_id=?",
        (user_id,)
    )

    connection.execute(
        "DELETE FROM users WHERE id=?",
        (user_id,)
    )

    connection.commit()
    connection.close()

    flash("Member deleted successfully.", "success")

    return redirect(url_for("admin_members"))
# ============================================================
# ADMIN SEARCH MEMBERS
# ============================================================

@app.route("/admin/members/search")
def admin_search():

    if not is_admin_logged_in():
        flash("Administrator access required.", "error")
        return redirect(url_for("admin_login"))

    query = request.args.get("q", "").strip()

    connection = get_db()

    members = connection.execute(
        """
        SELECT *
        FROM users
        WHERE
            first_name LIKE ?
            OR last_name LIKE ?
            OR username LIKE ?
            OR school LIKE ?
            OR group_name LIKE ?
        ORDER BY created_at DESC
        """,
        (
            f"%{query}%",
            f"%{query}%",
            f"%{query}%",
            f"%{query}%",
            f"%{query}%"
        )
    ).fetchall()

    applications = connection.execute(
        """
        SELECT
            ea.*,
            u.first_name,
            u.last_name,
            u.username,
            u.school,
            u.class_name,
            u.group_name
        FROM executive_applications ea
        JOIN users u
        ON ea.user_id=u.id
        ORDER BY ea.created_at DESC
        """
    ).fetchall()

    connection.close()

    return render_template(
        "members.html",
        members=members,
        applications=applications,
        search_query=query
    )
# ============================================================
# ADMIN MEMBERS
# ============================================================

@app.route("/admin/members")
def admin_members():

    if not is_admin_logged_in():

        flash(
            "Please log in as an administrator.",
            "error",
        )

        return redirect(
            url_for("admin_login")
        )

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
# APPROVE EXECUTIVE
# ============================================================

@app.route(
    "/admin/executive/<int:application_id>/approve",
    methods=["POST"],
)
def approve_executive(
    application_id
):

    if not is_admin_logged_in():

        flash(
            "Administrator access required.",
            "error",
        )

        return redirect(
            url_for("admin_login")
        )

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
            "error",
        )

        return redirect(
            url_for("admin_members")
        )

    if application["status"] != "pending":

        connection.close()

        flash(
            "This application has already been reviewed.",
            "error",
        )

        return redirect(
            url_for("admin_members")
        )

    # --------------------------------------------------------
    # APPROVE APPLICATION
    # --------------------------------------------------------

    connection.execute(
        """
        UPDATE executive_applications
        SET status = 'approved'
        WHERE id = ?
        """,
        (application_id,),
    )

    # --------------------------------------------------------
    # GRANT EXECUTIVE ROLE
    # --------------------------------------------------------

    connection.execute(
        """
        UPDATE users
        SET
            role = 'executive',
            position = ?
        WHERE id = ?
        """,
        (
            application["position"],
            application["user_id"],
        ),
    )

    connection.commit()
    connection.close()

    flash(
        "Executive application approved. "
        "The member now has executive access.",
        "success",
    )

    return redirect(
        url_for("admin_members")
    )


# ============================================================
# REJECT EXECUTIVE
# ============================================================

@app.route(
    "/admin/executive/<int:application_id>/reject",
    methods=["POST"],
)
def reject_executive(
    application_id
):

    if not is_admin_logged_in():

        flash(
            "Administrator access required.",
            "error",
        )

        return redirect(
            url_for("admin_login")
        )

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
            "error",
        )

        return redirect(
            url_for("admin_members")
        )

    if application["status"] != "pending":

        connection.close()

        flash(
            "This application has already been reviewed.",
            "error",
        )

        return redirect(
            url_for("admin_members")
        )

    connection.execute(
        """
        UPDATE executive_applications
        SET status = 'rejected'
        WHERE id = ?
        """,
        (application_id,),
    )

    # Make absolutely sure a rejected applicant remains
    # a normal member.

    connection.execute(
        """
        UPDATE users
        SET
            role = 'member',
            position = 'Member'
        WHERE id = ?
          AND role = 'member'
        """,
        (application["user_id"],),
    )

    connection.commit()
    connection.close()

    flash(
        "Executive application rejected.",
        "success",
    )

    return redirect(
        url_for("admin_members")
    )


# ============================================================
# CHANGE MEMBER ROLE
# ============================================================

@app.route(
    "/admin/member/<int:user_id>/role",
    methods=["POST"],
)
def change_member_role(user_id):

    if not is_admin_logged_in():

        flash(
            "Administrator access required.",
            "error",
        )

        return redirect(
            url_for("admin_login")
        )

    role = request.form.get(
        "role",
        "member",
    ).strip().lower()

    allowed_roles = {
        "member",
        "executive",
        "admin",
    }

    if role not in allowed_roles:

        flash(
            "Invalid role.",
            "error",
        )

        return redirect(
            url_for("admin_members")
        )

    # Do not allow the administrator to accidentally remove
    # their own admin role.

    current_admin_member_id = session.get(
        "admin_member_id"
    )

    if (
        current_admin_member_id
        and int(current_admin_member_id) == int(user_id)
        and role != "admin"
    ):

        flash(
            "You cannot remove your own administrator role.",
            "error",
        )

        return redirect(
            url_for("admin_members")
        )

    connection = get_db()

    if role == "member":

        connection.execute(
            """
            UPDATE users
            SET
                role = 'member',
                position = 'Member'
            WHERE id = ?
            """,
            (user_id,),
        )

    elif role == "executive":

        connection.execute(
            """
            UPDATE users
            SET
                role = 'executive'
            WHERE id = ?
            """,
            (user_id,),
        )

    else:

        connection.execute(
            """
            UPDATE users
            SET
                role = 'admin',
                position = 'Administrator'
            WHERE id = ?
            """,
            (user_id,),
        )

    connection.commit()
    connection.close()

    flash(
        "Member role updated.",
        "success",
    )

    return redirect(
        url_for("admin_members")
    )


# ============================================================
# DELETE MEMBER — STEP 1
# ============================================================
#
# Instead of deleting immediately, send the administrator to
# a confirmation page.
#

@app.route(
    "/admin/member/<int:user_id>/delete",
    methods=["GET", "POST"],
)
def delete_member(user_id):

    if not is_admin_logged_in():

        flash(
            "Administrator access required.",
            "error",
        )

        return redirect(
            url_for("admin_login")
        )

    connection = get_db()

    user = connection.execute(
        """
        SELECT
            id,
            first_name,
            last_name,
            username,
            role
        FROM users
        WHERE id = ?
        """,
        (user_id,),
    ).fetchone()

    connection.close()

    if not user:

        flash(
            "Member not found.",
            "error",
        )

        return redirect(
            url_for("admin_members")
        )

    # Never allow an administrator account to be deleted
    # through this member deletion tool.

    if user["role"] == "admin":

        flash(
            "Administrator accounts cannot be deleted "
            "from this panel.",
            "error",
        )

        return redirect(
            url_for("admin_members")
        )

    if request.method == "GET":

        # If delete_confirm.html exists, use it.
        # This gives the permanent deletion confirmation
        # its own page.

        return render_template(
            "delete_confirm.html",
            user=user,
        )

    confirmation = request.form.get(
        "confirm",
        "",
    ).strip().lower()

    if confirmation not in {
        "yes",
        "true",
        "1",
        "delete",
        "confirm",
    }:

        flash(
            "Account deletion cancelled. "
            "You must confirm permanent deletion.",
            "error",
        )

        return redirect(
            url_for("admin_members")
        )

    # --------------------------------------------------------
    # FINAL DELETE
    # --------------------------------------------------------

    connection = get_db()

    # Applications are removed first because they reference
    # the user.

    connection.execute(
        """
        DELETE FROM executive_applications
        WHERE user_id = ?
        """,
        (user_id,),
    )

    connection.execute(
        """
        DELETE FROM users
        WHERE id = ?
        """,
        (user_id,),
    )

    connection.commit()
    connection.close()

    flash(
        f"Member {user['first_name']} "
        f"{user['last_name']} was permanently deleted.",
        "success",
    )

    return redirect(
        url_for("admin_members")
    )


# ============================================================
# ADMIN SEARCH
# ============================================================

@app.route("/admin/search")
def admin_search():

    if not is_admin_logged_in():

        flash(
            "Administrator access required.",
            "error",
        )

        return redirect(
            url_for("admin_login")
        )

    query = request.args.get(
        "q",
        "",
    ).strip()

    connection = get_db()

    if query:

        search_value = f"%{query}%"

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
                role,
                position,
                email_verified,
                created_at
            FROM users
            WHERE
                first_name LIKE ?
                OR last_name LIKE ?
                OR username LIKE ?
                OR email LIKE ?
                OR school LIKE ?
                OR group_name LIKE ?
            ORDER BY created_at DESC
            """,
            (
                search_value,
                search_value,
                search_value,
                search_value,
                search_value,
                search_value,
            ),
        ).fetchall()

    else:

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
                role,
                position,
                email_verified,
                created_at
            FROM users
            ORDER BY created_at DESC
            """
        ).fetchall()

    connection.close()

    return render_template(
        "members.html",
        members=members,
        applications=[],
        search_query=query,
    )


# ============================================================
# HEALTH CHECK
# ============================================================

@app.route("/health")
def health():

    try:

        connection = get_db()

        connection.execute(
            "SELECT 1"
        ).fetchone()

        connection.close()

        return {
            "status": "ok",
            "service": "New Gen",
        }, 200

    except Exception as error:

        print(
            "HEALTH CHECK ERROR:",
            error,
        )

        return {
            "status": "error",
            "service": "New Gen",
        }, 500


# ============================================================
# ERROR HANDLERS
# ============================================================

@app.errorhandler(413)
def request_too_large(error):

    flash(
        "The submitted data is too large.",
        "error",
    )

    return redirect(
        url_for("home")
    )


@app.errorhandler(404)
def page_not_found(error):

    return render_template(
        "index.html",
        events=load_events()[:3],
    ), 404


# ============================================================
# RUN
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
                "5000",
            )
        ),
    )
