import json
import os
import secrets
import sqlite3
import urllib.error
import urllib.request

from datetime import datetime, timezone, timedelta

import psycopg
from psycopg.rows import dict_row

from flask import (
    Flask,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

from werkzeug.middleware.proxy_fix import ProxyFix

from werkzeug.security import (
    generate_password_hash,
    check_password_hash,
)


# ============================================================
# APP SETUP
# ============================================================

app = Flask(__name__)

app.wsgi_app = ProxyFix(
    app.wsgi_app,
    x_for=1,
    x_proto=1,
    x_host=1,
)

SESSION_SECRET = (
    os.environ.get("NEWGEN_SECRET_KEY")
    or os.environ.get("SESSION_SECRET")
)

if not SESSION_SECRET:
    raise RuntimeError(
        "SESSION_SECRET or NEWGEN_SECRET_KEY must be configured."
    )

app.secret_key = SESSION_SECRET

app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = bool(
    os.environ.get("RENDER")
)
app.config["SESSION_COOKIE_NAME"] = "newgen_session"
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(
    days=7
)
app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024


# ============================================================
# ADMIN CONFIGURATION
# ============================================================

ADMIN_USERNAME = os.environ.get(
    "NEWGEN_ADMIN_USER",
    "",
).strip()

ADMIN_PASSWORD = os.environ.get(
    "NEWGEN_ADMIN_PASS",
    "",
)

ADMIN_CREDENTIALS_CONFIGURED = bool(
    ADMIN_USERNAME and ADMIN_PASSWORD
)


# ============================================================
# EMAIL VERIFICATION
# ============================================================

VERIFICATION_EXPIRY_HOURS = 24

MAILER_URL = os.environ.get(
    "NEWGEN_MAILER_URL",
    "",
).strip()

MAILER_SECRET = os.environ.get(
    "NEWGEN_MAIL_SECRET",
    "",
)


# ============================================================
# DATABASE CONFIGURATION
# ============================================================

DATABASE_URL = os.environ.get(
    "DATABASE_URL",
    "",
).strip()

if not DATABASE_URL:
    raise RuntimeError(
        "DATABASE_URL must be configured."
    )

BASE_DIR = os.path.dirname(
    os.path.abspath(__file__)
)

OLD_SQLITE_DATABASE = os.path.join(
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

    return psycopg.connect(
        DATABASE_URL,
        row_factory=dict_row,
    )


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
            id BIGSERIAL PRIMARY KEY,

            first_name TEXT NOT NULL,
            last_name TEXT NOT NULL,

            username TEXT NOT NULL UNIQUE,
            email TEXT NOT NULL UNIQUE,

            phone TEXT NOT NULL DEFAULT '',

            school TEXT NOT NULL,
            class_name TEXT NOT NULL,
            group_name TEXT NOT NULL,

            reason_for_joining TEXT NOT NULL DEFAULT '',

            password_hash TEXT NOT NULL,

            email_verified BOOLEAN NOT NULL DEFAULT FALSE,
            phone_verified BOOLEAN NOT NULL DEFAULT FALSE,

            verification_token TEXT,
            verification_expires_at TIMESTAMPTZ,

            role TEXT NOT NULL DEFAULT 'member',
            position TEXT NOT NULL DEFAULT 'Member',

            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
        """
    )

    # --------------------------------------------------------
    # EVENTS
    # --------------------------------------------------------

    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS events (
            id BIGSERIAL PRIMARY KEY,

            event_key TEXT NOT NULL UNIQUE,

            title TEXT NOT NULL,
            event_date DATE NOT NULL,

            category TEXT NOT NULL DEFAULT '',
            location TEXT NOT NULL DEFAULT '',
            description TEXT NOT NULL DEFAULT '',

            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
        """
    )

    # --------------------------------------------------------
    # OFFICIAL ROLES
    # --------------------------------------------------------

    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS official_roles (
            id BIGSERIAL PRIMARY KEY,

            first_name TEXT NOT NULL,
            last_name TEXT NOT NULL,

            email TEXT NOT NULL UNIQUE,
            phone TEXT NOT NULL UNIQUE,

            role TEXT NOT NULL
                CHECK (role IN ('admin', 'executive')),

            position TEXT NOT NULL DEFAULT '',

            active BOOLEAN NOT NULL DEFAULT TRUE,

            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
        """
    )

    # --------------------------------------------------------
    # INDEXES
    # --------------------------------------------------------

    connection.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_users_email_lower
        ON users (LOWER(email))
        """
    )

    connection.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_users_username_lower
        ON users (LOWER(username))
        """
    )

    connection.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_users_role
        ON users (role)
        """
    )

    connection.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_events_date
        ON events (event_date)
        """
    )

    connection.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_official_roles_email_lower
        ON official_roles (LOWER(email))
        """
    )

    connection.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_official_roles_phone
        ON official_roles (phone)
        """
    )

    connection.commit()
    connection.close()


# ============================================================
# SQLITE MIGRATION HELPERS
# ============================================================

def sqlite_column_exists(
    row,
    name,
):
    return name in row.keys()


def migrate_old_data():

    connection = get_db()

    # --------------------------------------------------------
    # OLD SQLITE USERS
    # --------------------------------------------------------

    if os.path.exists(OLD_SQLITE_DATABASE):

        try:

            old_connection = sqlite3.connect(
                OLD_SQLITE_DATABASE
            )

            old_connection.row_factory = sqlite3.Row

            old_users = old_connection.execute(
                "SELECT * FROM users"
            ).fetchall()

            old_connection.close()

        except Exception as error:

            print(
                "OLD SQLITE USER MIGRATION ERROR:",
                error,
            )

            old_users = []

    else:

        old_users = []

    for old_user in old_users:

        email = str(
            old_user["email"]
            if sqlite_column_exists(old_user, "email")
            else ""
        ).strip().lower()

        username = str(
            old_user["username"]
            if sqlite_column_exists(old_user, "username")
            else ""
        ).strip()

        if not email or not username:
            continue

        existing = connection.execute(
            """
            SELECT id
            FROM users
            WHERE LOWER(email) = LOWER(%s)
               OR LOWER(username) = LOWER(%s)
            LIMIT 1
            """,
            (
                email,
                username,
            ),
        ).fetchone()

        if existing:
            continue

        role = "member"

        if sqlite_column_exists(
            old_user,
            "role",
        ):
            candidate_role = str(
                old_user["role"] or ""
            ).strip().lower()

            if candidate_role in {
                "member",
                "executive",
                "admin",
            }:
                role = candidate_role

        position = "Member"

        if sqlite_column_exists(
            old_user,
            "position",
        ):
            position = str(
                old_user["position"]
                or ""
            ).strip()

        if not position:

            if role == "admin":
                position = "Administrator"

            elif role == "executive":
                position = "Executive"

            else:
                position = "Member"

        created_at = (
            old_user["created_at"]
            if sqlite_column_exists(
                old_user,
                "created_at",
            )
            and old_user["created_at"]
            else datetime.now(
                timezone.utc
            )
        )

        verification_expires_at = (
            old_user["verification_expires_at"]
            if sqlite_column_exists(
                old_user,
                "verification_expires_at",
            )
            else None
        )

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
            VALUES (
                %s, %s, %s, %s, %s,
                %s, %s, %s, %s, %s,
                %s, %s, %s, %s, %s,
                %s, %s
            )
            """,
            (
                str(
                    old_user["first_name"]
                ).strip(),
                str(
                    old_user["last_name"]
                ).strip(),
                username,
                email,
                str(
                    old_user["phone"]
                    if sqlite_column_exists(
                        old_user,
                        "phone",
                    )
                    and old_user["phone"]
                    else ""
                ).strip(),
                str(
                    old_user["school"]
                ).strip(),
                str(
                    old_user["class_name"]
                ).strip(),
                str(
                    old_user["group_name"]
                ).strip(),
                str(
                    old_user["reason_for_joining"]
                    if sqlite_column_exists(
                        old_user,
                        "reason_for_joining",
                    )
                    and old_user["reason_for_joining"]
                    else ""
                ).strip(),
                old_user["password_hash"],
                bool(
                    old_user["email_verified"]
                    if sqlite_column_exists(
                        old_user,
                        "email_verified",
                    )
                    else False
                ),
                bool(
                    old_user["phone_verified"]
                    if sqlite_column_exists(
                        old_user,
                        "phone_verified",
                    )
                    else False
                ),
                (
                    old_user["verification_token"]
                    if sqlite_column_exists(
                        old_user,
                        "verification_token",
                    )
                    else None
                ),
                verification_expires_at,
                role,
                position,
                created_at,
            ),
        )

    # --------------------------------------------------------
    # OLD events.json
    # --------------------------------------------------------

    if os.path.exists(EVENTS_FILE):

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

        if isinstance(
            old_events,
            list,
        ):

            for old_event in old_events:

                if not isinstance(
                    old_event,
                    dict,
                ):
                    continue

                title = str(
                    old_event.get(
                        "title",
                        "",
                    )
                ).strip()

                event_date = str(
                    old_event.get(
                        "date",
                        "",
                    )
                ).strip()

                if not title or not event_date:
                    continue

                try:

                    parsed_date = datetime.strptime(
                        event_date,
                        "%Y-%m-%d",
                    ).date()

                except ValueError:

                    continue

                event_key = str(
                    old_event.get("id")
                    or secrets.token_urlsafe(12)
                )

                existing_event = connection.execute(
                    """
                    SELECT id
                    FROM events
                    WHERE event_key = %s
                    LIMIT 1
                    """,
                    (event_key,),
                ).fetchone()

                if existing_event:
                    continue

                now = datetime.now(
                    timezone.utc
                )

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
                    VALUES (
                        %s, %s, %s, %s,
                        %s, %s, %s, %s
                    )
                    """,
                    (
                        event_key,
                        title,
                        parsed_date,
                        str(
                            old_event.get(
                                "category",
                                "",
                            )
                        ).strip(),
                        str(
                            old_event.get(
                                "location",
                                "",
                            )
                        ).strip(),
                        str(
                            old_event.get(
                                "description",
                                "",
                            )
                        ).strip(),
                        now,
                        now,
                    ),
                )

    connection.commit()
    connection.close()

# ============================================================
# ENVIRONMENT ADMIN
# ============================================================

def ensure_env_admin_account():

    if not ADMIN_CREDENTIALS_CONFIGURED:
        return

    connection = get_db()

    existing = connection.execute(
        """
        SELECT id
        FROM users
        WHERE LOWER(username) = LOWER(%s)
        LIMIT 1
        """,
        (ADMIN_USERNAME,),
    ).fetchone()

    password_hash = generate_password_hash(
        ADMIN_PASSWORD
    )

    if existing:

        connection.execute(
            """
            UPDATE users
            SET
                role = 'admin',
                position = 'Administrator',
                password_hash = %s,
                email_verified = TRUE,
                phone_verified = TRUE
            WHERE id = %s
            """,
            (
                password_hash,
                existing["id"],
            ),
        )

    else:

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
                role,
                position
            )
            VALUES (
                %s, %s, %s, %s, %s,
                %s, %s, %s, %s, %s,
                TRUE, TRUE, 'admin',
                'Administrator'
            )
            """,
            (
                "New Gen",
                "Administrator",
                ADMIN_USERNAME,
                f"{ADMIN_USERNAME}@newgen.local",
                "",
                "New Gen",
                "Administrator",
                "Administration",
                "System administrator account",
                password_hash,
            ),
        )

    connection.commit()
    connection.close()


# ============================================================
# OFFICIAL ROLE HELPERS
# ============================================================

def normalize_phone(value):

    return "".join(
        character
        for character in str(value or "")
        if character.isdigit()
    )


def get_official_role(
    email,
    phone,
    connection=None,
):

    owns_connection = False

    if connection is None:

        connection = get_db()
        owns_connection = True

    normalized_phone = normalize_phone(
        phone
    )

    official_role = connection.execute(
        """
        SELECT
            id,
            first_name,
            last_name,
            email,
            phone,
            role,
            position,
            active
        FROM official_roles
        WHERE active = TRUE
          AND (
                LOWER(email) = LOWER(%s)
                OR regexp_replace(
                    phone,
                    '[^0-9]',
                    '',
                    'g'
                ) = %s
          )
        LIMIT 1
        """,
        (
            email,
            normalized_phone,
        ),
    ).fetchone()

    if owns_connection:
        connection.close()

    return official_role


def sync_user_role(
    user,
    connection,
):

    # The configured environment admin is always admin.
    if (
        ADMIN_CREDENTIALS_CONFIGURED
        and user["username"].lower()
        == ADMIN_USERNAME.lower()
    ):

        connection.execute(
            """
            UPDATE users
            SET
                role = 'admin',
                position = 'Administrator'
            WHERE id = %s
            """,
            (user["id"],),
        )

        return "admin", "Administrator"

    official_role = get_official_role(
        user["email"],
        user["phone"],
        connection,
    )

    if not official_role:

        connection.execute(
            """
            UPDATE users
            SET
                role = 'member',
                position = 'Member'
            WHERE id = %s
            """,
            (user["id"],),
        )

        return "member", "Member"

    role = official_role["role"]

    position = (
        official_role["position"]
        or (
            "Administrator"
            if role == "admin"
            else "Executive"
        )
    )

    connection.execute(
        """
        UPDATE users
        SET
            role = %s,
            position = %s
        WHERE id = %s
        """,
        (
            role,
            position,
            user["id"],
        ),
    )

    return role, position


# ============================================================
# START DATABASE
# ============================================================

init_database()
migrate_old_data()
ensure_env_admin_account()


# ============================================================
# EVENT HELPERS
# ============================================================

def load_events():

    connection = get_db()

    rows = connection.execute(
        """
        SELECT
            event_key AS id,
            title,
            TO_CHAR(
                event_date,
                'YYYY-MM-DD'
            ) AS date,
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
            TO_CHAR(
                event_date,
                'YYYY-MM-DD'
            ) AS date,
            category,
            location,
            description,
            created_at,
            updated_at
        FROM events
        WHERE event_key = %s
        LIMIT 1
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
        session.get("member_logged_in") is True
        and bool(
            session.get("member_id")
        )
    )


def get_current_member():

    user_id = session.get(
        "member_id"
    )

    if not user_id:
        return None

    connection = get_db()

    user = connection.execute(
        """
        SELECT *
        FROM users
        WHERE id = %s
        LIMIT 1
        """,
        (user_id,),
    ).fetchone()

    connection.close()

    return user


def is_admin_logged_in():

    if session.get(
        "admin_logged_in"
    ) is True:

        return True

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
        WHERE id = %s
        LIMIT 1
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
            str(value)[:10],
            "%Y-%m-%d",
        )

        return date_object.strftime(
            "%d/%m/%Y"
        )

    except ValueError:

        return str(value)


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
    ] = (
        "camera=(), "
        "microphone=(), "
        "geolocation=()"
    )

    return response


# ============================================================
# HOME
# ============================================================

@app.route("/")
def home():

    return render_template(
        "index.html",
        events=load_events()[:3],
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

        for field, (
            value,
            label,
        ) in required_fields.items():

            if not value:

                errors[field] = (
                    f"{label} is required."
                )

        if username:

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
                    "Username may only contain letters, "
                    "numbers, underscores and hyphens."
                )

        if email and (
            "@" not in email
            or "." not in email.rsplit(
                "@",
                1,
            )[-1]
        ):

            errors["email"] = (
                "Enter a valid email address."
            )

        if password and len(password) < 8:

            errors["password"] = (
                "Password must be at least 8 characters."
            )

        if password != confirm_password:

            errors["confirm_password"] = (
                "Passwords do not match."
            )

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

        if (
            class_name
            and class_name not in allowed_classes
        ):

            errors["class_name"] = (
                "Please select a valid class."
            )

        if (
            group_name
            and group_name not in allowed_groups
        ):

            errors["group_name"] = (
                "Please select a valid New Gen group."
            )

        if errors:

            return render_template(
                "signup.html",
                errors=errors,
                form_error=(
                    "Please correct the highlighted fields."
                ),
                form_data=request.form,
            )

        connection = get_db()

        existing_email = connection.execute(
            """
            SELECT id
            FROM users
            WHERE LOWER(email) = LOWER(%s)
            LIMIT 1
            """,
            (email,),
        ).fetchone()

        existing_username = connection.execute(
            """
            SELECT id
            FROM users
            WHERE LOWER(username) = LOWER(%s)
            LIMIT 1
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
                form_data=request.form,
            )

        official_role = get_official_role(
            email,
            phone,
            connection,
        )

        assigned_role = "member"
        assigned_position = "Member"

        if official_role:

            assigned_role = official_role["role"]

            assigned_position = (
                official_role["position"]
                or (
                    "Administrator"
                    if assigned_role == "admin"
                    else "Executive"
                )
            )

        password_hash = generate_password_hash(
            password
        )

        verification_token = secrets.token_urlsafe(
            32
        )

        verification_expires_at = (
            datetime.now(timezone.utc)
            + timedelta(
                hours=VERIFICATION_EXPIRY_HOURS
            )
        )

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
                position
            )
            VALUES (
                %s, %s, %s, %s, %s,
                %s, %s, %s, %s, %s,
                FALSE,
                FALSE,
                %s,
                %s,
                %s,
                %s
            )
            RETURNING id
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
                verification_token,
                verification_expires_at,
                assigned_role,
                assigned_position,
            ),
        )

        user_id = cursor.fetchone()["id"]

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
        form_data={},
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

        member = get_current_member()

        if member:

            if member["role"] == "admin":
                return redirect(
                    url_for("admin_portal")
                )

            if member["role"] == "executive":
                return redirect(
                    url_for("executive_dashboard")
                )

            return redirect(
                url_for("member_dashboard")
            )

        session.clear()

    if request.method == "POST":

        login_value = request.form.get(
            "login",
            "",
        ).strip()

        password = request.form.get(
            "password",
            "",
        )

        if not login_value:

            flash(
                "Please enter your username or email.",
                "error",
            )

            return render_template(
                "login.html",
                errors={
                    "login":
                        "Username or email is required."
                },
                form_data={
                    "login": login_value,
                },
            )

        if not password:

            flash(
                "Please enter your password.",
                "error",
            )

            return render_template(
                "login.html",
                errors={
                    "password":
                        "Password is required."
                },
                form_data={
                    "login": login_value,
                },
            )

        connection = get_db()

        user = connection.execute(
            """
            SELECT *
            FROM users
            WHERE LOWER(email) = LOWER(%s)
               OR LOWER(username) = LOWER(%s)
            LIMIT 1
            """,
            (
                login_value,
                login_value,
            ),
        ).fetchone()

        if not user:

            connection.close()

            flash(
                "Incorrect username/email or password.",
                "error",
            )

            return render_template(
                "login.html",
                errors={
                    "login":
                        "Incorrect username/email or password."
                },
                form_data={
                    "login": login_value,
                },
            )

        sync_user_role(
            user,
            connection,
        )

        user = connection.execute(
            """
            SELECT *
            FROM users
            WHERE id = %s
            LIMIT 1
            """,
            (user["id"],),
        ).fetchone()

        password_correct = False

        try:

            password_correct = check_password_hash(
                user["password_hash"],
                password,
            )

        except Exception as error:

            print(
                "PASSWORD CHECK ERROR:",
                error,
            )

        if not password_correct:

            connection.close()

            flash(
                "Incorrect username/email or password.",
                "error",
            )

            return render_template(
                "login.html",
                errors={
                    "login":
                        "Incorrect username/email or password."
                },
                form_data={
                    "login": login_value,
                },
            )

        if (
            user["role"] != "admin"
            and not user["email_verified"]
        ):

            connection.close()

            flash(
                "Please verify your email before logging in.",
                "error",
            )

            return render_template(
                "login.html",
                errors={
                    "login":
                        "Please verify your email before logging in."
                },
                form_data={
                    "login": login_value,
                },
            )

        connection.commit()
        connection.close()

        session.clear()
        session.permanent = True

        session["member_logged_in"] = True
        session["member_id"] = user["id"]

        if user["role"] == "admin":

            session["admin_logged_in"] = True
            session["admin_member_id"] = user["id"]

            flash(
                f"Welcome back, {user['first_name']}!",
                "success",
            )

            return redirect(
                url_for("admin_portal")
            )

        if user["role"] == "executive":

            flash(
                f"Welcome back, {user['first_name']}!",
                "success",
            )

            return redirect(
                url_for("executive_dashboard")
            )

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
        form_data={},
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

    if (
        member["role"] != "admin"
        and not member["email_verified"]
    ):

        session.clear()

        flash(
            "Please verify your email before accessing your dashboard.",
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
        WHERE LOWER(email) = LOWER(%s)
        LIMIT 1
        """,
        (email,),
    ).fetchone()

    if not user:

        connection.close()

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
    )

    connection.execute(
        """
        UPDATE users
        SET
            verification_token = %s,
            verification_expires_at = %s
        WHERE id = %s
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

@app.route(
    "/verify-email/<token>"
)
def verify_email(token):

    connection = get_db()

    user = connection.execute(
        """
        SELECT *
        FROM users
        WHERE verification_token = %s
        LIMIT 1
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

        if isinstance(
            expires_at,
            datetime,
        ):

            expiry = expires_at

        else:

            try:

                expiry = datetime.fromisoformat(
                    str(expires_at)
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

    connection.execute(
        """
        UPDATE users
        SET
            email_verified = TRUE,
            verification_token = NULL,
            verification_expires_at = NULL
        WHERE id = %s
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

    if not member:

        session.clear()

        flash(
            "Your account could not be found.",
            "error",
        )

        return redirect(
            url_for("login")
        )

    if member["role"] != "executive":

        flash(
            "Executive access is restricted to official "
            "New Gen executives.",
            "error",
        )

        return redirect(
            url_for("member_dashboard")
        )

    connection = get_db()

    member_count = connection.execute(
        """
        SELECT COUNT(*) AS count
        FROM users
        WHERE role != 'admin'
        """
    ).fetchone()["count"]

    executive_count = connection.execute(
        """
        SELECT COUNT(*) AS count
        FROM users
        WHERE role = 'executive'
        """
    ).fetchone()["count"]

    connection.close()

    return render_template(
        "executive_dashboard.html",
        member=member,
        member_count=member_count,
        executive_count=executive_count,
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

            return render_template(
                "admin_login.html",
                errors={
                    "username":
                        "Administrator username is required."
                },
                form_data={
                    "username": username,
                },
            )

        if not password:

            return render_template(
                "admin_login.html",
                errors={
                    "password":
                        "Administrator password is required."
                },
                form_data={
                    "username": username,
                },
            )

        connection = get_db()

        admin_user = connection.execute(
            """
            SELECT *
            FROM users
            WHERE LOWER(username) = LOWER(%s)
              AND role = 'admin'
            LIMIT 1
            """,
            (username,),
        ).fetchone()

        connection.close()

        authenticated = False
        admin_member_id = None

        if admin_user:

            try:

                authenticated = check_password_hash(
                    admin_user["password_hash"],
                    password,
                )

            except Exception:

                authenticated = False

            if authenticated:

                admin_member_id = admin_user["id"]

        if (
            not authenticated
            and ADMIN_CREDENTIALS_CONFIGURED
        ):

            authenticated = (
                secrets.compare_digest(
                    username,
                    ADMIN_USERNAME,
                )
                and secrets.compare_digest(
                    password,
                    ADMIN_PASSWORD,
                )
            )

        if not authenticated:

            return render_template(
                "admin_login.html",
                errors={
                    "username":
                        "Administrator username or password is incorrect."
                },
                form_data={
                    "username": username,
                },
            )

        session.clear()
        session.permanent = True

        session["admin_logged_in"] = True

        if admin_member_id:

            session["admin_member_id"] = (
                admin_member_id
            )

            session["member_logged_in"] = True
            session["member_id"] = (
                admin_member_id
            )

        flash(
            "Administrator access granted.",
            "success",
        )

        return redirect(
            url_for("admin_portal")
        )

    return render_template(
        "admin_login.html",
        errors={},
        form_data={},
    )


# ============================================================
# ADMIN LOGOUT
# ============================================================

@app.route("/admin/logout")
def admin_logout():

    session.clear()

    flash(
        "You have been logged out of the administrator area.",
        "success",
    )

    return redirect(
        url_for("home")
    )


# ============================================================
# ADMIN PORTAL
# ============================================================

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
        WHERE role != 'admin'
        """
    ).fetchone()["count"]

    executive_count = connection.execute(
        """
        SELECT COUNT(*) AS count
        FROM users
        WHERE role = 'executive'
        """
    ).fetchone()["count"]

    connection.close()

    return render_template(
        "admin.html",
        members=members,
        applications=[],
        events=load_events(),
        event_count=event_count,
        member_count=member_count,
        executive_count=executive_count,
        pending_count=0,
        mode="Create",
        event=None,
    )


# ============================================================
# ADMIN EVENT CREATE / EDIT
# ============================================================

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
                members=[],
                applications=[],
                events=events,
                event=current_event,
                mode=(
                    "Edit"
                    if current_event
                    else "Create"
                ),
                errors=errors,
                event_count=len(events),
                member_count=0,
                executive_count=0,
                pending_count=0,
            )

        try:

            parsed_date = datetime.strptime(
                date_value,
                "%Y-%m-%d",
            ).date()

        except ValueError:

            return render_template(
                "admin.html",
                members=[],
                applications=[],
                events=events,
                event=current_event,
                mode=(
                    "Edit"
                    if current_event
                    else "Create"
                ),
                errors={
                    "date":
                        "A valid event date is required."
                },
                event_count=len(events),
                member_count=0,
                executive_count=0,
                pending_count=0,
            )

        now = datetime.now(
            timezone.utc
        )

        connection = get_db()

        existing = connection.execute(
            """
            SELECT id
            FROM events
            WHERE event_key = %s
            LIMIT 1
            """,
            (event_id_value,),
        ).fetchone()

        if existing:

            connection.execute(
                """
                UPDATE events
                SET
                    title = %s,
                    event_date = %s,
                    category = %s,
                    location = %s,
                    description = %s,
                    updated_at = %s
                WHERE event_key = %s
                """,
                (
                    title,
                    parsed_date,
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
                VALUES (
                    %s, %s, %s, %s,
                    %s, %s, %s, %s
                )
                """,
                (
                    event_id_value,
                    title,
                    parsed_date,
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
        members=[],
        applications=[],
        events=events,
        event=current_event,
        mode=(
            "Edit"
            if current_event
            else "Create"
        ),
        errors={},
        event_count=len(events),
        member_count=0,
        executive_count=0,
        pending_count=0,
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
        WHERE event_key = %s
        LIMIT 1
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

    connection.execute(
        """
        DELETE FROM events
        WHERE event_key = %s
        """,
        (event_id,),
    )

    connection.commit()
    connection.close()

    flash(
        f"Event '{event['title']}' deleted successfully.",
        "success",
    )

    return redirect(
        url_for("admin_portal")
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

    connection.close()

    return render_template(
        "admin_members.html",
        members=members,
        applications=[],
        search_query="",
    )


# ============================================================
# ADMIN MEMBER SEARCH
# ============================================================

@app.route("/admin/members/search")
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
        WHERE
            first_name ILIKE %s
            OR last_name ILIKE %s
            OR username ILIKE %s
            OR email ILIKE %s
            OR school ILIKE %s
            OR group_name ILIKE %s
        ORDER BY created_at DESC
        """,
        (
            f"%{query}%",
            f"%{query}%",
            f"%{query}%",
            f"%{query}%",
            f"%{query}%",
            f"%{query}%",
        ),
    ).fetchall()

    connection.close()

    return render_template(
        "admin_members.html",
        members=members,
        applications=[],
        search_query=query,
    )


# ============================================================
# MEMBERS DIRECTORY
# ============================================================

@app.route("/members")
def members():

    if not is_member_logged_in():

        flash(
            "Please log in to view the New Gen members directory.",
            "error",
        )

        return redirect(
            url_for("login")
        )

    member = get_current_member()

    if not member:

        session.clear()

        flash(
            "Your account could not be found. Please log in again.",
            "error",
        )

        return redirect(
            url_for("login")
        )

    if (
        member["role"] != "admin"
        and not member["email_verified"]
    ):

        flash(
            "Please verify your email before viewing the members directory.",
            "error",
        )

        return redirect(
            url_for(
                "verify_notice",
                email=member["email"],
            )
        )

    connection = get_db()

    members_list = connection.execute(
        """
        SELECT
            id,
            first_name,
            last_name,
            username,
            school,
            class_name,
            group_name,
            role,
            position,
            created_at
        FROM users
        WHERE role != 'admin'
        ORDER BY created_at DESC
        """
    ).fetchall()

    connection.close()

    return render_template(
        "members.html",
        members=members_list,
    )


# ============================================================
# ADMIN MEMBER DELETE CONFIRMATION
# ============================================================

@app.route(
    "/admin/member/<int:user_id>/delete"
)
def delete_member_page(user_id):

    if not is_admin_logged_in():

        flash(
            "Administrator access required.",
            "error",
        )

        return redirect(
            url_for("admin_login")
        )

    connection = get_db()

    member = connection.execute(
        """
        SELECT *
        FROM users
        WHERE id = %s
        LIMIT 1
        """,
        (user_id,),
    ).fetchone()

    connection.close()

    if not member:

        flash(
            "Member not found.",
            "error",
        )

        return redirect(
            url_for("admin_members")
        )

    if member["role"] == "admin":

        flash(
            "Administrator accounts cannot be deleted from this panel.",
            "error",
        )

        return redirect(
            url_for("admin_members")
        )

    return render_template(
        "delete_confirm.html",
        person=member,
    )


# ============================================================
# ADMIN MEMBER DELETE
# ============================================================

@app.route(
    "/admin/member/<int:user_id>/delete/confirm",
    methods=["POST"],
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
        WHERE id = %s
        LIMIT 1
        """,
        (user_id,),
    ).fetchone()

    if not user:

        connection.close()

        flash(
            "Member not found.",
            "error",
        )

        return redirect(
            url_for("admin_members")
        )

    if user["role"] == "admin":

        connection.close()

        flash(
            "Administrator accounts cannot be deleted "
            "from this panel.",
            "error",
        )

        return redirect(
            url_for("admin_members")
        )

    connection.execute(
        """
        DELETE FROM users
        WHERE id = %s
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
# ADMIN ROLE CONTROL
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

    requested_role = request.form.get(
        "role",
        "member",
    ).strip().lower()

    if requested_role not in {
        "member",
        "executive",
        "admin",
    }:

        flash(
            "Invalid role.",
            "error",
        )

        return redirect(
            url_for("admin_members")
        )

    current_admin_member_id = session.get(
        "admin_member_id"
    )

    if (
        current_admin_member_id
        and int(current_admin_member_id)
        == int(user_id)
        and requested_role != "admin"
    ):

        flash(
            "You cannot remove your own administrator role.",
            "error",
        )

        return redirect(
            url_for("admin_members")
        )

    connection = get_db()

    user = connection.execute(
        """
        SELECT
            id,
            email,
            phone,
            role
        FROM users
        WHERE id = %s
        LIMIT 1
        """,
        (user_id,),
    ).fetchone()

    if not user:

        connection.close()

        flash(
            "Member not found.",
            "error",
        )

        return redirect(
            url_for("admin_members")
        )

    if requested_role in {
        "admin",
        "executive",
    }:

        official_role = get_official_role(
            user["email"],
            user["phone"],
            connection,
        )

        if not official_role:

            connection.close()

            flash(
                "That elevated role cannot be assigned manually. "
                "The person must be in the official New Gen roster.",
                "error",
            )

            return redirect(
                url_for("admin_members")
            )

        if official_role["role"] != requested_role:

            connection.close()

            flash(
                "The requested role does not match the official roster.",
                "error",
            )

            return redirect(
                url_for("admin_members")
            )

        new_position = (
            official_role["position"]
            or (
                "Administrator"
                if requested_role == "admin"
                else "Executive"
            )
        )

        connection.execute(
            """
            UPDATE users
            SET
                role = %s,
                position = %s
            WHERE id = %s
            """,
            (
                requested_role,
                new_position,
                user_id,
            ),
        )

    else:

        connection.execute(
            """
            UPDATE users
            SET
                role = 'member',
                position = 'Member'
            WHERE id = %s
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
        member=get_current_member(),
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
