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

            role TEXT NOT NULL DEFAULT 'member',

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
    return session.get("admin_logged_in") is True


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


# ============================================================
# HOME
# ============================================================

@app.route("/")
def home():
    return """
    <html style="background:black;color:white;font-size:40px;
    display:flex;justify-content:center;align-items:center;height:100vh;">
        NEW GEN TEST 2026
    </html>
    """

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
                role,
                created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                "member",
                created_at,
            ),
        )

        connection.commit()
        connection.close()

        flash(
            "Account created successfully. "
            "Please verify your email before using all member features.",
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
            message="This verification link is invalid or has expired.",
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
