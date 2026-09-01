import json
import os
import uuid
import sqlite3

from werkzeug.security import generate_password_hash

from flask import Flask, flash, redirect, render_template, request, session, url_for

app = Flask(__name__)
app.secret_key = os.environ.get('NEWGEN_SECRET_KEY', 'newgen-secret-key-2026')

ADMIN_USERNAME = os.environ.get('NEWGEN_ADMIN_USER', 'newgenadmin')
ADMIN_PASSWORD = os.environ.get('NEWGEN_ADMIN_PASS', 'NewGen2026!')

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
EVENTS_FILE = os.path.join(BASE_DIR, 'events.json')
# ---------------------------------------------------
# Member database
# ---------------------------------------------------

DATABASE_FILE = os.path.join(BASE_DIR, 'members.db')


def get_db():
    connection = sqlite3.connect(DATABASE_FILE)
    connection.row_factory = sqlite3.Row
    return connection


def init_database():
    connection = get_db()

    connection.execute("""
        CREATE TABLE IF NOT EXISTS members (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            first_name TEXT NOT NULL,
            last_name TEXT NOT NULL,
            username TEXT NOT NULL UNIQUE,
            email TEXT NOT NULL UNIQUE,
            phone TEXT NOT NULL,
            school TEXT NOT NULL,
            class_name TEXT NOT NULL,
            group_name TEXT NOT NULL,
            reason TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            email_verified INTEGER NOT NULL DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    connection.commit()
    connection.close()


init_database()


def load_events():
    if not os.path.exists(EVENTS_FILE):
        return []
    with open(EVENTS_FILE, 'r', encoding='utf-8') as file:
        try:
            data = json.load(file)
            return data if isinstance(data, list) else []
        except json.JSONDecodeError:
            return []


def save_events(events):
    with open(EVENTS_FILE, 'w', encoding='utf-8') as file:
        json.dump(events, file, indent=2)


def is_admin_logged_in():
    return session.get('admin_logged_in') is True


@app.route('/')
def home():
    events = sorted(load_events(), key=lambda event: event.get('date', ''))[:3]
    return render_template('index.html', events=events)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':

        first_name = request.form.get('first_name', '').strip()
        last_name = request.form.get('last_name', '').strip()
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip().lower()
        phone = request.form.get('phone', '').strip()
        school = request.form.get('school', '').strip()
        class_name = request.form.get('class_name', '').strip()
        group_name = request.form.get('group_name', '').strip()
        reason = request.form.get('reason', '').strip()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')

        # Check required fields
        if not all([
            first_name,
            last_name,
            username,
            email,
            phone,
            school,
            class_name,
            group_name,
            reason,
            password
        ]):
            flash('Please complete every field.', 'error')
            return render_template('signup.html')

        # Check password confirmation
        if password != confirm_password:
            flash('Passwords do not match.', 'error')
            return render_template('signup.html')

        # Basic password length requirement
        if len(password) < 8:
            flash('Password must be at least 8 characters.', 'error')
            return render_template('signup.html')

        connection = get_db()

        # Check whether username already exists
        existing_username = connection.execute(
            'SELECT id FROM members WHERE username = ?',
            (username,)
        ).fetchone()

        if existing_username:
            connection.close()
            flash('That username is already taken.', 'error')
            return render_template('signup.html')

        # Check whether email already exists
        existing_email = connection.execute(
            'SELECT id FROM members WHERE email = ?',
            (email,)
        ).fetchone()

        if existing_email:
            connection.close()
            flash('An account with that email already exists.', 'error')
            return render_template('signup.html')

        # Hash the password before storing it
        password_hash = generate_password_hash(password)

        connection.execute("""
            INSERT INTO members (
                first_name,
                last_name,
                username,
                email,
                phone,
                school,
                class_name,
                group_name,
                reason,
                password_hash
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            first_name,
            last_name,
            username,
            email,
            phone,
            school,
            class_name,
            group_name,
            reason,
            password_hash
        ))

        connection.commit()
        connection.close()

        flash(
            'Your New Gen account has been created successfully!',
            'success'
        )

        return redirect(url_for('login'))

    return render_template('signup.html')

@app.route('/music-dance')
def music_dance():
    return render_template('music_dance.html')


@app.route('/art')
def art():
    return render_template('art.html')


@app.route('/poetry')
def poetry():
    return render_template('poetry.html')


@app.route('/tech')
def tech():
    return render_template('tech.html')


@app.route('/calendar')
def calendar():
    events = sorted(load_events(), key=lambda event: event.get('date', ''))
    featured_event = events[0] if events else None
    return render_template('calendar.html', events=events, featured_event=featured_event)


@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if is_admin_logged_in():
        return redirect(url_for('admin'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()

        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            session['admin_logged_in'] = True
            flash('Admin access granted.', 'success')
            return redirect(url_for('admin'))

        flash('Incorrect username or password.', 'error')

    return render_template('admin_login.html')


@app.route('/admin/logout')
def admin_logout():
    session.pop('admin_logged_in', None)
    flash('You have been logged out.', 'success')
    return redirect(url_for('admin_login'))


@app.route('/admin', methods=['GET', 'POST'])
@app.route('/admin/edit/<event_id>', methods=['GET', 'POST'])
def admin(event_id=None):
    if not is_admin_logged_in():
        flash('Please log in to manage events.', 'error')
        return redirect(url_for('admin_login'))

    events = sorted(load_events(), key=lambda event: event.get('date', ''))
    current_event = next((event for event in events if event.get('id') == event_id), None)

    if request.method == 'POST':
        event_id_value = request.form.get('event_id') or str(uuid.uuid4())
        title = request.form.get('title', '').strip()
        day = request.form.get('day', '').strip()
        month = request.form.get('month', '').strip()
        year = request.form.get('year', '').strip()
        category = request.form.get('category', '').strip()
        location = request.form.get('location', '').strip()
        description = request.form.get('description', '').strip()
        date_value = build_iso_date(day, month, year)

        if not title or not date_value:
            flash('Title and complete date are required.', 'error')
            return render_template('admin.html', events=events, event=current_event, mode='Create')

        event_data = {
            'id': event_id_value,
            'title': title,
            'date': date_value,
            'category': category,
            'location': location,
            'description': description,
        }

        existing_events = load_events()
        if any(item.get('id') == event_id_value for item in existing_events):
            updated_events = [
                event_data if item.get('id') == event_id_value else item
                for item in existing_events
            ]
        else:
            updated_events = existing_events + [event_data]

        save_events(updated_events)
        flash('Event saved successfully.', 'success')
        return redirect(url_for('admin'))

    return render_template('admin.html', events=events, event=current_event, mode='Edit' if current_event else 'Create')


@app.route('/admin/delete/<event_id>', methods=['POST'])
def delete_event(event_id):
    if not is_admin_logged_in():
        flash('Please log in to manage events.', 'error')
        return redirect(url_for('admin_login'))

    events = load_events()
    remaining = [event for event in events if event.get('id') != event_id]
    save_events(remaining)
    flash('Event deleted successfully.', 'success')
    return redirect(url_for('admin'))


def format_display_date(value):
    if not value:
        return ''
    try:
        year, month, day = value.split('-')
        return f'{day}/{month}/{year}'
    except ValueError:
        return value


def build_iso_date(day, month, year):
    day = str(day).strip().zfill(2)
    month = str(month).strip().zfill(2)
    year = str(year).strip()
    if not day or not month or not year:
        return ''
    return f'{year}-{month}-{day}'

app.jinja_env.globals['format_display_date'] = format_display_date

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=8000)
