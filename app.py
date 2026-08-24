import json
import os
import uuid

from flask import Flask, flash, redirect, render_template, request, session, url_for

app = Flask(__name__)
SESSION_SECRET = os.environ.get('NEWGEN_SECRET_KEY') or os.environ.get('SESSION_SECRET')
if not SESSION_SECRET:
    raise RuntimeError('SESSION_SECRET or NEWGEN_SECRET_KEY must be configured.')
app.secret_key = SESSION_SECRET

ADMIN_USERNAME = os.environ.get('NEWGEN_ADMIN_USER')
ADMIN_PASSWORD = os.environ.get('NEWGEN_ADMIN_PASS')
ADMIN_CREDENTIALS_CONFIGURED = bool(ADMIN_USERNAME and ADMIN_PASSWORD)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
EVENTS_FILE = os.path.join(BASE_DIR, 'events.json')


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

    if not ADMIN_CREDENTIALS_CONFIGURED:
        flash('Admin access is unavailable until secure credentials are configured.', 'error')
        return render_template('admin_login.html'), 503

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
    app.run(
        debug=os.environ.get('FLASK_DEBUG') == '1',
        host='0.0.0.0',
        port=int(os.environ.get('PORT', '5000')),
    )