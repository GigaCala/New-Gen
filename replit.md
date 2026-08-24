# Running the project on Replit

This is a Flask application with server-rendered templates and JSON-backed event
data.

## Run

The Replit workflow starts the app with:

```bash
python app.py
```

The app listens on `0.0.0.0` and uses port `5000` by default. Set `PORT` only
when running it on another port.

## Configuration

- `SESSION_SECRET` is required for Flask sessions. `NEWGEN_SECRET_KEY` can be
  be used instead when an explicitly dedicated session secret is preferred.
- `NEWGEN_ADMIN_USER` and `NEWGEN_ADMIN_PASS` are required for the admin login.
  Configure them as protected Replit Secrets before starting the app.
- Events are stored in `events.json`.