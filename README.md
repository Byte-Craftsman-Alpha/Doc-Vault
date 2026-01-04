# Cloud Vault (Flask + SQLite)

Explorer-style “cloud vault” built with Flask. Users can create folders, upload any documents, pin folders to Quick access, and search. Admins can monitor any user’s vault.

## Features

- **Authentication**: username + password signup/login
- **Explorer UI**: address bar, quick access, folders + file details view
- **Folders**: create folders (per-user)
- **Root uploads**: upload to **Vault (root)** or into a folder
- **Pinned folders**: pin/unpin folders to show in sidebar
- **Search**: partial filename match + advanced filters (extension, filetype, date)
- **Admin monitoring**: `/admin` view for all users and their folders/files

## Setup

```powershell
python -m venv .venv
.\.venv\Scripts\activate
pip install -r requirements.txt
```

## Run

### Option A: Run with a default admin

```powershell
$env:ADMIN_USERNAME = "admin"
$env:ADMIN_PASSWORD = "admin123"
flask --app app run
```

### Option B: Run without creating an admin automatically

```powershell
flask --app app run
```

App will create:
- SQLite DB at `instance/vault.db`
- Uploads stored under `instance/uploads/`

## Environment variables

Use `.env.example` as a template.

- `SECRET_KEY`
  - Required for secure sessions.
  - **Set a strong random value in production.**
- `ADMIN_USERNAME`, `ADMIN_PASSWORD`
  - Optional bootstrap admin user.
  - If set, the app will create/promote that user as admin on startup.
- `DATABASE_URL`
  - Optional SQLAlchemy database URL.
  - Default: `sqlite:///instance/vault.db`
- `UPLOAD_ROOT`
  - Optional file storage path.
  - Default: `instance/uploads`
- `MAX_CONTENT_LENGTH`
  - Optional max request size in bytes.
  - Default: `200MB`

## Repo hygiene

- Do **not** commit `.env`
- Do **not** commit runtime files under `instance/`
- Do **not** commit virtual environments (`.venv/`, `myenv/`)

See `.gitignore`.

## Project structure

- `app.py` Flask app (models, routes)
- `templates/` HTML templates
- `instance/` runtime DB + uploads (ignored by git)

## Security

See `SECURITY.md`.

## Notes

- Regular users: can create folders and upload/download their own files.
- Admin users: can monitor any user’s vault from `/admin`.
