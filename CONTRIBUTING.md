# Contributing

## Development setup

```powershell
python -m venv .venv
.\.venv\Scripts\activate
pip install -r requirements.txt
```

## Running locally

```powershell
flask --app app run
```

## Guidelines

- Keep changes small and focused.
- Prefer security-by-default behavior.
- Do not commit secrets (`.env`) or runtime artifacts (`instance/`, virtualenv folders).

## Reporting bugs

Include:
- Steps to reproduce
- Expected vs actual behavior
- Screenshots/logs where applicable
