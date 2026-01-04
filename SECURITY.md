# Security Policy

## Supported Versions

This project is currently maintained on the `main` branch.

## Reporting a Vulnerability

Please do not open public issues for security-sensitive problems.

- Send a report by email to the maintainer or your organization security contact.
- Include a clear description, reproduction steps, and impact.

## Security Notes

- Set a strong `SECRET_KEY` in production.
- Do not commit `.env` files. Use `.env.example` as a template.
- Admin bootstrap is optional and controlled by `ADMIN_USERNAME` / `ADMIN_PASSWORD`.
- Uploaded files are stored on disk under `instance/uploads/` and served only through authenticated routes.
