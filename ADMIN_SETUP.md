# Admin login setup

Set these environment variables before starting the Flask app:

- `ADMIN_EMAIL`: email address used for the admin login.
- `ADMIN_PASSWORD`: admin password (use a unique password of at least 12 characters).
- `FLASK_SECRET_KEY`: a long, random secret that remains consistent between app restarts and across workers.

The admin account is configured separately from customer registration. Admins sign in through the regular `/login` page and are sent to `/admin`, which lists submitted work requests. Requests to `/admin` are restricted to authenticated admin sessions.

If `FLASK_SECRET_KEY` is not set, the app generates a temporary random key when it starts; sessions will not persist across restarts. Configure a stable secret for deployment.
