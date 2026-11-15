 Admin login setup

Configure the admin record in Firestore before starting the Flask app:

- Create a document in the `Admin` collection with string fields named `Email` and `Password`.
- The app checks the submitted email against `Email` and password against `Password`. A Werkzeug password hash (`scrypt:` or `pbkdf2:`) is also supported for `Password`.
- `FLASK_SECRET_KEY`: a long, random secret that remains consistent between app restarts and across workers.

Admins sign in through the regular `/login` page using the credentials stored in Firestore. The Firebase service account used by the app must have permission to read the `Admin` and `WorkRequests` collections.

For security, store a password hash rather than a plaintext password. Do not expose or commit the Firebase service-account JSON key.

If `FLASK_SECRET_KEY` is not set, the app generates a temporary random key when it starts; sessions will not persist across restarts. Configure a stable secret for deployment.
