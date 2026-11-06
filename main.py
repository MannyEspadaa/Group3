import os
import re
import hashlib

from flask import (
    Flask, render_template, request, redirect,
    url_for, session, jsonify, flash
)

from werkzeug.security import generate_password_hash, check_password_hash
from google.api_core.exceptions import AlreadyExists
from firebase_config import db


app = Flask(__name__)

app.secret_key = os.environ.get(
    "FLASK_SECRET_KEY",
    "change-this-secret-before-deployment"
)

EMAIL_PATTERN = re.compile(r'^[^@\s]+@[^@\s]+\.[^@\s]+$')

# Firestore collection
CUSTOMERS = db.collection("Customer")


# Find a customer using their email address
def find_customer_by_email(email):

    customers = CUSTOMERS.where(
        "Email", "==", email
    ).limit(1).stream()

    for document in customers:
        customer = document.to_dict()
        customer["CustomerID"] = document.id
        return customer

    return None


# HOME PAGE
@app.route('/')
def home():
    return render_template('home.html')


# LOGIN
@app.route('/login', methods=['GET', 'POST'])
def login():

    if request.method == 'POST':

        email = (request.form.get('email') or '').strip().lower()
        password = request.form.get('password') or ''

        # Find customer in Firestore
        customer = find_customer_by_email(email)

        # Check if customer exists and password matches
        if customer and check_password_hash(
            customer.get('Password', ''),
            password
        ):

            # Save customer information in session
            session['user_id'] = customer['CustomerID']
            session['first_name'] = customer['FirstName']
            session['last_name'] = customer['LastName']

            return redirect(url_for('profile'))

        flash('Incorrect email or password.')

    return render_template('login.html')

# REGISTER
@app.route('/register', methods=['GET', 'POST'])
def register():

    if request.method == 'POST':

        first_name = (request.form.get('first') or '').strip()
        last_name = (request.form.get('last') or '').strip()
        email = (request.form.get('email') or '').strip().lower()
        password = request.form.get('password') or ''
        confirm_password = request.form.get('confirm_password') or ''

        # VALIDATION

        if not first_name or not last_name:
            return render_template(
                'register.html',
                error='First and last name are required.'
            )

        if len(first_name) > 25 or len(last_name) > 25:
            return render_template(
                'register.html',
                error='Names must be 25 characters or fewer.'
            )

        if not EMAIL_PATTERN.fullmatch(email):
            return render_template(
                'register.html',
                error='Please enter a valid email address.'
            )

        if len(email) > 50:
            return render_template(
                'register.html',
                error='Email must be 50 characters or fewer.'
            )

        if len(password) < 12:
            return render_template(
                'register.html',
                error='Password must be at least 12 characters long.'
            )

        if len(password) > 128:
            return render_template(
                'register.html',
                error='Password must be 128 characters or fewer.'
            )

        if password != confirm_password:
            return render_template(
                'register.html',
                error='Passwords do not match.'
            )

        # Create a consistent document ID from the email.
        # This helps prevent duplicate registrations.

        customer_id = hashlib.sha256(
            email.encode('utf-8')
        ).hexdigest()

        customer_ref = CUSTOMERS.document(customer_id)

        # CUSTOMER DATA

        customer_data = {
            'CustomerID': customer_id,
            'FirstName': first_name,
            'LastName': last_name,
            'Email': email,
            'Password': generate_password_hash(password),
            'PhoneNumber': None,
            'Address': None,
            'City': None,
            'State': None
        }

        try:

            # Create fails if the document ID already exists.
            customer_ref.create(customer_data)

        except AlreadyExists:

            return render_template(
                'register.html',
                error='An account with that email already exists.'
            )

        except Exception:

            app.logger.exception("Firestore registration failed.")

            return render_template(
                'register.html',
                error='Registration is temporarily unavailable. Please try again.'
            ), 503

        # SAVE SESSION

        session['user_id'] = customer_id
        session['first_name'] = first_name
        session['last_name'] = last_name

        return redirect(url_for('home'))

    return render_template('register.html')


# PROFILE
@app.route('/profile')
def profile():

    user_id = session.get('user_id')

    if not user_id:
        flash('Please log in to view your profile.')
        return redirect(url_for('login'))

    customer_document = CUSTOMERS.document(str(user_id)).get()

    if not customer_document.exists:

        session.clear()

        flash('Customer account not found.')
        return redirect(url_for('login'))

    customer = customer_document.to_dict()

    customer['CustomerID'] = customer_document.id

    return render_template(
        'profile.html',
        customer=customer
    )


# UPDATE PROFILE
@app.route('/update_profile', methods=['POST'])
def update_profile():

    user_id = session.get('user_id')

    if not user_id:
        flash('Please log in to update your profile.')
        return redirect(url_for('login'))

    first_name = request.form.get('FirstName', '').strip()
    last_name = request.form.get('LastName', '').strip()
    email = request.form.get('Email', '').strip().lower()
    phone = request.form.get('PhoneNumber', '').strip()
    address = request.form.get('Address', '').strip()
    city = request.form.get('City', '').strip()
    state = request.form.get('State', '').strip().upper()

    # VALIDATION

    if not first_name or not last_name or not email:
        flash('First name, last name, and email are required.')
        return redirect(url_for('profile'))

    if len(first_name) > 25 or len(last_name) > 25:
        flash('First and last names must be 25 characters or fewer.')
        return redirect(url_for('profile'))

    if len(email) > 50 or not EMAIL_PATTERN.fullmatch(email):
        flash('Please enter a valid email address.')
        return redirect(url_for('profile'))

    if len(address) > 30 or len(city) > 25:
        flash('Address or city exceeds the allowed length.')
        return redirect(url_for('profile'))

    if state and not re.fullmatch(r'[A-Z]{2}', state):
        flash('State must be a two-letter abbreviation.')
        return redirect(url_for('profile'))

    if phone and not re.fullmatch(r'\d{1,11}', phone):
        flash('Phone number must contain up to 11 digits.')
        return redirect(url_for('profile'))

    customer_ref = CUSTOMERS.document(str(user_id))

    try:

        customer_document = customer_ref.get()

        if not customer_document.exists:
            session.clear()
            flash('Customer account not found.')
            return redirect(url_for('login'))

        # CHECK FOR DUPLICATE EMAIL

        existing_customers = CUSTOMERS.where(
            'Email', '==', email
        ).limit(2).stream()

        for customer in existing_customers:

            if customer.id != str(user_id):
                flash('That email address is already in use.')
                return redirect(url_for('profile'))

        # UPDATE FIRESTORE DOCUMENT

        customer_ref.update({

            'FirstName': first_name,
            'LastName': last_name,
            'Email': email,
            'PhoneNumber': phone or None,
            'Address': address or None,
            'City': city or None,
            'State': state or None

        })

        session['first_name'] = first_name
        session['last_name'] = last_name

        flash('Your profile has been updated successfully.')

    except Exception:

        app.logger.exception("Firestore profile update failed.")

        flash('Unable to update your profile. Please try again.')

    return redirect(url_for('profile'))


# CHANGE PASSWORD
@app.route('/change_password', methods=['POST'])
def change_password():

    user_id = session.get('user_id')

    if not user_id:
        flash('Please log in to change your password.')
        return redirect(url_for('login'))

    current_password = request.form.get('current_password', '')
    new_password = request.form.get('new_password', '')
    confirm_password = request.form.get('confirm_password', '')

    # VALIDATION

    if not current_password or not new_password or not confirm_password:
        flash('Please complete all password fields.')
        return redirect(url_for('profile'))

    if len(new_password) < 8:
        flash('Your new password must be at least 8 characters long.')
        return redirect(url_for('profile'))

    if new_password != confirm_password:
        flash('The new passwords do not match.')
        return redirect(url_for('profile'))

    customer_ref = CUSTOMERS.document(str(user_id))

    try:

        customer_document = customer_ref.get()

        if not customer_document.exists:

            session.clear()

            flash('Customer account not found.')
            return redirect(url_for('login'))

        customer = customer_document.to_dict()

        stored_password = customer.get('Password', '')

        if not isinstance(stored_password, str) or not check_password_hash(
            stored_password, current_password
        ):

            flash('Your current password is incorrect.')
            return redirect(url_for('profile'))

        # HASH NEW PASSWORD

        hashed_password = generate_password_hash(new_password)

        customer_ref.update({
            'Password': hashed_password
        })

        flash('Your password has been changed successfully.')

    except Exception:

        app.logger.exception("Firestore password update failed.")

        flash('Unable to change your password. Please try again.')

    return redirect(url_for('profile'))


# LOGOUT
@app.route('/logout', methods=['POST', 'GET'])
def logout():

    session.clear()

    flash('You have been logged out.')

    return redirect(url_for('home'))


# RUN APPLICATION
if __name__ == '__main__':
    app.run(debug=True)
