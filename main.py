from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash
from flask_mysqldb import MySQL
from werkzeug.security import generate_password_hash, check_password_hash
import MySQLdb.cursors
import re

app = Flask(__name__)

app.secret_key = '-'

app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = '-'
app.config['MYSQL_DB'] = 'universal_power_washing'
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'

mysql = MySQL(app)

EMAIL_PATTERN = re.compile(r'^[^@\s]+@[^@\s]+\.[^@\s]+$')


@app.route('/')
def home():
    return render_template('home.html')

@app.route('/index', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        return login()
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = (request.form.get('email') or '').strip().lower()
        password = request.form.get('password') or ''

        if not EMAIL_PATTERN.fullmatch(email):
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest' or request.is_json:
                return jsonify({'success': False, 'message': 'Please enter a valid email address.'}), 400
            return render_template('index.html', error='Please enter a valid email address.')

        cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cur.execute('SELECT CustomerID, FirstName, LastName, Password FROM customer WHERE Email = %s',(email,),)
        customer = cur.fetchone()

        try:
            password_matches = (
                customer is not None
                and isinstance(customer['Password'], str)
                and check_password_hash(customer['Password'], password)
            )
        except ValueError:
            password_matches = False

        if not password_matches:
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest' or request.is_json:
                return jsonify({'success': False, 'message': 'Invalid email or password.'}), 401
            return render_template('index.html', error='Invalid email or password.')

        session['user_id'] = customer['CustomerID']
        session['first_name'] = customer['FirstName']
        session['last_name'] = customer['LastName']

        if request.headers.get('X-Requested-With') == 'XMLHttpRequest' or request.is_json:
            return jsonify({
                'success': True,
                'message': 'Login successful.',
                'user': {'id': customer['CustomerID'],'first_name': customer['FirstName'],'last_name': customer['LastName'],},
            })

        return redirect(url_for('home'))

    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        first_name = (request.form.get('first') or '').strip()
        last_name = (request.form.get('last') or '').strip()
        email = (request.form.get('email') or '').strip().lower()
        password = request.form.get('password') or ''
        confirm_password = request.form.get('confirm_password') or ''

        if not first_name or not last_name:
            return render_template('register.html', error='First and last name are required.')
        if len(first_name) > 25 or len(last_name) > 25:
            return render_template('register.html', error='Names must be 25 characters or fewer.')
        if not EMAIL_PATTERN.fullmatch(email):
            return render_template('register.html', error='Please enter a valid email address.')
        if len(email) > 50:
            return render_template('register.html', error='Email must be 50 characters or fewer.')
        if len(password) < 12:
            return render_template('register.html', error='Password must be at least 12 characters long.')
        if len(password) > 128:
            return render_template('register.html', error='Password must be 128 characters or fewer.')
        if password != confirm_password:
            return render_template('register.html', error='Passwords do not match.')

        cur = mysql.connection.cursor()
        registration_lock = 'universal_power_washing_customer_registration'
        cur.execute('SELECT GET_LOCK(%s, 10) AS lock_acquired', (registration_lock,))
        if cur.fetchone()['lock_acquired'] != 1:
            return render_template('register.html',error='Registration is temporarily unavailable. Please try again.',), 503

        try:
            cur.execute('SELECT CustomerID FROM customer WHERE Email = %s', (email,))
            if cur.fetchone():
                return render_template('register.html', error='An account with that email already exists.')

            password_hash = generate_password_hash(password)
            cur.execute('SELECT COALESCE(MAX(CustomerID), 0) + 1 AS next_id FROM customer')
            customer_id = cur.fetchone()['next_id']
            cur.execute('''INSERT INTO customer (CustomerID, Password, Email, FirstName, LastName) VALUES (%s, %s, %s, %s, %s)''',
                (customer_id, password_hash, email, first_name, last_name),)
            mysql.connection.commit()
        finally:
            cur.execute('SELECT RELEASE_LOCK(%s)', (registration_lock,))

        session['user_id'] = customer_id
        session['first_name'] = first_name
        session['last_name'] = last_name

        return redirect(url_for('home'))

    return render_template('register.html')

@app.route('/profile')
def profile():
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("""SELECT * FROM Customer WHERE CustomerID = %s""", (session['user_id'],))

    customer = cursor.fetchone()
    cursor.close()

    return render_template('profile.html', customer=customer)

@app.route('/update_profile', methods=['POST'])
def update_profile():
    first_name = request.form.get('FirstName', '').strip()
    last_name = request.form.get('LastName', '').strip()
    email = request.form.get('Email', '').strip()
    phone = request.form.get('PhoneNumber', '').strip()
    address = request.form.get('Address', '').strip()
    city = request.form.get('City', '').strip()
    state = request.form.get('State', '').strip().upper()

    # Validate required fields
    if not first_name or not last_name or not email:
        flash('First name, last name, and email are required.')
        return redirect(url_for('profile'))

    if len(first_name) > 25 or len(last_name) > 25:
        flash('First and last names must be 25 characters or fewer.')
        return redirect(url_for('profile'))

    if len(email) > 50 or not re.fullmatch(r'[^@\s]+@[^@\s]+\.[^@\s]+', email):
        flash('Please enter a valid email address.')
        return redirect(url_for('profile'))

    if len(address) > 30 or len(city) > 25:
        flash('Address or city exceeds the allowed length.')
        return redirect(url_for('profile'))

    if state and not re.fullmatch(r'[A-Z]{2}', state):
        flash('State must be a two-letter abbreviation.')
        return redirect(url_for('profile'))

    # Your current PhoneNumber column is INT(11).
    # Accept digits only and allow an empty phone number.
    if phone and not re.fullmatch(r'\d{1,11}', phone):
        flash('Phone number must contain up to 11 digits.')
        return redirect(url_for('profile'))

    phone_number = int(phone) if phone else None

    cursor = mysql.connection.cursor()

    try:
        # Ensure the email isn't already used by another customer.
        cursor.execute("""SELECT CustomerID FROM Customer WHERE Email = %s AND CustomerID != %s""", (email, session['user_id']))

        if cursor.fetchone():
            flash('That email address is already in use.')
            return redirect(url_for('profile'))

        cursor.execute("""UPDATE Customer SET FirstName = %s,LastName = %s,Email = %s,PhoneNumber = %s,Address = %s,City = %s,State = %s WHERE CustomerID = %s""",
                       (first_name,last_name,email,phone_number,address or None,city or None,state or None,session['user_id']))

        mysql.connection.commit()
        flash('Your profile has been updated successfully.')

    except Exception:
        mysql.connection.rollback()
        app.logger.exception('Failed to update customer profile.')
        flash('Unable to update your profile. Please try again.')

    finally:
        cursor.close()

    return redirect(url_for('profile'))

@app.route('/change_password', methods=['POST'])
def change_password():
    current_password = request.form.get('current_password', '')
    new_password = request.form.get('new_password', '')
    confirm_password = request.form.get('confirm_password', '')

    if not current_password or not new_password or not confirm_password:
        flash('Please complete all password fields.')
        return redirect(url_for('profile'))

    if len(new_password) < 8:
        flash('Your new password must be at least 8 characters long.')
        return redirect(url_for('profile'))

    if new_password != confirm_password:
        flash('The new passwords do not match.')
        return redirect(url_for('profile'))

    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

    try:
        cursor.execute("""SELECT Password FROM Customer WHERE CustomerID = %s""", (session['user_id'],))

        customer = cursor.fetchone()

        if customer is None:
            session.clear()
            flash('Customer account not found.')
            return redirect(url_for('login'))

        stored_password = customer['Password']

        if not check_password_hash(stored_password, current_password):
            flash('Your current password is incorrect.')
            return redirect(url_for('profile'))

        hashed_password = generate_password_hash(new_password)

        cursor.execute("""UPDATE Customer SET Password = %s WHERE CustomerID = %s""", (hashed_password, session['user_id']))

        mysql.connection.commit()
        flash('Your password has been changed successfully.')

    except Exception:
        mysql.connection.rollback()
        app.logger.exception('Failed to change customer password.')
        flash('Unable to change your password. Please try again.')

    finally:
        cursor.close()

    return redirect(url_for('profile'))

@app.route('/logout', methods=['POST', 'GET'])
def logout():
    session.clear()
    flash('You have been logged out.')
    return redirect(url_for('home'))

if __name__ == '__main__':
    app.run()
