from flask import Flask, render_template, request, redirect, url_for, session, jsonify
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
        cur.execute(
            'SELECT CustomerID, FirstName, LastName, Password FROM customer WHERE Email = %s',
            (email,),
        )
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
                'user': {
                    'id': customer['CustomerID'],
                    'first_name': customer['FirstName'],
                    'last_name': customer['LastName'],
                },
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
            return render_template(
                'register.html',
                error='Registration is temporarily unavailable. Please try again.',
            ), 503

        try:
            cur.execute('SELECT CustomerID FROM customer WHERE Email = %s', (email,))
            if cur.fetchone():
                return render_template('register.html', error='An account with that email already exists.')

            password_hash = generate_password_hash(password)
            cur.execute('SELECT COALESCE(MAX(CustomerID), 0) + 1 AS next_id FROM customer')
            customer_id = cur.fetchone()['next_id']
            cur.execute(
                '''
                INSERT INTO customer (CustomerID, Password, Email, FirstName, LastName)
                VALUES (%s, %s, %s, %s, %s)
                ''',
                (customer_id, password_hash, email, first_name, last_name),
            )
            mysql.connection.commit()
        finally:
            cur.execute('SELECT RELEASE_LOCK(%s)', (registration_lock,))

        session['user_id'] = customer_id
        session['first_name'] = first_name
        session['last_name'] = last_name

        return redirect(url_for('home'))

    return render_template('register.html')


@app.route('/logout', methods=['POST', 'GET'])
def logout():
    session.clear()
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest' or request.is_json:
        return jsonify({'success': True, 'message': 'Logged out successfully.'})
    return redirect(url_for('home'))


if __name__ == '__main__':
    app.run()
