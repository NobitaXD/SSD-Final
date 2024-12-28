import re
import sqlite3
import contextlib
from datetime import timedelta

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from flask import (
    Flask, render_template, 
    request, session, redirect
)
from flask_talisman import Talisman
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import logging

from create_database import setup_database
from utils import login_required, set_session

app = Flask(__name__)

# App Configuration
app.config['SECRET_KEY'] = 'EXAMPLE_xpSm7p5bgJY8rNoBjGWiz5yjxMNlW6231IBI62OkLc='
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=15)

# Security Middleware
talisman = Talisman()
limiter = Limiter(get_remote_address, app=app)
talisman.init_app(app)

# Logging Configuration
logging.basicConfig(level=logging.INFO, filename="security.log", 
                    format="%(asctime)s - %(levelname)s - %(message)s")

# Content Security Policy (CSP)
csp = {
    'default-src': '\'self\'',
    'script-src': ['\'self\''],
    'style-src': ['\'self\'', 'https://fonts.googleapis.com'],
    'font-src': ['\'self\'', 'https://fonts.gstatic.com']
}
talisman.content_security_policy = csp

# Database Setup
setup_database(name='users.db')


@app.route('/')
@login_required
def index():
    logging.info(f"User data accessed: {session}")
    return render_template('index.html', username=session.get('username'))


@app.route('/logout')
def logout():
    logging.info(f"User logged out: {session.get('username')}")
    session.clear()
    session.permanent = False
    return redirect('/login')


@limiter.limit("5 per minute", methods=["POST"])
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html')

    username = request.form.get('username')
    password = request.form.get('password')
    
    # Attempt to query associated user data
    query = 'select username, password, email from users where username = :username;'

    with contextlib.closing(sqlite3.connect('users.db')) as conn:
        with conn:
            account = conn.execute(query, {'username': username}).fetchone()

    if not account:
        logging.warning(f"Failed login attempt for non-existent username: {username}")
        return render_template('login.html', error='Username does not exist')

    # Verify password
    try:
        ph = PasswordHasher()
        ph.verify(account[1], password)
    except VerifyMismatchError:
        logging.warning(f"Incorrect password attempt for username: {username}")
        return render_template('login.html', error='Incorrect password')

    # Check if password hash needs to be updated
    if ph.check_needs_rehash(account[1]):
        query = 'update set password = :password where username = :username;'
        params = {'password': ph.hash(password), 'username': account[0]}
        with contextlib.closing(sqlite3.connect('users.db')) as conn:
            with conn:
                conn.execute(query, params)

    # Set session cookie for user
    set_session(username=account[0], remember_me='remember-me' in request.form)
    logging.info(f"Successful login for username: {username}")
    return redirect('/')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'GET':
        return render_template('register.html')
    
    # Store data to variables
    password = request.form.get('password')
    confirm_password = request.form.get('confirm-password')
    username = request.form.get('username')
    email = request.form.get('email')

    # Verify data
    if len(password) < 8:
        return render_template('register.html', error='Your password must be 8 or more characters')
    if password != confirm_password:
        return render_template('register.html', error='Passwords do not match')
    if not re.match(r'^[a-zA-Z0-9]+$', username):
        return render_template('register.html', error='Username must only be letters and numbers')
    if not 3 < len(username) < 26:
        return render_template('register.html', error='Username must be between 4 and 25 characters')

    query = 'select username from users where username = :username;'
    with contextlib.closing(sqlite3.connect('users.db')) as conn:
        with conn:
            result = conn.execute(query, {'username': username}).fetchone()
    if result:
        return render_template('register.html', error='Username already exists')

    # Create password hash
    ph = PasswordHasher()
    hashed_password = ph.hash(password)

    query = 'insert into users(username, password, email) values (:username, :password, :email);'
    params = {
        'username': username,
        'password': hashed_password,
        'email': email
    }

    with contextlib.closing(sqlite3.connect('users.db')) as conn:
        with conn:
            conn.execute(query, params)

    # Log the user in right away since no email verification
    set_session(username=username)
    logging.info(f"New user registered: {username}")
    return redirect('/')


@app.errorhandler(429)
def rate_limit_error(e):
    return "Too many requests. Please try again later.", 429


if __name__ == '__main__':
    app.run(debug=True)