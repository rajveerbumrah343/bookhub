from flask import Flask, render_template, request, redirect, url_for, session, flash, abort
from config import Config
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from supabase import create_client
from flask_wtf.csrf import CSRFProtect, generate_csrf
import pymysql
import os
from datetime import datetime, timedelta
from functools import wraps

app = Flask(__name__)
app.config.from_object(Config)
app.permanent_session_lifetime = timedelta(minutes=30)
csrf = CSRFProtect(app)

app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024

# CSRF Token Injection
@app.context_processor
def inject_csrf():
    return dict(csrf_token=generate_csrf)

# Supabase configuration
SUPABASE_URL = "https://nblpwmdtfknblpzjnnja.supabase.co"
SUPABASE_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Im5ibHB3bWR0ZmtuYmxwempubmphIiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImlhdCI6MTc0NjEwOTc3NywiZXhwIjoyMDYxNjg1Nzc3fQ.IWSBIjPzwTu6lVhW0hAKSmbaJu1FEfvvlfE2jEqJXcI"

SUPABASE_BUCKET = "shaktimaan343"
supabase = create_client(SUPABASE_URL, SUPABASE_KEY)

# Database connection helper
def get_db_connection():
    return pymysql.connect(
        host=app.config['MYSQL_HOST'],
        user=app.config['MYSQL_USER'],
        password=app.config['MYSQL_PASSWORD'],
        database=app.config['MYSQL_DB'],
        cursorclass=pymysql.cursors.DictCursor
    )


def is_admin():
    if 'admin_id' in session:
        return True
    # Or check the database if you're using a different approach
    if 'user_id' in session:
        conn = get_db_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute("SELECT is_admin FROM users WHERE id = %s", (session['user_id'],))
                user = cursor.fetchone()
                return user and user['is_admin']
        finally:
            conn.close()
    return False




# Helper functions for both admin and user
def is_logged_in():
    return 'user_id' in session or 'admin_id' in session

def get_user_id():
    return session.get('user_id')

def admin_exists():
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT id FROM users WHERE is_admin=TRUE LIMIT 1")
            return cursor.fetchone() is not None
    finally:
        conn.close()

@app.context_processor
def inject_template_helpers():
    return dict(
        is_logged_in=is_logged_in,
        get_user_id=get_user_id,
        is_admin=is_admin,
        admin_exists=admin_exists,  
        csrf_token=generate_csrf
    )


# ==================== ADMIN ====================




def log_admin_action(action):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            # Get admin_id from either session['admin_id'] or session['user_id'] if is_admin
            admin_id = session.get('admin_id')
            if admin_id is None and 'user_id' in session:
                cursor.execute("SELECT id FROM users WHERE id = %s AND is_admin=TRUE", (session['user_id'],))
                if admin := cursor.fetchone():
                    admin_id = admin['id']
            
            if admin_id is None:
                return  # Skip logging if we can't determine admin
            
            cursor.execute(
                "INSERT INTO admin_logs (admin_id, action, timestamp) VALUES (%s, %s, NOW())",
                (admin_id, action)
            )
            conn.commit()
    finally:
        conn.close()

# Update your admin_required decorator
def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not is_admin():
            abort(403)  # Forbidden if not admin
        return f(*args, **kwargs)
    return decorated






@app.route('/admin/initial_setup', methods=['GET', 'POST'])
def admin_initial_setup():
    if admin_exists():  # Use our new helper function
        flash('Admin already exists', 'danger')
        return redirect(url_for('admin_login'))
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT id FROM users WHERE is_admin=TRUE LIMIT 1")
            if cursor.fetchone():
                flash('Admin already exists', 'danger')
                return redirect(url_for('admin_login'))
            if request.method == 'POST':
                username = request.form['username']
                email = request.form['email']
                password = request.form['password']
                hashed_pw = generate_password_hash(password)
                cursor.execute(
                    "INSERT INTO users (username, email, password_hash, is_admin) VALUES (%s,%s,%s,TRUE)",
                    (username, email, hashed_pw)
                )
                conn.commit()
                session['admin_id'] = cursor.lastrowid
                session['admin_username'] = username
                log_admin_action('INITIAL_ADMIN_CREATED')
                flash('Admin account created!', 'success')
                return redirect(url_for('admin_login'))
    finally:
        conn.close()
    return render_template('admin/initial_setup.html')

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if 'admin_id' in session:
        return redirect(url_for('admin_dashboard'))
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        conn = get_db_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute("SELECT id, username, password_hash FROM users WHERE email=%s AND is_admin=TRUE", (email,))
                admin = cursor.fetchone()
                if admin and check_password_hash(admin['password_hash'], password):
                    session.permanent = True
                    session['admin_id'] = admin['id']
                    session['admin_username'] = admin['username']
                    log_admin_action('ADMIN_LOGIN')
                    flash('Logged in successfully!', 'success')
                    return redirect(url_for('admin_dashboard'))
                flash('Invalid credentials', 'danger')
        finally:
            conn.close()
    return render_template('admin/login.html')

@app.route('/admin/logout')
@admin_required
def admin_logout():
    log_admin_action('ADMIN_LOGOUT')
    session.clear()
    flash('Logged out successfully', 'success')
    return redirect(url_for('admin_login'))

@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT * FROM books ORDER BY upload_date DESC")
            books = cursor.fetchall()
    finally:
        conn.close()
    return render_template('admin/dashboard.html', books=books, username=session.get('admin_username'))

@app.route('/admin/profile', methods=['GET', 'POST'])
@admin_required
def admin_profile():
    if request.method == 'POST':
        new_username = request.form.get('username')
        new_password = request.form.get('password')
        conn = get_db_connection()
        try:
            with conn.cursor() as cursor:
                updates = []
                params = []
                if new_username:
                    updates.append('username=%s')
                    params.append(new_username)
                if new_password:
                    hashed = generate_password_hash(new_password)
                    updates.append('password_hash=%s')
                    params.append(hashed)
                if updates:
                    params.append(session['admin_id'])
                    cursor.execute(f"UPDATE users SET {', '.join(updates)} WHERE id=%s", tuple(params))
                    conn.commit()
                    if new_username:
                        session['admin_username'] = new_username
                    log_admin_action('PROFILE_UPDATED')
                    flash('Profile updated', 'success')
                else:
                    flash('No changes made', 'info')
        finally:
            conn.close()
    return render_template('admin/profile.html', username=session.get('admin_username'))

@app.route('/admin/books/upload', methods=['GET', 'POST'])
@admin_required
def admin_upload_book():
    if request.method == 'POST':
        title = request.form['title']
        file = request.files['pdf_file']
        if file and file.filename.endswith('.pdf'):
            fname = secure_filename(f"{title}.pdf")
            data = file.read()
            supabase.storage.from_(SUPABASE_BUCKET).upload(fname,data,{"content-type": "application/pdf"})
            url = supabase.storage.from_(SUPABASE_BUCKET).get_public_url(fname)
            conn = get_db_connection()
            try:
                with conn.cursor() as cursor:
                    cursor.execute(
                        "INSERT INTO books (book_name,pdf_url,upload_date,uploaded_by,is_active) VALUES (%s,%s,NOW(),%s,TRUE)",
                        (title, url, session['admin_id'])
                    )
                    conn.commit()
                    log_admin_action(f'BOOK_UPLOADED:{fname}')
                    flash('Book uploaded', 'success')
                    return redirect(url_for('admin_dashboard'))
            finally:
                conn.close()
        flash('Invalid PDF file', 'danger')
    return render_template('admin/upload_book.html', username=session.get('admin_username'))

@app.route('/admin/books/<int:book_id>/remove', methods=['POST'])
@admin_required
def admin_remove_book(book_id):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            # Just remove the DB record
            cursor.execute("DELETE FROM books WHERE id=%s", (book_id,))
            conn.commit()

            log_admin_action(f'BOOK_REMOVED:{book_id}')
            flash('Book removed', 'success')
    finally:
        conn.close()
    return redirect(url_for('admin_dashboard'))


# ==================== USER ====================
@app.route('/')
def home():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('login.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        conn = get_db_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
                user = cursor.fetchone()
                if user and check_password_hash(user['password_hash'], password):
                    session['user_id'] = user['id']
                    session['username'] = user['username']
                    flash('You have successfully logged in!', 'success')
                    return redirect(url_for('dashboard'))
                flash('Invalid credentials', 'danger')
        finally:
            conn.close()
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        conn = get_db_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute("SELECT id FROM users WHERE email = %s", (email,))
                if cursor.fetchone():
                    flash('Email already registered', 'danger')
                    return render_template('signup.html')
                hashed_pw = generate_password_hash(password)
                cursor.execute(
                    "INSERT INTO users (username, email, password_hash) VALUES (%s, %s, %s)",
                    (username, email, hashed_pw)
                )
                conn.commit()
                flash('Registration successful! Please log in.', 'success')
                return redirect(url_for('login'))
        finally:
            conn.close()
    return render_template('signup.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user_id = session['user_id']
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("""
                SELECT b.id, b.book_name, b.upload_date, uba.expires_at 
                FROM user_book_access uba
                JOIN books b ON uba.book_id = b.id
                WHERE uba.user_id = %s AND uba.expires_at > NOW()
                ORDER BY uba.expires_at DESC
            """, (user_id,))
            accessible_books = cursor.fetchall()
            cursor.execute("SELECT * FROM books ORDER BY upload_date DESC")
            all_books = cursor.fetchall()
    finally:
        conn.close()
    return render_template('dashboard.html', 
                         accessible_books=accessible_books, 
                         all_books=all_books, 
                         username=session.get('username'))

@app.route('/books')
def books():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user_id = session['user_id']
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("""
                SELECT b.id, b.book_name, b.pdf_url, uba.expires_at
                FROM user_book_access uba
                JOIN books b ON uba.book_id = b.id
                WHERE uba.user_id = %s AND uba.expires_at > NOW()
                ORDER BY uba.expires_at DESC
            """, (user_id,))
            accessible_books = cursor.fetchall()
    finally:
        conn.close()

    return render_template('books.html', 
                           accessible_books=accessible_books,
                           username=session.get('username'))


@app.route('/view_book/<int:book_id>')
def view_book(book_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user_id = session['user_id']
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT * FROM books WHERE id = %s", (book_id,))
            book = cursor.fetchone()
            if not book:
                flash('Book not found', 'danger')
                return redirect(url_for('dashboard'))
            cursor.execute("""
                SELECT expires_at FROM user_book_access
                WHERE user_id = %s AND book_id = %s AND expires_at > NOW()
            """, (user_id, book_id))
            access = cursor.fetchone()
            if not access:
                flash('You do not have access to this book or access has expired', 'danger')
                return redirect(url_for('dashboard'))
            book['expires_at'] = access['expires_at']
    finally:
        conn.close()
    return render_template('view_book.html', book=book, username=session.get('username'))


@app.route('/books/<int:book_id>/access', methods=['POST'])
def access_book(book_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            # Check if already has access
            cursor.execute("SELECT * FROM user_book_access WHERE user_id=%s AND book_id=%s AND expires_at > NOW()", (user_id, book_id))
            if cursor.fetchone():
                flash("You already have access to this book.", "info")
            else:
                expires_at = datetime.utcnow() + timedelta(days=14)
                cursor.execute(
                    "INSERT INTO user_book_access (user_id, book_id, granted_at, expires_at) VALUES (%s, %s, NOW(), %s)",
                    (user_id, book_id, expires_at)
                )
                conn.commit()
                flash("Access granted for 14 days!", "success")
    finally:
        conn.close()

    return redirect(url_for('dashboard'))


if __name__ == '__main__':
    app.run(debug=True)