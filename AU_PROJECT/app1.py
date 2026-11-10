import os
from flask import Flask, render_template, request, flash, redirect, url_for, jsonify
import oracledb
from flask_cors import CORS
from dotenv import load_dotenv
from itsdangerous import URLSafeTimedSerializer
from werkzeug.security import generate_password_hash, check_password_hash

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY")
CORS(app)

# Oracle DB Config
oracle_user = os.getenv("ORACLE_USER")
oracle_password = os.getenv("ORACLE_PASSWORD")
oracle_dsn = os.getenv("ORACLE_DSN")

def get_oracle_connection():
    return oracledb.connect(user=oracle_user, password=oracle_password, dsn=oracle_dsn)

# Token serializer for secure URL generation
serializer = URLSafeTimedSerializer(app.secret_key)

@app.route('/')
def login_page():
    return render_template('login.html')

@app.route('/test_db')
def test_db():
    try:
        with get_oracle_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT 1 FROM DUAL")
                result = cur.fetchone()
        return f"Database Connected: {result}"
    except Exception as e:
        return f"Database connection failed: {e}"

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('user_id')
    password = request.form.get('password')
    with get_oracle_connection() as conn:
        with conn.cursor() as cursor:
            cursor.execute("SELECT * FROM users WHERE user_id = :1", [username])
            user = cursor.fetchone()
    if user and check_password_hash(user[3], password):
        return {'status': 'success'}
    else:
        return {'status': 'error', 'message': 'Invalid username or password'}

@app.route('/front')
def front_page():
    return render_template('frontpage.html')

@app.route('/first_time_login', methods=['GET', 'POST'])
def first_time_login():
    if request.method == 'POST':
        user_id = request.form.get('user_id')
        email = request.form.get('email')
        with get_oracle_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT * FROM users WHERE user_id=:1 AND email=:2", (user_id, email))
                user = cur.fetchone()
        if user:
            flash('User verified. Email functionality has been removed.', 'success')
        else:
            flash('Invalid User ID or Email.', 'error')
        return redirect(url_for('first_time_login'))
    return render_template('first_time_login.html')

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        user_id = request.form.get('user_id')
        email = request.form.get('email')
        with get_oracle_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT * FROM users WHERE user_id=:1 AND email=:2", (user_id, email))
                user = cur.fetchone()
        if user:
            flash('User verified. Email functionality has been removed.', 'success')
        else:
            flash('Invalid User ID or Email.', 'error')
    return render_template('forgot_password.html')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        user_id = serializer.loads(token, salt='password-reset', max_age=3600)
    except Exception:
        return "Invalid or expired token", 403

    if request.method == 'POST':
        new_password = request.form.get('new_password')
        hashed_password = generate_password_hash(new_password)
        with get_oracle_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("UPDATE users SET password=:1 WHERE user_id=:2", (hashed_password, user_id))
                conn.commit()
        flash('Password updated successfully.', 'success')
        return redirect(url_for('login_page'))

    return render_template('reset_password_form.html', user_id=user_id)

@app.route('/set_password/<token>', methods=['GET', 'POST'])
def set_password(token):
    try:
        user_id = serializer.loads(token, salt='first-time-login', max_age=3600)
    except Exception:
        return "Invalid or expired token", 403

    if request.method == 'POST':
        new_password = request.form.get('new_password')
        hashed_password = generate_password_hash(new_password)
        with get_oracle_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("UPDATE users SET password=:1 WHERE user_id=:2", (hashed_password, user_id))
                conn.commit()
        flash('Password set successfully. You can now login.', 'success')
        return redirect(url_for('login_page'))

    return render_template('set_password_form.html', user_id=user_id)

@app.route('/account_level')
def account_level_page():
    return render_template('account_level.html')

@app.route('/api/accounts', methods=['GET'])
def get_account_details_api():
    account_number = request.args.get('account_number')
    mobile_number = request.args.get('mobile_number')

    if not account_number and not mobile_number:
        return jsonify({'status': 'error', 'message': 'Please provide account_number or mobile_number as query parameter'}), 400

    with get_oracle_connection() as conn:
        with conn.cursor() as cur:
            query = "SELECT id, name, account_number, mobile_number, status, alerts_sent, created_at FROM accounts WHERE "
            params = []
            if account_number and mobile_number:
                query += "account_number = :1 OR mobile_number = :2"
                params = [account_number, mobile_number]
            elif account_number:
                query += "account_number = :1"
                params = [account_number]
            else:
                query += "mobile_number = :1"
                params = [mobile_number]

            cur.execute(query, params)
            account = cur.fetchone()

    if account:
        account_data = {
            'id': account[0],
            'name': account[1],
            'account_number': account[2],
            'mobile_number': account[3],
            'status': account[4],
            'alerts_sent': account[5],
            'created_at': str(account[6])
        }
        return jsonify({'status': 'success', 'account': account_data})
    else:
        return jsonify({'status': 'error', 'message': 'Account not found'}), 404

if __name__ == '__main__':
    app.run(debug=True)