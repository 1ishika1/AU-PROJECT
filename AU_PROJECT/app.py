import os
import base64
from email.mime.text import MIMEText
from flask import Flask, render_template, request, flash, redirect, url_for, jsonify
from flask_mysqldb import MySQL
from flask_cors import CORS
import mysql.connector
from dotenv import load_dotenv
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from itsdangerous import URLSafeTimedSerializer
from werkzeug.security import generate_password_hash, check_password_hash

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY")

# MySQL Config
app.config['MYSQL_HOST'] = os.getenv('MYSQL_HOST')
app.config['MYSQL_USER'] = os.getenv('MYSQL_USER')
app.config['MYSQL_PASSWORD'] = os.getenv('MYSQL_PASSWORD')
app.config['MYSQL_DB'] = os.getenv('MYSQL_DB')

mysql = MySQL(app)

# Gmail API SCOPES
SCOPES = ['https://www.googleapis.com/auth/gmail.send']

# Token serializer for secure URL generation
serializer = URLSafeTimedSerializer(app.secret_key)

def get_gmail_service():
    creds = None

    if os.path.exists('token.json'):
        creds = Credentials.from_authorized_user_file('token.json', SCOPES)

    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file('credentials.json', SCOPES)
            creds = flow.run_local_server(port=0)
        with open('token.json', 'w') as token:
            token.write(creds.to_json())

    return build('gmail', 'v1', credentials=creds)

def send_email(to, subject, message_text):
    service = get_gmail_service()
    message = MIMEText(message_text)
    message['to'] = to
    message['subject'] = subject
    raw = base64.urlsafe_b64encode(message.as_bytes()).decode()
    body = {'raw': raw}
    return service.users().messages().send(userId='me', body=body).execute()

@app.route('/')
def login_page():
    return render_template('login.html')

@app.route('/test_db')
def test_db():
    try:
        cur = mysql.connection.cursor()
        cur.execute("SELECT 1")
        result = cur.fetchone()
        cur.close()
        return f"Database Connected: {result}"
    except Exception as e:
        return f"Database connection failed: {e}"

@app.route('/test_email')
def test_email():
    try:
        send_email(
            to='your_email@gmail.com',
            subject='Test Email',
            message_text='This is a test.'
        )
        return "Email sent"
    except Exception as e:
        return f"Email failed: {e}"

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('user_id')
    password = request.form.get('password')
    cursor = mysql.connection.cursor()
    cursor.execute("SELECT * FROM users WHERE user_id = %s", (username))
    user = cursor.fetchone()
    cursor.close()
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
        cur = mysql.connection.cursor()
        cur.execute("SELECT * FROM users WHERE user_id=%s AND email=%s", (user_id, email))
        user = cur.fetchone()
        cur.close()
        if user:
            try:
                token = serializer.dumps(user_id, salt='first-time-login')
                setup_link = url_for('set_password', token=token, _external=True)
                send_email(
                    to=email,
                    subject='Set Your Password - First Time Login',
                    message_text=f"Hi {user_id},\n\nClick the link below to set your password:\n{setup_link}"
                )
                flash('Password setup link sent to your registered email.', 'success')
            except Exception as e:
                flash(f'Failed to send email: {str(e)}', 'error')
        else:
            flash('Invalid User ID or Email.', 'error')
        return redirect(url_for('first_time_login'))
    return render_template('first_time_login.html')

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        user_id = request.form.get('user_id')
        email = request.form.get('email')
        cur = mysql.connection.cursor()
        cur.execute("SELECT * FROM users WHERE user_id=%s AND email=%s", (user_id, email))
        user = cur.fetchone()
        cur.close()
        if user:
            try:
                token = serializer.dumps(user_id, salt='password-reset')
                reset_link = url_for('reset_password', token=token, _external=True)
                send_email(
                    to=email,
                    subject='Password Reset Link',
                    message_text=f"Hi,\n\nClick the link below to reset your password:\n{reset_link}"
                )
                flash('Reset link sent to your email.', 'success')
            except Exception as e:
                flash(f'Failed to send email: {str(e)}', 'error')
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
        cur = mysql.connection.cursor()
        cur.execute("UPDATE users SET password=%s WHERE user_id=%s", (hashed_password, user_id))
        mysql.connection.commit()
        cur.close()
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
        cur = mysql.connection.cursor()
        cur.execute("UPDATE users SET password=%s WHERE user_id=%s", (hashed_password, user_id))
        mysql.connection.commit()
        cur.close()
        flash('Password set successfully. You can now login.', 'success')
        return redirect(url_for('login_page'))

    return render_template('set_password_form.html', user_id=user_id)

@app.route('/account_level')
def account_level_page():
    return render_template('account_level.html')


# NEW API: fetch account details by account_number or mobile_number
@app.route('/api/accounts', methods=['GET'])
def get_account_details_api():
    account_number = request.args.get('account_number')
    mobile_number = request.args.get('mobile_number')

    if not account_number and not mobile_number:
        return jsonify({'status': 'error', 'message': 'Please provide account_number or mobile_number as query parameter'}), 400

    cur = mysql.connection.cursor()
    query = "SELECT id, name, account_number, mobile_number, status, alerts_sent, created_at FROM accounts WHERE "
    params = []

    if account_number and mobile_number:
        query += "account_number = %s OR mobile_number = %s"
        params = [account_number, mobile_number]
    elif account_number:
        query += "account_number = %s"
        params = [account_number]
    else:
        query += "mobile_number = %s"
        params = [mobile_number]

    cur.execute(query, params)
    account = cur.fetchone()
    cur.close()

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
