from flask import Flask, request, jsonify, session, render_template, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt
from datetime import datetime
import mysql.connector
from mysql.connector import Error
import os
from dotenv import load_dotenv
import re
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import random

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your-secret-key-here')

# Initialize extensions
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login_page'

# Database connection function
def get_db_connection():
    """Get a database connection."""
    try:
        conn = mysql.connector.connect(
            host=os.getenv('DB_HOST', 'localhost'),
            user=os.getenv('DB_USER', 'root'),
            password=os.getenv('DB_PASSWORD', '1234'),
            database=os.getenv('DB_NAME', 'bank_db')
        )
        return conn
    except mysql.connector.Error as err:
        print(f"Database connection error: {err}")
        return None

# AES Encryption setup
def get_encryption_key():
    key = os.getenv('ENCRYPTION_KEY').encode()
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # AES-256 requires 32 bytes
        salt=b'salt_',
        iterations=100000,
    )
    return kdf.derive(key)

def encrypt_data(data):
    """Encrypt sensitive data using AES encryption."""
    if data is None:
        return None
    try:
        # Generate a random IV
        iv = get_random_bytes(16)
        # Create cipher object
        cipher = AES.new(get_encryption_key(), AES.MODE_CBC, iv)
        # Pad the data to be a multiple of 16 bytes
        padded_data = pad(data.encode(), AES.block_size)
        # Encrypt the data
        encrypted_data = cipher.encrypt(padded_data)
        # Combine IV and encrypted data
        combined = iv + encrypted_data
        # Return base64 encoded result
        return base64.b64encode(combined).decode('utf-8')
    except Exception as e:
        print(f"Encryption error: {str(e)}")
        return None

def decrypt_data(encrypted_data):
    """Decrypt sensitive data using AES decryption."""
    if encrypted_data is None:
        return None
    try:
        # Decode base64 data
        combined = base64.b64decode(encrypted_data)
        # Extract IV and encrypted data
        iv = combined[:16]
        encrypted_data = combined[16:]
        # Create cipher object
        cipher = AES.new(get_encryption_key(), AES.MODE_CBC, iv)
        # Decrypt the data
        decrypted_data = cipher.decrypt(encrypted_data)
        # Unpad the data
        unpadded_data = unpad(decrypted_data, AES.block_size)
        # Return decoded result
        return unpadded_data.decode('utf-8')
    except Exception as e:
        print(f"Decryption error: {str(e)}")
        return None

# User class
class User(UserMixin):
    def __init__(self, user_data):
        self.id = user_data[0]
        self.username = user_data[1]
        self.email = decrypt_data(user_data[2])
        self.account_id = decrypt_data(user_data[4])
        self.balance = float(user_data[5])

@login_manager.user_loader
def load_user(user_id):
    connection = get_db_connection()
    if connection:
        try:
            cursor = connection.cursor()
            cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
            user_data = cursor.fetchone()
            if user_data:
                return User(user_data)
        finally:
            cursor.close()
            connection.close()
    return None

def validate_email(email):
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

# Template Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login')
def login_page():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('login.html')

@app.route('/register')
def register_page():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('register.html')

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')

# API Routes
@app.route('/api/register', methods=['POST'])
def api_register():
    data = request.get_json()
    
    if not all(key in data for key in ['username', 'email', 'password']):
        return jsonify({'error': 'Missing required fields'}), 400
    
    if not validate_email(data['email']):
        return jsonify({'error': 'Invalid email format'}), 400
    
    connection = get_db_connection()
    if not connection:
        return jsonify({'error': 'Database connection error'}), 500
    
    try:
        cursor = connection.cursor()
        
        # Check if username exists
        cursor.execute("SELECT id FROM users WHERE username = %s", (data['username'],))
        if cursor.fetchone():
            return jsonify({'error': 'Username already exists'}), 400
        
        # Check if email exists
        encrypted_email = encrypt_data(data['email'])
        cursor.execute("SELECT id FROM users WHERE email = %s", (encrypted_email,))
        if cursor.fetchone():
            return jsonify({'error': 'Email already registered'}), 400
        
        # Generate account ID and hash password
        account_id = f"ACC{datetime.now().strftime('%Y%m%d%H%M%S')}"
        hashed_password = bcrypt.generate_password_hash(data['password']).decode('utf-8')
        encrypted_account_id = encrypt_data(account_id)
        
        # Insert new user
        cursor.execute("""
            INSERT INTO users (username, email, password_hash, account_id, balance)
            VALUES (%s, %s, %s, %s, %s)
        """, (data['username'], encrypted_email, hashed_password, encrypted_account_id, 0.0))
        
        connection.commit()
        return jsonify({
            'message': 'Registration successful',
            'account_id': account_id
        }), 201
        
    except Error as e:
        return jsonify({'error': str(e)}), 500
    finally:
        cursor.close()
        connection.close()

@app.route('/api/login', methods=['POST'])
def api_login():
    data = request.get_json()
    
    if not all(key in data for key in ['username', 'password']):
        return jsonify({'error': 'Missing required fields'}), 400
    
    connection = get_db_connection()
    if not connection:
        return jsonify({'error': 'Database connection error'}), 500
    
    try:
        cursor = connection.cursor()
        cursor.execute("SELECT * FROM users WHERE username = %s", (data['username'],))
        user_data = cursor.fetchone()
        
        if user_data and bcrypt.check_password_hash(user_data[3], data['password']):
            user = User(user_data)
            login_user(user)
            return jsonify({'message': 'Login successful'}), 200
        
        return jsonify({'error': 'Invalid username or password'}), 401
    finally:
        cursor.close()
        connection.close()

@app.route('/api/balance', methods=['GET'])
@login_required
def api_balance():
    connection = get_db_connection()
    if not connection:
        return jsonify({'error': 'Database connection error'}), 500
    
    try:
        cursor = connection.cursor()
        cursor.execute("SELECT account_id, balance FROM users WHERE id = %s", (current_user.id,))
        encrypted_account_id, balance = cursor.fetchone()
        
        return jsonify({
            'account_id': decrypt_data(encrypted_account_id),
            'balance': float(balance)
        }), 200
    finally:
        cursor.close()
        connection.close()

@app.route('/api/statement', methods=['GET'])
@login_required
def api_statement():
    connection = get_db_connection()
    if not connection:
        return jsonify({'error': 'Database connection error'}), 500
    
    try:
        cursor = connection.cursor()
        cursor.execute("""
            SELECT transaction_type, amount, balance_after, timestamp
            FROM transactions
            WHERE user_id = %s
            ORDER BY timestamp DESC
        """, (current_user.id,))
        
        transactions = [{
            'transaction_type': decrypt_data(t[0]),
            'amount': float(t[1]),
            'balance_after': float(t[2]),
            'timestamp': t[3].strftime('%Y-%m-%d %H:%M:%S')
        } for t in cursor.fetchall()]
        
        return jsonify({
            'transactions': transactions
        }), 200
    finally:
        cursor.close()
        connection.close()

@app.route('/api/deposit', methods=['POST'])
@login_required
def api_deposit():
    data = request.get_json()
    
    if 'amount' not in data:
        return jsonify({'error': 'Amount is required'}), 400
    
    try:
        amount = float(data['amount'])
        if amount <= 0:
            return jsonify({'error': 'Amount must be positive'}), 400
        
        connection = get_db_connection()
        if not connection:
            return jsonify({'error': 'Database connection error'}), 500
        
        try:
            cursor = connection.cursor()
            
            # Update user balance
            cursor.execute("""
                UPDATE users SET balance = balance + %s WHERE id = %s
            """, (amount, current_user.id))
            
            # Get new balance
            cursor.execute("SELECT balance FROM users WHERE id = %s", (current_user.id,))
            new_balance = cursor.fetchone()[0]
            
            # Record transaction
            cursor.execute("""
                INSERT INTO transactions (user_id, transaction_type, amount, balance_after)
                VALUES (%s, %s, %s, %s)
            """, (current_user.id, encrypt_data('deposit'), amount, new_balance))
            
            connection.commit()
            
            return jsonify({
                'message': 'Deposit successful',
                'new_balance': float(new_balance)
            }), 200
            
        finally:
            cursor.close()
            connection.close()
            
    except ValueError:
        return jsonify({'error': 'Invalid amount format'}), 400

@app.route('/api/withdraw', methods=['POST'])
@login_required
def api_withdraw():
    data = request.get_json()
    
    if 'amount' not in data:
        return jsonify({'error': 'Amount is required'}), 400
    
    try:
        amount = float(data['amount'])
        if amount <= 0:
            return jsonify({'error': 'Amount must be positive'}), 400
        
        connection = get_db_connection()
        if not connection:
            return jsonify({'error': 'Database connection error'}), 500
        
        try:
            cursor = connection.cursor()
            
            # Check balance
            cursor.execute("SELECT balance FROM users WHERE id = %s", (current_user.id,))
            current_balance = cursor.fetchone()[0]
            
            if amount > float(current_balance):
                return jsonify({'error': 'Insufficient funds'}), 400
            
            # Update user balance
            cursor.execute("""
                UPDATE users SET balance = balance - %s WHERE id = %s
            """, (amount, current_user.id))
            
            # Get new balance
            cursor.execute("SELECT balance FROM users WHERE id = %s", (current_user.id,))
            new_balance = cursor.fetchone()[0]
            
            # Record transaction
            cursor.execute("""
                INSERT INTO transactions (user_id, transaction_type, amount, balance_after)
                VALUES (%s, %s, %s, %s)
            """, (current_user.id, encrypt_data('withdrawal'), amount, new_balance))
            
            connection.commit()
            
            return jsonify({
                'message': 'Withdrawal successful',
                'new_balance': float(new_balance)
            }), 200
            
        finally:
            cursor.close()
            connection.close()
            
    except ValueError:
        return jsonify({'error': 'Invalid amount format'}), 400

@app.route('/api/logout', methods=['POST'])
@login_required
def api_logout():
    logout_user()
    return jsonify({'message': 'Logout successful'}), 200

def create_user(username, email, password):
    """Create a new user with encrypted data."""
    try:
        conn = get_db_connection()
        if not conn:
            return None

        cursor = conn.cursor()
        
        # Generate account ID
        account_id = generate_account_id()
        
        # Encrypt sensitive data
        encrypted_email = encrypt_data(email)
        encrypted_account_id = encrypt_data(account_id)
        
        # Hash password
        password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
        
        # Insert user
        cursor.execute('''
            INSERT INTO users (username, email, password_hash, account_id, balance)
            VALUES (%s, %s, %s, %s, %s)
        ''', (username, encrypted_email, password_hash, encrypted_account_id, 0.00))
        
        user_id = cursor.lastrowid
        conn.commit()
        
        return {
            'id': user_id,
            'username': username,
            'email': email,
            'account_id': account_id,
            'balance': 0.00
        }
    except mysql.connector.Error as err:
        print(f"Error creating user: {err}")
        return None
    finally:
        if 'conn' in locals():
            conn.close()

def get_user_by_username(username):
    """Get user by username with decrypted data."""
    try:
        conn = get_db_connection()
        if not conn:
            return None

        cursor = conn.cursor(dictionary=True)
        cursor.execute('SELECT * FROM users WHERE username = %s', (username,))
        user = cursor.fetchone()
        
        if user:
            # Decrypt sensitive data
            user['email'] = decrypt_data(user['email'])
            user['account_id'] = decrypt_data(user['account_id'])
        
        return user
    except mysql.connector.Error as err:
        print(f"Error getting user: {err}")
        return None
    finally:
        if 'conn' in locals():
            conn.close()

def get_user_by_id(user_id):
    """Get user by ID with decrypted data."""
    try:
        conn = get_db_connection()
        if not conn:
            return None

        cursor = conn.cursor(dictionary=True)
        cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))
        user = cursor.fetchone()
        
        if user:
            # Decrypt sensitive data
            user['email'] = decrypt_data(user['email'])
            user['account_id'] = decrypt_data(user['account_id'])
        
        return user
    except mysql.connector.Error as err:
        print(f"Error getting user: {err}")
        return None
    finally:
        if 'conn' in locals():
            conn.close()

def create_transaction(user_id, transaction_type, amount, balance_after):
    """Create a new transaction with encrypted data."""
    try:
        conn = get_db_connection()
        if not conn:
            return None

        cursor = conn.cursor()
        
        # Encrypt transaction type
        encrypted_type = encrypt_data(transaction_type)
        
        # Insert transaction
        cursor.execute('''
            INSERT INTO transactions (user_id, transaction_type, amount, balance_after)
            VALUES (%s, %s, %s, %s)
        ''', (user_id, encrypted_type, amount, balance_after))
        
        transaction_id = cursor.lastrowid
        conn.commit()
        
        return {
            'id': transaction_id,
            'user_id': user_id,
            'transaction_type': transaction_type,
            'amount': amount,
            'balance_after': balance_after,
            'timestamp': datetime.now()
        }
    except mysql.connector.Error as err:
        print(f"Error creating transaction: {err}")
        return None
    finally:
        if 'conn' in locals():
            conn.close()

def get_transactions(user_id):
    """Get user's transactions with decrypted data."""
    try:
        conn = get_db_connection()
        if not conn:
            return []

        cursor = conn.cursor(dictionary=True)
        cursor.execute('''
            SELECT * FROM transactions 
            WHERE user_id = %s 
            ORDER BY timestamp DESC
        ''', (user_id,))
        
        transactions = cursor.fetchall()
        
        # Decrypt transaction types
        for transaction in transactions:
            transaction['transaction_type'] = decrypt_data(transaction['transaction_type'])
        
        return transactions
    except mysql.connector.Error as err:
        print(f"Error getting transactions: {err}")
        return []
    finally:
        if 'conn' in locals():
            conn.close()

def generate_account_id():
    """Generate a unique account ID using timestamp and random number."""
    timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
    random_num = ''.join([str(random.randint(0, 9)) for _ in range(4)])
    return f'ACC{timestamp}{random_num}'

if __name__ == '__main__':
    app.run(debug=True)
