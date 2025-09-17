#!/usr/bin/env python3
import flask
import sqlite3
import hashlib
import uuid
import os
import re
import datetime
import smtplib
import socket
import email
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication
from flask import Flask, request, render_template, jsonify, session, redirect, url_for, send_file
from io import BytesIO
import threading
import time

app = Flask(__name__)
app.secret_key = 'odq-mail-secret-key-2024'
notifications = []

import base64
import quopri
import re


# Конфигурация сервера
SERVER_CONFIG = {
    'MAIL_SERVER_HOST': 'localhost',
    'SMTP_PORT': 25,
    'IMAP_PORT': 143,
    'DATABASE_FILE': 'mail_server.db',
    'WEB_HOST': '0.0.0.0',
    'WEB_PORT': 5000,
    'DEBUG': True,
    'PAGE_SIZES': [10, 20, 50, 100],
    'DEFAULT_PAGE_SIZE': 20,
    'SMTP_TIMEOUT': 30,
    'DB_TIMEOUT': 10,
    'CHECK_NEW_MAIL_MINUTES': 5,  # Проверка новых писем каждые 5 минут
}


def decode_email_content(content):
    """Декодирует содержимое email из MIME формата"""
    try:
        # Если это plain text, возвращаем как есть
        if not content.startswith('Content-Type:'):
            return content
        
        # Ищем текстовую часть
        text_match = re.search(r'Content-Type: text/plain.*?Content-Transfer-Encoding: base64\r\n\r\n(.*?)\r\n--', content, re.DOTALL | re.IGNORECASE)
        if text_match:
            encoded_text = text_match.group(1).strip()
            try:
                decoded_bytes = base64.b64decode(encoded_text)
                return decoded_bytes.decode('utf-8', errors='ignore')
            except:
                pass
        
        # Пробуем найти другую кодировку
        quoted_match = re.search(r'Content-Transfer-Encoding: quoted-printable.*?\r\n\r\n(.*?)\r\n--', content, re.DOTALL | re.IGNORECASE)
        if quoted_match:
            encoded_text = quoted_match.group(1).strip()
            try:
                decoded_bytes = quopri.decodestring(encoded_text)
                return decoded_bytes.decode('utf-8', errors='ignore')
            except:
                pass
        
        # Если не нашли закодированный контент, возвращаем как есть
        return content
        
    except Exception as e:
        print(f"Ошибка декодирования письма: {e}")
        return content


def get_db_connection():
    conn = sqlite3.connect(SERVER_CONFIG['DATABASE_FILE'])
    conn.row_factory = sqlite3.Row
    return conn
def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        salt TEXT NOT NULL,
        name TEXT NOT NULL,
        phone TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    ''')
    
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS emails (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        uuid TEXT UNIQUE NOT NULL,
        from_email TEXT NOT NULL,
        to_email TEXT NOT NULL,
        subject TEXT NOT NULL,
        body TEXT NOT NULL,
        size INTEGER NOT NULL,
        folder TEXT NOT NULL,
        is_read BOOLEAN DEFAULT 0,
        received_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        user_id INTEGER,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )
    ''')
    
    # Создаем индексы для улучшения производительности
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_emails_user_folder ON emails (user_id, folder)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_emails_received ON emails (received_at)')
    
    # Создаем тестового пользователя если нет
    cursor.execute('SELECT * FROM users WHERE email = ?', ('admin@oditynet.ru',))
    if not cursor.fetchone():
        import secrets
        import string
        salt = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(16))
        password_hash = hashlib.sha256((salt + 'admin123').encode()).hexdigest()
        
        cursor.execute('''
        INSERT INTO users (email, password_hash, salt, name, phone)
        VALUES (?, ?, ?, ?, ?)
        ''', ('admin@oditynet.ru', password_hash, salt, 'Administrator', '+1234567890'))
    
    conn.commit()
    conn.close()

def hash_password(password, salt):
    return hashlib.sha256((salt + password).encode()).hexdigest()

def send_email_via_smtp(from_email, to_emails, subject, body, attachments=None):
    """Отправка письма через SMTP"""
    try:
        msg = MIMEMultipart()
        msg['From'] = from_email
        msg['To'] = ', '.join(to_emails) if isinstance(to_emails, list) else to_emails
        msg['Subject'] = subject
        msg['Date'] = email.utils.formatdate(localtime=True)
        msg['Message-ID'] = email.utils.make_msgid()
        
        msg.attach(MIMEText(body, 'plain', 'utf-8'))
        
        with smtplib.SMTP(
            host=SERVER_CONFIG['MAIL_SERVER_HOST'],
            port=SERVER_CONFIG['SMTP_PORT'],
            timeout=SERVER_CONFIG['SMTP_TIMEOUT']
        ) as server:
            server.sendmail(from_email, to_emails, msg.as_string())
            
        return True, "Письмо успешно отправлено"
        
    except Exception as e:
        return False, f"Ошибка отправки: {str(e)}"

def get_emails_from_db(folder='INBOX', page=1, page_size=20, user_email=None):
    """Получение писем из базы данных"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Получаем user_id по email
        cursor.execute('SELECT id FROM users WHERE email = ?', (user_email,))
        user = cursor.fetchone()
        if not user:
            return {'emails': [], 'total': 0, 'page': 1, 'pages': 0}
        
        user_id = user['id']
        offset = (page - 1) * page_size
        
        # ИСПРАВЛЕННЫЙ ЗАПРОС - используем emails вместо mail_headers
        cursor.execute('''
        SELECT e.* 
        FROM emails e 
        WHERE e.user_id = ? AND e.folder = ?
        ORDER BY e.received_at DESC 
        LIMIT ? OFFSET ?
        ''', (user_id, folder, page_size, offset))
        
        emails = [dict(row) for row in cursor.fetchall()]
        
        cursor.execute('''
        SELECT COUNT(*) as count 
        FROM emails e 
        WHERE e.user_id = ? AND e.folder = ?
        ''', (user_id, folder))
        
        total_count = cursor.fetchone()['count']
        conn.close()
        
        return {
            'emails': emails,
            'total': total_count,
            'page': page,
            'pages': (total_count + page_size - 1) // page_size
        }
        
    except Exception as e:
        print(f"Ошибка получения писем: {e}")
        return {'emails': [], 'total': 0, 'page': 1, 'pages': 0}

def get_email_content(uuid):
    """Получение полного содержимого письма"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Получаем письмо - ИСПРАВЛЕННЫЙ ЗАПРОС
        cursor.execute('SELECT * FROM emails WHERE uuid = ?', (uuid,))
        email_data = dict(cursor.fetchone())
        
        if not email_data:
            return None
        
        # Декодируем содержимое
        decoded_body = decode_email_content(email_data['body'])
        
        conn.close()
        
        return {
            'header': {
                'uuid': email_data['uuid'],
                'from_email': email_data['from_email'],
                'to_email': email_data['to_email'],
                'subject': email_data['subject'],
                'date': email_data['received_at'],
                'size': email_data['size'],
                'folder': email_data['folder'],
                'is_read': email_data['is_read']
            },
            'content': decoded_body,
            'attachments': []
        }
        
    except Exception as e:
        print(f"Ошибка получения письма: {e}")
        return None


@app.before_request
def check_notifications():
    """Проверяет уведомления перед каждым запросом"""
    if 'user_id' in session:
        # Здесь можно добавить проверку новых уведомлений
        pass

@app.route('/api/notifications')
def get_notifications():
    """Получение уведомлений"""
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    unread_count = sum(1 for n in notifications if not n['read'])
    
    return jsonify({
        'notifications': notifications,
        'unread_count': unread_count
    })

@app.route('/api/notifications/read_all', methods=['POST'])
def mark_all_notifications_read():
    """Пометить все уведомления как прочитанные"""
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    for notification in notifications:
        notification['read'] = True
    
    return jsonify({'success': True})

@app.route('/api/notifications/add', methods=['POST'])
def add_notification():
    """Добавить уведомление (для внутреннего использования)"""
    data = request.get_json()
    message = data.get('message')
    level = data.get('level', 'error')  # error, warning, info, success
    
    notifications.append({
        'id': len(notifications) + 1,
        'message': message,
        'level': level,
        'read': False,
        'timestamp': datetime.datetime.now().isoformat()
    })
    
    return jsonify({'success': True})

# Функция для добавления уведомлений об ошибках
def add_error_notification(message):
    """Добавляет уведомление об ошибке"""
    notifications.append({
        'id': len(notifications) + 1,
        'message': message,
        'level': 'error',
        'read': False,
        'timestamp': datetime.datetime.now().isoformat()
    })

@app.route('/')
def index():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    return render_template('index.html', 
                         user_name=session.get('user_name', 'User'),
                         SERVER_CONFIG=SERVER_CONFIG)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('SELECT * FROM users WHERE email = ?', (email,))
        user = cursor.fetchone()
        
        if user:
            stored_hash = user['password_hash']
            salt = user['salt']
            input_hash = hash_password(password, salt)
            
            if stored_hash == input_hash:
                session['user_id'] = user['id']
                session['user_email'] = user['email']
                session['user_name'] = user['name']
                conn.close()
                return redirect(url_for('index'))
        
        conn.close()
        return '''
        <!DOCTYPE html>
        <html lang="ru">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Вход - ODQ Mail</title>
            <style>
                * { margin: 0; padding: 0; box-sizing: border-box; }
                body {
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    min-height: 100vh;
                    display: flex;
                    justify-content: center;
                    align-items: center;
                }
                .login-container {
                    background: white;
                    padding: 40px;
                    border-radius: 15px;
                    box-shadow: 0 15px 35px rgba(0,0,0,0.2);
                    width: 100%;
                    max-width: 400px;
                    text-align: center;
                }
                .logo {
                    font-size: 32px;
                    margin-bottom: 20px;
                    color: #2c3e50;
                }
                .form-group {
                    margin-bottom: 20px;
                    text-align: left;
                }
                label {
                    display: block;
                    margin-bottom: 5px;
                    color: #2c3e50;
                    font-weight: 500;
                }
                input[type="email"],
                input[type="password"] {
                    width: 100%;
                    padding: 12px;
                    border: 2px solid #bdc3c7;
                    border-radius: 8px;
                    font-size: 16px;
                    transition: border-color 0.3s;
                }
                input[type="email"]:focus,
                input[type="password"]:focus {
                    border-color: #3498db;
                    outline: none;
                }
                .btn {
                    width: 100%;
                    padding: 12px;
                    background: #3498db;
                    color: white;
                    border: none;
                    border-radius: 8px;
                    font-size: 16px;
                    cursor: pointer;
                    transition: background 0.3s;
                }
                .btn:hover {
                    background: #2980b9;
                }
                .error {
                    color: #e74c3c;
                    margin-top: 10px;
                    font-size: 14px;
                }
                .register-link {
                    margin-top: 20px;
                    color: #7f8c8d;
                }
                .register-link a {
                    color: #3498db;
                    text-decoration: none;
                }
            </style>
        </head>
        <body>
            <div class="login-container">
                <div class="logo">📧 ODQ Mail</div>
                <h2>Вход в систему</h2>
                <form method="post">
                    <div class="form-group">
                        <label>Email:</label>
                        <input type="email" name="email" required>
                    </div>
                    <div class="form-group">
                        <label>Пароль:</label>
                        <input type="password" name="password" required>
                    </div>
                    <button type="submit" class="btn">Войти</button>
                    <div class="error">Неверный email или пароль</div>
                </form>
                <div class="register-link">
                    Нет аккаунта? <a href="/register">Зарегистрироваться</a>
                </div>
            </div>
        </body>
        </html>
        '''
    
    return '''
    <!DOCTYPE html>
    <html lang="ru">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Вход - ODQ Mail</title>
        <style>
            * { margin: 0; padding: 0; box-sizing: border-box; }
            body {
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                min-height: 100vh;
                display: flex;
                justify-content: center;
                align-items: center;
            }
            .login-container {
                background: white;
                padding: 40px;
                border-radius: 15px;
                box-shadow: 0 15px 35px rgba(0,0,0,0.2);
                width: 100%;
                max-width: 400px;
                text-align: center;
            }
            .logo {
                font-size: 32px;
                margin-bottom: 20px;
                color: #2c3e50;
            }
            .form-group {
                margin-bottom: 20px;
                text-align: left;
            }
            label {
                display: block;
                margin-bottom: 5px;
                color: #2c3e50;
                font-weight: 500;
            }
            input[type="email"],
            input[type="password"] {
                width: 100%;
                padding: 12px;
                border: 2px solid #bdc3c7;
                border-radius: 8px;
                font-size: 16px;
                transition: border-color 0.3s;
            }
            input[type="email"]:focus,
            input[type="password"]:focus {
                border-color: #3498db;
                outline: none;
            }
            .btn {
                width: 100%;
                padding: 12px;
                background: #3498db;
                color: white;
                border: none;
                border-radius: 8px;
                font-size: 16px;
                cursor: pointer;
                transition: background 0.3s;
            }
            .btn:hover {
                background: #2980b9;
            }
            .register-link {
                margin-top: 20px;
                color: #7f8c8d;
            }
            .register-link a {
                color: #3498db;
                text-decoration: none;
            }
        </style>
    </head>
    <body>
        <div class="login-container">
            <div class="logo">📧 ODQ Mail</div>
            <h2>Вход в систему</h2>
            <form method="post">
                <div class="form-group">
                    <label>Email:</label>
                    <input type="email" name="email" required>
                </div>
                <div class="form-group">
                    <label>Пароль:</label>
                    <input type="password" name="password" required>
                </div>
                <button type="submit" class="btn">Войти</button>
            </form>
            <div class="register-link">
                Нет аккаунта? <a href="/register">Зарегистрироваться</a>
            </div>
        </div>
    </body>
    </html>
    '''

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        name = request.form['name']
        phone = request.form.get('phone', '')
        
        if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
            return '''
            <div class="error">Неверный формат email</div>
            '''
        
        if len(password) < 6:
            return '''
            <div class="error">Пароль должен содержать至少 6 символов</div>
            '''
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        try:
            cursor.execute('SELECT * FROM users WHERE email = ?', (email,))
            if cursor.fetchone():
                return '''
                <div class="error">Пользователь с таким email уже существует</div>
                '''
            
            import secrets
            import string
            salt = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(16))
            password_hash = hash_password(password, salt)
            
            cursor.execute('''
            INSERT INTO users (email, password_hash, salt, name, phone)
            VALUES (?, ?, ?, ?, ?)
            ''', (email, password_hash, salt, name, phone))
            
            conn.commit()
            conn.close()
            
            return redirect(url_for('login'))
        except Exception as e:
            conn.close()
            return f'''
            <div class="error">Ошибка регистрации: {str(e)}</div>
            '''
    
    return '''
    <!DOCTYPE html>
    <html lang="ru">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Регистрация - ODQ Mail</title>
        <style>
            * { margin: 0; padding: 0; box-sizing: border-box; }
            body {
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                min-height: 100vh;
                display: flex;
                justify-content: center;
                align-items: center;
            }
            .register-container {
                background: white;
                padding: 40px;
                border-radius: 15px;
                box-shadow: 0 15px 35px rgba(0,0,0,0.2);
                width: 100%;
                max-width: 400px;
                text-align: center;
            }
            .logo {
                font-size: 32px;
                margin-bottom: 20px;
                color: #2c3e50;
            }
            .form-group {
                margin-bottom: 20px;
                text-align: left;
            }
            label {
                display: block;
                margin-bottom: 5px;
                color: #2c3e50;
                font-weight: 500;
            }
            input[type="text"],
            input[type="email"],
            input[type="password"],
            input[type="tel"] {
                width: 100%;
                padding: 12px;
                border: 2px solid #bdc3c7;
                border-radius: 8px;
                font-size: 16px;
                transition: border-color 0.3s;
            }
            input:focus {
                border-color: #3498db;
                outline: none;
            }
            .btn {
                width: 100%;
                padding: 12px;
                background: #3498db;
                color: white;
                border: none;
                border-radius: 8px;
                font-size: 16px;
                cursor: pointer;
                transition: background 0.3s;
            }
            .btn:hover {
                background: #2980b9;
            }
            .error {
                color: #e74c3c;
                margin-top: 10px;
                font-size: 14px;
            }
            .login-link {
                margin-top: 20px;
                color: #7f8c8d;
            }
            .login-link a {
                color: #3498db;
                text-decoration: none;
            }
        </style>
    </head>
    <body>
        <div class="register-container">
            <div class="logo">📧 ODQ Mail</div>
            <h2>Регистрация</h2>
            <form method="post">
                <div class="form-group">
                    <label>Имя:</label>
                    <input type="text" name="name" required>
                </div>
                <div class="form-group">
                    <label>Email:</label>
                    <input type="email" name="email" required>
                </div>
                <div class="form-group">
                    <label>Пароль:</label>
                    <input type="password" name="password" required>
                </div>
                <div class="form-group">
                    <label>Телефон (необязательно):</label>
                    <input type="tel" name="phone">
                </div>
                <button type="submit" class="btn">Зарегистрироваться</button>
            </form>
            <div class="login-link">
                Уже есть аккаунт? <a href="/login">Войти</a>
            </div>
        </div>
    </body>
    </html>
    '''

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/api/emails/<folder>')
def get_emails(folder):
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    page = request.args.get('page', 1, type=int)
    page_size = request.args.get('page_size', SERVER_CONFIG['DEFAULT_PAGE_SIZE'], type=int)
    
    emails_data = get_emails_from_db(
        folder=folder,
        page=page,
        page_size=page_size,
        user_email=session['user_email']
    )
    
    return jsonify(emails_data)

@app.route('/api/email/<uuid>')
def get_email(uuid):
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    email_content = get_email_content(uuid)
    if not email_content:
        return jsonify({'error': 'Письмо не найдено'}), 404
    
    # Помечаем как прочитанное - ИСПРАВЛЕННЫЙ ЗАПРОС
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('UPDATE emails SET is_read = 1 WHERE uuid = ?', (uuid,))
    conn.commit()
    conn.close()
    
    return jsonify(email_content)

@app.route('/api/email/send', methods=['POST'])
def send_email():
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    data = request.get_json()
    to_email = data.get('to')
    subject = data.get('subject')
    body = data.get('body')
    
    if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', to_email):
        return jsonify({'error': 'Неверный формат email получателя'})
    
    success, message = send_email_via_smtp(
        from_email=session['user_email'],
        to_emails=[to_email],
        subject=subject,
        body=body
    )
    
    if success:
        # Сохраняем копию в отправленные
        #save_email_to_db(session['user_email'], to_email, subject, body, 'SENT')
        return jsonify({'success': True, 'message': message})
    else:
        return jsonify({'error': message}), 500


def save_email_to_db(from_email, to_email, subject, body, folder='SENT'):
    """Сохраняем письмо в базу данных"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Получаем user_id отправителя
        cursor.execute('SELECT id FROM users WHERE email = ?', (from_email,))
        from_user = cursor.fetchone()
        if not from_user:
            print(f"Пользователь {from_email} не найден")
            conn.close()
            return False
        
        from_user_id = from_user['id']
        mail_uuid = str(uuid.uuid4())
        
        # ИСПРАВЛЕННЫЙ ЗАПРОС - используем emails
        cursor.execute('''
        INSERT INTO emails (uuid, from_email, to_email, subject, body, size, folder, user_id)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (mail_uuid, from_email, to_email, subject, body, len(body), folder, from_user_id))
        
        conn.commit()
        conn.close()
        return True
        
    except Exception as e:
        print(f"Ошибка сохранения письма: {e}")
        return False

@app.route('/api/email/delete', methods=['POST'])
def delete_emails():
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    data = request.get_json()
    uuids = data.get('uuids', [])
    folder = data.get('folder', 'INBOX')
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        for uuid in uuids:
            if folder == 'TRASH':
                # Полное удаление - ИСПРАВЛЕННЫЙ ЗАПРОС
                cursor.execute('DELETE FROM emails WHERE uuid = ?', (uuid,))
            else:
                # Перемещение в корзину - ИСПРАВЛЕННЫЙ ЗАПРОС
                cursor.execute('''
                UPDATE emails 
                SET folder = 'TRASH', received_at = datetime('now') 
                WHERE uuid = ?
                ''', (uuid,))
        
        conn.commit()
        conn.close()
        return jsonify({'success': True, 'deleted': len(uuids)})
    except Exception as e:
        conn.close()
        return jsonify({'error': str(e)}), 500

@app.template_filter('datetime')
def format_datetime(value):
    """Фильтр для форматирования даты"""
    if isinstance(value, str):
        try:
            value = datetime.datetime.fromisoformat(value.replace('Z', '+00:00'))
        except:
            return value
    return value.strftime('%d.%m.%Y %H:%M')

if __name__ == '__main__':
    init_db()
    app.run(
        host=SERVER_CONFIG['WEB_HOST'],
        port=SERVER_CONFIG['WEB_PORT'],
        debug=SERVER_CONFIG['DEBUG']
    )
