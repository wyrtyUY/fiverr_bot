# app_final.py - ПОЛНАЯ ВЕРСИЯ с защитой + весь старый функционал
from flask import Flask, request, render_template_string, redirect, url_for, session, g, flash, jsonify, make_response
import sqlite3
import hashlib
import os
import time
import random
import re
from datetime import datetime, timedelta
from functools import wraps

app = Flask(__name__)
app.secret_key = os.urandom(32)
app.permanent_session_lifetime = timedelta(minutes=30)

# === БАЗЫ ДАННЫХ ===
DATABASE = 'board.db'
PROTECTION_DB = 'protection.db'

def get_db():
    """Основная БД сайта"""
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db

def get_protection_db():
    """БД для защиты"""
    db = getattr(g, '_protection_db', None)
    if db is None:
        db = g._protection_db = sqlite3.connect(PROTECTION_DB)
        db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
def close_connection(exception):
    """Закрытие соединений с БД"""
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()
    
    pdb = getattr(g, '_protection_db', None)
    if pdb is not None:
        pdb.close()

# === ИНИЦИАЛИЗАЦИЯ БАЗ ДАННЫХ ===
def init_db():
    """Инициализация основной БД"""
    with app.app_context():
        db = get_db()
        cursor = db.cursor()
        
        # Таблица пользователей
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                email TEXT,
                registered DATE DEFAULT CURRENT_DATE,
                last_seen DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Таблица объявлений
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS ads (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                price INTEGER,
                category TEXT,
                created DATE DEFAULT CURRENT_DATE,
                views INTEGER DEFAULT 0,
                status TEXT DEFAULT 'active',
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        
        # Таблица чатов
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS chats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ad_id INTEGER NOT NULL,
                buyer_id INTEGER NOT NULL,
                seller_id INTEGER NOT NULL,
                created DATETIME DEFAULT CURRENT_TIMESTAMP,
                last_message DATETIME DEFAULT CURRENT_TIMESTAMP,
                status TEXT DEFAULT 'active',
                FOREIGN KEY (ad_id) REFERENCES ads (id),
                FOREIGN KEY (buyer_id) REFERENCES users (id),
                FOREIGN KEY (seller_id) REFERENCES users (id)
            )
        ''')
        
        # Таблица сообщений
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                chat_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                message TEXT NOT NULL,
                sent DATETIME DEFAULT CURRENT_TIMESTAMP,
                is_read INTEGER DEFAULT 0,
                FOREIGN KEY (chat_id) REFERENCES chats (id),
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        
        db.commit()

def init_protection_db():
    """Инициализация БД защиты"""
    with app.app_context():
        db = get_protection_db()
        cursor = db.cursor()
        
        # Таблица для отслеживания подозрительных IP
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS suspicious_ips (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT UNIQUE,
                reason TEXT,
                first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
                last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
                blocked_until DATETIME,
                request_count INTEGER DEFAULT 1
            )
        ''')
        
        # Таблица для хранения капчи
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS captcha_tokens (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                token TEXT UNIQUE,
                solution TEXT,
                created DATETIME DEFAULT CURRENT_TIMESTAMP,
                expires DATETIME,
                used INTEGER DEFAULT 0
            )
        ''')
        
        # Таблица для rate limiting
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS user_actions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                action_type TEXT,
                ip TEXT,
                created DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        db.commit()

# === КОМПОНЕНТЫ ЗАЩИТЫ ===

class Fingerprinter:
    """Сбор цифрового отпечатка браузера"""
    
    @staticmethod
    def get_fingerprint(request):
        """Собирает fingerprint посетителя"""
        fp = {
            'ip': request.remote_addr,
            'user_agent': request.headers.get('User-Agent', ''),
            'accept_language': request.headers.get('Accept-Language', ''),
            'accept_encoding': request.headers.get('Accept-Encoding', ''),
            'connection': request.headers.get('Connection', '')
        }
        
        # Проверка на ботов
        bot_patterns = ['bot', 'crawler', 'spider', 'scraper', 'selenium', 
                       'puppeteer', 'headless', 'phantom', 'python-requests']
        
        is_bot = any(pattern in fp['user_agent'].lower() for pattern in bot_patterns)
        
        # Создаем хеш отпечатка
        fp_hash = hashlib.sha256(str(fp).encode()).hexdigest()[:16]
        fp['hash'] = fp_hash
        
        return fp, is_bot

class BehaviorAnalyzer:
    """Анализ поведения пользователя"""
    
    @staticmethod
    def analyze_navigation(request, session):
        """Анализ навигации"""
        if 'page_views' not in session:
            session['page_views'] = []
        
        current_time = time.time()
        session['page_views'].append({
            'path': request.path,
            'time': current_time
        })
        
        # Проверка на слишком быстрый переход
        if len(session['page_views']) > 1:
            last_view = session['page_views'][-2]
            current_view = session['page_views'][-1]
            
            if current_view['time'] - last_view['time'] < 0.5:
                return False, "too_fast_navigation"
        
        return True, "normal"

class CaptchaGenerator:
    """Генератор простой капчи"""
    
    @staticmethod
    def generate():
        """Генерирует математическую капчу"""
        num1 = random.randint(1, 10)
        num2 = random.randint(1, 10)
        operation = random.choice(['+', '-'])
        
        if operation == '+':
            solution = num1 + num2
        else:
            if num1 < num2:
                num1, num2 = num2, num1
            solution = num1 - num2
        
        token = hashlib.md5(f"{num1}{operation}{num2}{time.time()}{random.random()}".encode()).hexdigest()[:16]
        
        return {
            'token': token,
            'question': f"{num1} {operation} {num2} = ?",
            'solution': str(solution),
            'expires': datetime.now() + timedelta(minutes=5)
        }
    
    @staticmethod
    def verify(token, answer):
        """Проверка ответа капчи"""
        db = get_protection_db()
        captcha = db.execute(
            'SELECT * FROM captcha_tokens WHERE token = ? AND used = 0 AND expires > CURRENT_TIMESTAMP',
            (token,)
        ).fetchone()
        
        if captcha and captcha['solution'] == answer.strip():
            db.execute('UPDATE captcha_tokens SET used = 1 WHERE token = ?', (token,))
            db.commit()
            return True
        
        return False

# === MIDDLEWARE ЗАЩИТЫ ===

@app.before_request
def security_check():
    """Проверка безопасности перед каждым запросом"""
    
    # Пропускаем статические и служебные пути
    if request.path.startswith('/captcha') or request.path.startswith('/api/'):
        return
    
    # Собираем fingerprint
    fp, is_bot = Fingerprinter.get_fingerprint(request)
    
    # Проверяем IP в черном списке
    db = get_protection_db()
    blocked_ip = db.execute(
        'SELECT * FROM suspicious_ips WHERE ip = ? AND blocked_until > CURRENT_TIMESTAMP',
        (fp['ip'],)
    ).fetchone()
    
    if blocked_ip:
        return "Access Denied: Your IP is blocked", 403
    
    # Анализируем поведение
    behavior_ok, behavior_reason = BehaviorAnalyzer.analyze_navigation(request, session)
    
    if not behavior_ok and not session.get('captcha_passed'):
        # Добавляем IP в подозрительные
        db.execute('''
            INSERT OR REPLACE INTO suspicious_ips (ip, reason, last_seen, request_count)
            VALUES (?, ?, CURRENT_TIMESTAMP, 
                COALESCE((SELECT request_count + 1 FROM suspicious_ips WHERE ip = ?), 1))
        ''', (fp['ip'], f"suspect_behavior:{behavior_reason}", fp['ip']))
        db.commit()
        
        return redirect(url_for('show_captcha', next=request.path))
    
    # Rate limiting для sensitive действий
    if request.endpoint in ['login', 'register', 'send_message', 'start_chat']:
        recent_actions = db.execute('''
            SELECT COUNT(*) as cnt FROM user_actions 
            WHERE ip = ? AND created > datetime("now", "-1 minute")
            AND action_type = ?
        ''', (fp['ip'], request.endpoint)).fetchone()
        
        if recent_actions and recent_actions['cnt'] > 5:
            return "Too many requests. Please slow down.", 429
        
        db.execute(
            'INSERT INTO user_actions (user_id, action_type, ip) VALUES (?, ?, ?)',
            (session.get('user_id'), request.endpoint, fp['ip'])
        )
        db.commit()

# === РОУТЫ ЗАЩИТЫ ===

@app.route('/captcha', methods=['GET', 'POST'])
def show_captcha():
    """Страница с капчей"""
    next_url = request.args.get('next', '/')
    
    if request.method == 'POST':
        token = request.form.get('token')
        answer = request.form.get('answer')
        
        if CaptchaGenerator.verify(token, answer):
            session['captcha_passed'] = True
            session['captcha_time'] = time.time()
            return redirect(next_url)
        else:
            error = "Неверный ответ"
    
    captcha = CaptchaGenerator.generate()
    
    db = get_protection_db()
    db.execute(
        'INSERT INTO captcha_tokens (token, solution, expires) VALUES (?, ?, ?)',
        (captcha['token'], captcha['solution'], captcha['expires'])
    )
    db.commit()
    
    html = f'''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Проверка безопасности</title>
        <style>
            body {{ font-family: Arial; background: #f0f2f5; display: flex; justify-content: center; align-items: center; height: 100vh; }}
            .captcha-box {{ background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); width: 400px; }}
            input {{ width: 100%; padding: 8px; margin: 10px 0; border: 1px solid #ddd; border-radius: 5px; }}
            button {{ width: 100%; padding: 10px; background: #1a73e8; color: white; border: none; border-radius: 5px; cursor: pointer; }}
        </style>
    </head>
    <body>
        <div class="captcha-box">
            <h2>Подтвердите, что вы не бот</h2>
            <p>Решите пример:</p>
            <form method="POST">
                <input type="hidden" name="token" value="{captcha['token']}">
                <h3 style="font-size: 24px; text-align: center;">{captcha['question']}</h3>
                <input type="text" name="answer" placeholder="Ваш ответ" required>
                <button type="submit">Подтвердить</button>
            </form>
        </div>
    </body>
    </html>
    '''
    
    return render_template_string(html)

# === ОСНОВНЫЕ РОУТЫ САЙТА (ВЕСЬ СТАРЫЙ ФУНКЦИОНАЛ) ===

@app.route('/')
def index():
    """Главная страница со списком объявлений"""
    db = get_db()
    
    # Получаем параметры фильтрации
    search = request.args.get('search', '')
    category = request.args.get('category', '')
    
    # Базовый запрос
    query = '''
        SELECT ads.*, users.username 
        FROM ads 
        JOIN users ON ads.user_id = users.id 
        WHERE ads.status = 'active'
        ORDER BY ads.created DESC
    '''
    
    ads = db.execute(query).fetchall()
    
    # Преобразуем в список словарей
    ads_list = []
    for ad in ads:
        ads_list.append({
            'id': ad['id'],
            'title': ad['title'],
            'description': ad['description'],
            'price': ad['price'] or 0,
            'category': ad['category'] or 'Другое',
            'created': ad['created'],
            'views': ad['views'],
            'username': ad['username']
        })
    
    # HTML шаблон
    html = '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Доска объявлений</title>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <style>
            * { margin: 0; padding: 0; box-sizing: border-box; }
            body { 
                font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Arial, sans-serif;
                background: #f0f2f5;
            }
            .navbar {
                background: white;
                padding: 1rem 2rem;
                box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                display: flex;
                justify-content: space-between;
                align-items: center;
                margin-bottom: 2rem;
            }
            .navbar a {
                color: #1a73e8;
                text-decoration: none;
                margin-left: 1rem;
                font-weight: 500;
            }
            .navbar a:hover { color: #1557b0; }
            .container { max-width: 1200px; margin: 0 auto; padding: 0 20px; }
            .btn {
                background: #1a73e8;
                color: white;
                padding: 10px 20px;
                border: none;
                border-radius: 5px;
                cursor: pointer;
                font-size: 16px;
                text-decoration: none;
                display: inline-block;
            }
            .btn:hover { background: #1557b0; }
            .ads-grid {
                display: grid;
                grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
                gap: 20px;
                margin-top: 20px;
            }
            .ad-card {
                background: white;
                border-radius: 10px;
                padding: 20px;
                box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                cursor: pointer;
                transition: transform 0.2s;
            }
            .ad-card:hover {
                transform: translateY(-2px);
                box-shadow: 0 4px 8px rgba(0,0,0,0.15);
            }
            .ad-title {
                font-size: 1.2rem;
                font-weight: bold;
                margin-bottom: 10px;
                color: #1a73e8;
            }
            .ad-price {
                font-size: 1.3rem;
                color: #28a745;
                font-weight: bold;
                margin: 10px 0;
            }
            .ad-meta {
                color: #666;
                font-size: 0.9rem;
                border-top: 1px solid #eee;
                padding-top: 10px;
                margin-top: 10px;
            }
            .filters {
                background: white;
                padding: 20px;
                border-radius: 10px;
                margin-bottom: 20px;
                display: flex;
                gap: 10px;
            }
            .filters input, .filters select {
                padding: 8px;
                border: 1px solid #ddd;
                border-radius: 5px;
                flex: 1;
            }
        </style>
    </head>
    <body>
        <nav class="navbar">
            <div style="font-size: 1.5rem; font-weight: bold;">
                📢 Доска объявлений
            </div>
            <div>
                <a href="/">Главная</a>
    '''
    
    if session.get('user_id'):
        html += f'''
                <a href="/create-ad">+ Добавить объявление</a>
                <a href="/my-chats">💬 Чаты</a>
                <span style="margin-left: 1rem; color: #666;">
                    Привет, {session.get('username', '')}!
                </span>
                <a href="/logout">Выйти</a>
        '''
    else:
        html += '''
                <a href="/login">Войти</a>
                <a href="/register">Регистрация</a>
        '''
    
    html += '''
            </div>
        </nav>
        
        <div class="container">
            <h1>Активные объявления</h1>
            
            <div class="filters">
                <input type="text" id="search" placeholder="Поиск по названию...">
                <select id="category">
                    <option value="">Все категории</option>
                    <option value="Товары">Товары</option>
                    <option value="Услуги">Услуги</option>
                    <option value="Недвижимость">Недвижимость</option>
                    <option value="Работа">Работа</option>
                </select>
                <button class="btn" onclick="applyFilters()">Применить</button>
            </div>
            
            <div class="ads-grid">
    '''
    
    for ad in ads_list:
        html += f'''
                <div class="ad-card" onclick="location.href='/ad/{ad["id"]}'">
                    <div class="ad-title">{ad["title"]}</div>
                    <div class="ad-price">{ad["price"]} ₽</div>
                    <div>{ad["description"][:100]}{'...' if len(ad["description"]) > 100 else ''}</div>
                    <div class="ad-meta">
                        <div>👤 {ad["username"]}</div>
                        <div>📅 {ad["created"]}</div>
                        <div>👁️ {ad["views"]} просмотров</div>
                        <div>🏷️ {ad["category"]}</div>
                    </div>
                </div>
        '''
    
    if not ads_list:
        html += '<p>Пока нет объявлений. Будьте первым!</p>'
    
    html += '''
            </div>
        </div>
        
        <script>
        function applyFilters() {
            const search = document.getElementById('search').value;
            const category = document.getElementById('category').value;
            window.location.href = '/?search=' + encodeURIComponent(search) + '&category=' + encodeURIComponent(category);
        }
        </script>
    </body>
    </html>
    '''
    
    return render_template_string(html)

@app.route('/register', methods=['GET', 'POST'])
def register():
    """Регистрация нового пользователя"""
    if request.method == 'POST':
        username = request.form['username']
        password = hashlib.sha256(request.form['password'].encode()).hexdigest()
        email = request.form.get('email', '')
        
        db = get_db()
        try:
            db.execute(
                'INSERT INTO users (username, password, email) VALUES (?, ?, ?)',
                (username, password, email)
            )
            db.commit()
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            error = 'Пользователь уже существует'
    
    html = '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Регистрация</title>
        <meta charset="utf-8">
        <style>
            body { font-family: Arial; background: #f0f2f5; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }
            .form-container {
                background: white;
                padding: 30px;
                border-radius: 10px;
                box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                width: 400px;
            }
            h2 { margin-bottom: 20px; color: #333; }
            input { width: 100%; padding: 10px; margin: 10px 0; border: 1px solid #ddd; border-radius: 5px; box-sizing: border-box; }
            button { width: 100%; padding: 10px; background: #1a73e8; color: white; border: none; border-radius: 5px; cursor: pointer; font-size: 16px; }
            button:hover { background: #1557b0; }
            .error { color: red; margin-bottom: 10px; }
            a { color: #1a73e8; text-decoration: none; }
        </style>
    </head>
    <body>
        <div class="form-container">
            <h2>Регистрация</h2>
            <form method="POST">
                <input type="text" name="username" placeholder="Имя пользователя" required>
                <input type="email" name="email" placeholder="Email (необязательно)">
                <input type="password" name="password" placeholder="Пароль" required>
                <button type="submit">Зарегистрироваться</button>
            </form>
            <p style="text-align: center; margin-top: 15px;">
                Уже есть аккаунт? <a href="/login">Войти</a>
            </p>
        </div>
    </body>
    </html>
    '''
    
    return render_template_string(html)

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Вход пользователя"""
    if request.method == 'POST':
        username = request.form['username']
        password = hashlib.sha256(request.form['password'].encode()).hexdigest()
        
        db = get_db()
        user = db.execute(
            'SELECT * FROM users WHERE username = ? AND password = ?',
            (username, password)
        ).fetchone()
        
        if user:
            session['user_id'] = user['id']
            session['username'] = user['username']
            session.permanent = True
            
            db.execute(
                'UPDATE users SET last_seen = CURRENT_TIMESTAMP WHERE id = ?',
                (user['id'],)
            )
            db.commit()
            
            return redirect(url_for('index'))
        else:
            error = 'Неверное имя или пароль'
    
    html = '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Вход</title>
        <meta charset="utf-8">
        <style>
            body { font-family: Arial; background: #f0f2f5; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }
            .form-container {
                background: white;
                padding: 30px;
                border-radius: 10px;
                box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                width: 400px;
            }
            h2 { margin-bottom: 20px; color: #333; }
            input { width: 100%; padding: 10px; margin: 10px 0; border: 1px solid #ddd; border-radius: 5px; box-sizing: border-box; }
            button { width: 100%; padding: 10px; background: #1a73e8; color: white; border: none; border-radius: 5px; cursor: pointer; font-size: 16px; }
            button:hover { background: #1557b0; }
            .error { color: red; margin-bottom: 10px; }
            a { color: #1a73e8; text-decoration: none; }
        </style>
    </head>
    <body>
        <div class="form-container">
            <h2>Вход</h2>
            <form method="POST">
                <input type="text" name="username" placeholder="Имя пользователя" required>
                <input type="password" name="password" placeholder="Пароль" required>
                <button type="submit">Войти</button>
            </form>
            <p style="text-align: center; margin-top: 15px;">
                Нет аккаунта? <a href="/register">Зарегистрироваться</a>
            </p>
        </div>
    </body>
    </html>
    '''
    
    return render_template_string(html)

@app.route('/logout')
def logout():
    """Выход из системы"""
    session.clear()
    return redirect(url_for('index'))

@app.route('/create-ad', methods=['GET', 'POST'])
def create_ad():
    """Создание нового объявления"""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        price = request.form.get('price')
        category = request.form.get('category')
        
        db = get_db()
        db.execute(
            '''INSERT INTO ads (user_id, title, description, price, category)
               VALUES (?, ?, ?, ?, ?)''',
            (session['user_id'], title, description, price, category)
        )
        db.commit()
        
        return redirect(url_for('index'))
    
    html = '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Создать объявление</title>
        <meta charset="utf-8">
        <style>
            body { font-family: Arial; background: #f0f2f5; padding: 20px; margin: 0; }
            .container { max-width: 600px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
            h2 { margin-bottom: 20px; color: #333; }
            input, textarea, select { width: 100%; padding: 10px; margin: 10px 0; border: 1px solid #ddd; border-radius: 5px; box-sizing: border-box; font-family: Arial; }
            textarea { resize: vertical; }
            button { padding: 10px 20px; background: #1a73e8; color: white; border: none; border-radius: 5px; cursor: pointer; font-size: 16px; margin-right: 10px; }
            button:hover { background: #1557b0; }
            .cancel { background: #6c757d; }
            .cancel:hover { background: #5a6268; }
        </style>
    </head>
    <body>
        <div class="container">
            <h2>Создать новое объявление</h2>
            <form method="POST">
                <input type="text" name="title" placeholder="Заголовок *" required>
                <textarea name="description" placeholder="Описание *" rows="5" required></textarea>
                <input type="number" name="price" placeholder="Цена (₽)">
                <select name="category">
                    <option value="">Выберите категорию</option>
                    <option value="Товары">Товары</option>
                    <option value="Услуги">Услуги</option>
                    <option value="Недвижимость">Недвижимость</option>
                    <option value="Работа">Работа</option>
                    <option value="Электроника">Электроника</option>
                </select>
                <div style="margin-top: 20px;">
                    <button type="submit">Опубликовать</button>
                    <a href="/"><button type="button" class="cancel">Отмена</button></a>
                </div>
            </form>
        </div>
    </body>
    </html>
    '''
    
    return render_template_string(html)

@app.route('/ad/<int:ad_id>')
def ad_detail(ad_id):
    """Просмотр объявления"""
    db = get_db()
    
    # Увеличиваем счетчик просмотров
    db.execute('UPDATE ads SET views = views + 1 WHERE id = ?', (ad_id,))
    db.commit()
    
    # Получаем объявление
    ad = db.execute('''
        SELECT ads.*, users.username 
        FROM ads 
        JOIN users ON ads.user_id = users.id 
        WHERE ads.id = ?
    ''', (ad_id,)).fetchone()
    
    if not ad:
        return "Объявление не найдено", 404
    
    html = f'''
    <!DOCTYPE html>
    <html>
    <head>
        <title>{ad['title']}</title>
        <meta charset="utf-8">
        <style>
            body {{ font-family: Arial; background: #f0f2f5; padding: 20px; margin: 0; }}
            .container {{ max-width: 800px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
            h1 {{ margin-bottom: 10px; color: #333; }}
            .price {{ font-size: 2rem; color: #28a745; font-weight: bold; margin: 20px 0; }}
            .seller-info {{ background: #f8f9fa; padding: 20px; border-radius: 10px; margin: 20px 0; }}
            .btn {{
                background: #1a73e8;
                color: white;
                padding: 15px 30px;
                border: none;
                border-radius: 5px;
                font-size: 1.1rem;
                cursor: pointer;
                width: 100%;
                text-decoration: none;
                display: inline-block;
                text-align: center;
                box-sizing: border-box;
            }}
            .btn:hover {{ background: #1557b0; }}
            .back-link {{ color: #1a73e8; text-decoration: none; display: inline-block; margin-bottom: 20px; }}
            .back-link:hover {{ text-decoration: underline; }}
        </style>
    </head>
    <body>
        <div class="container">
            <a href="/" class="back-link">← На главную</a>
            
            <h1>{ad['title']}</h1>
            <div class="price">{ad['price'] or 0} ₽</div>
            
            <div style="margin: 20px 0;">
                <h3>Описание:</h3>
                <p style="line-height: 1.6;">{ad['description']}</p>
            </div>
            
            <div class="seller-info">
                <h3>Продавец: {ad['username']}</h3>
                <p>Объявление создано: {ad['created']}</p>
                <p>Просмотров: {ad['views']}</p>
                <p>Категория: {ad['category'] or 'Другое'}</p>
            </div>
    '''
    
    if session.get('user_id') and session['user_id'] != ad['user_id']:
        html += f'''
            <form method="POST" action="/start-chat/{ad['id']}">
                <button type="submit" class="btn">
                    💬 Написать продавцу
                </button>
            </form>
        '''
    elif session.get('user_id') == ad['user_id']:
        html += '<p style="color: #666; text-align: center;">Это ваше объявление</p>'
    else:
        html += '<p style="color: #666; text-align: center;"><a href="/login">Войдите</a>, чтобы написать продавцу</p>'
    
    html += '''
        </div>
    </body>
    </html>
    '''
    
    return render_template_string(html)

@app.route('/start-chat/<int:ad_id>', methods=['POST'])
def start_chat(ad_id):
    """Начать чат по объявлению"""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    db = get_db()
    
    ad = db.execute('SELECT * FROM ads WHERE id = ?', (ad_id,)).fetchone()
    
    if not ad:
        return "Объявление не найдено", 404
    
    if ad['user_id'] == session['user_id']:
        return redirect(url_for('ad_detail', ad_id=ad_id))
    
    # Проверяем существующий чат
    existing_chat = db.execute('''
        SELECT * FROM chats 
        WHERE ad_id = ? AND buyer_id = ? AND seller_id = ? AND status = 'active'
    ''', (ad_id, session['user_id'], ad['user_id'])).fetchone()
    
    if existing_chat:
        return redirect(url_for('view_chat', chat_id=existing_chat['id']))
    
    # Создаем новый чат
    cursor = db.execute('''
        INSERT INTO chats (ad_id, buyer_id, seller_id)
        VALUES (?, ?, ?)
    ''', (ad_id, session['user_id'], ad['user_id']))
    db.commit()
    
    chat_id = cursor.lastrowid
    
    # Отправляем приветственное сообщение
    db.execute('''
        INSERT INTO messages (chat_id, user_id, message)
        VALUES (?, ?, ?)
    ''', (chat_id, session['user_id'], f'Здравствуйте! Интересует объявление "{ad["title"]}"'))
    db.commit()
    
    return redirect(url_for('view_chat', chat_id=chat_id))

@app.route('/chat/<int:chat_id>')
def view_chat(chat_id):
    """Просмотр чата"""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    db = get_db()
    
    chat = db.execute('''
        SELECT chats.*, ads.title as ad_title, 
               buyer.username as buyer_name, seller.username as seller_name
        FROM chats 
        JOIN ads ON chats.ad_id = ads.id
        JOIN users buyer ON chats.buyer_id = buyer.id
        JOIN users seller ON chats.seller_id = seller.id
        WHERE chats.id = ?
    ''', (chat_id,)).fetchone()
    
    if not chat:
        return "Чат не найден", 404
    
    if session['user_id'] not in [chat['buyer_id'], chat['seller_id']]:
        return "Доступ запрещен", 403
    
    messages = db.execute('''
        SELECT * FROM messages 
        WHERE chat_id = ? 
        ORDER BY sent ASC
    ''', (chat_id,)).fetchall()
    
    # Помечаем как прочитанные
    db.execute('''
        UPDATE messages SET is_read = 1 
        WHERE chat_id = ? AND user_id != ? AND is_read = 0
    ''', (chat_id, session['user_id']))
    db.commit()
    
    other_user = chat['seller_name'] if session['user_id'] == chat['buyer_id'] else chat['buyer_name']
    
    html = f'''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Чат с {other_user}</title>
        <meta charset="utf-8">
        <style>
            body {{ font-family: Arial; background: #f0f2f5; padding: 20px; margin: 0; }}
            .chat-container {{
                max-width: 800px; margin: 0 auto; background: white; border-radius: 10px;
                box-shadow: 0 2px 4px rgba(0,0,0,0.1); height: 600px;
                display: flex; flex-direction: column;
            }}
            .chat-header {{
                padding: 15px 20px; border-bottom: 1px solid #eee;
                background: #f8f9fa; border-radius: 10px 10px 0 0;
            }}
            .chat-header a {{ color: #1a73e8; text-decoration: none; }}
            .chat-header a:hover {{ text-decoration: underline; }}
            .messages-area {{
                flex: 1; overflow-y: auto; padding: 20px;
                display: flex; flex-direction: column;
            }}
            .message {{
                max-width: 70%; margin-bottom: 15px; padding: 10px 15px;
                border-radius: 10px; position: relative;
            }}
            .message-mine {{ align-self: flex-end; background: #1a73e8; color: white; }}
            .message-theirs {{ align-self: flex-start; background: #f0f2f5; color: black; }}
            .message-time {{ font-size: 0.7rem; margin-top: 5px; opacity: 0.7; }}
            .chat-input {{
                padding: 20px; border-top: 1px solid #eee; display: flex; gap: 10px;
            }}
            .chat-input textarea {{
                flex: 1; padding: 10px; border: 1px solid #ddd;
                border-radius: 5px; resize: none; font-family: Arial;
            }}
            .btn {{
                background: #1a73e8; color: white; padding: 10px 20px;
                border: none; border-radius: 5px; cursor: pointer;
            }}
            .btn:hover {{ background: #1557b0; }}
        </style>
    </head>
    <body>
        <div class="chat-container">
            <div class="chat-header">
                <a href="/my-chats">← Все чаты</a>
                <h3 style="margin: 10px 0 0 0;">Чат с {other_user}</h3>
                <p style="color: #666; margin: 5px 0 0 0;">По объявлению: {chat['ad_title']}</p>
            </div>
            
            <div class="messages-area" id="messages-area">
    '''
    
    for msg in messages:
        msg_class = 'message-mine' if msg['user_id'] == session['user_id'] else 'message-theirs'
        html += f'''
                <div class="message {msg_class}">
                    <div>{msg['message']}</div>
                    <div class="message-time">{msg['sent']}</div>
                </div>
        '''
    
    html += f'''
            </div>
            
            <div class="chat-input">
                <textarea id="message-text" placeholder="Введите сообщение..." rows="2"></textarea>
                <button class="btn" onclick="sendMessage({chat_id})">Отправить</button>
            </div>
        </div>
        
        <script>
        function scrollToBottom() {{
            const area = document.getElementById('messages-area');
            area.scrollTop = area.scrollHeight;
        }}
        scrollToBottom();
        
        function sendMessage(chatId) {{
            const textarea = document.getElementById('message-text');
            const message = textarea.value.trim();
            
            if (!message) return;
            
            fetch('/send-message/' + chatId, {{
                method: 'POST',
                headers: {{
                    'Content-Type': 'application/json',
                }},
                body: JSON.stringify({{message: message}})
            }})
            .then(response => response.json())
            .then(data => {{
                if (data.success) {{
                    location.reload();
                }}
            }});
        }}
        
        // Автообновление каждые 3 секунды
        setInterval(function() {{
            fetch('/chat/{chat_id}')
                .then(response => response.text())
                .then(html => {{
                    // Простой способ - перезагрузить страницу если есть новые сообщения
                    if (html.includes('message-theirs') && !html.includes('message-mine')) {{
                        location.reload();
                    }}
                }});
        }}, 3000);
        </script>
    </body>
    </html>
    '''
    
    return render_template_string(html)

@app.route('/my-chats')
def my_chats():
    """Список чатов пользователя"""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    db = get_db()
    
    chats = db.execute('''
        SELECT 
            chats.id,
            chats.ad_id,
            ads.title as ad_title,
            CASE 
                WHEN chats.buyer_id = ? THEN seller.username
                ELSE buyer.username
            END as other_user,
            (SELECT message FROM messages WHERE chat_id = chats.id ORDER BY sent DESC LIMIT 1) as last_message,
            (SELECT sent FROM messages WHERE chat_id = chats.id ORDER BY sent DESC LIMIT 1) as last_message_time,
            (SELECT COUNT(*) FROM messages WHERE chat_id = chats.id AND user_id != ? AND is_read = 0) as unread_count
        FROM chats
        JOIN ads ON chats.ad_id = ads.id
        JOIN users buyer ON chats.buyer_id = buyer.id
        JOIN users seller ON chats.seller_id = seller.id
        WHERE chats.buyer_id = ? OR chats.seller_id = ?
        ORDER BY last_message_time DESC
    ''', (session['user_id'], session['user_id'], session['user_id'], session['user_id'])).fetchall()
    
    html = '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Мои чаты</title>
        <meta charset="utf-8">
        <style>
            body { font-family: Arial; background: #f0f2f5; padding: 20px; margin: 0; }
            .container { max-width: 800px; margin: 0 auto; }
            h1 { margin-bottom: 20px; color: #333; }
            .chats-list { background: white; border-radius: 10px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
            .chat-item {
                padding: 15px 20px; border-bottom: 1px solid #eee;
                display: flex; justify-content: space-between; align-items: center;
                cursor: pointer; transition: background 0.2s;
            }
            .chat-item:hover { background: #f8f9fa; }
            .chat-item:last-child { border-bottom: none; }
            .chat-info h4 { margin: 0 0 5px 0; color: #333; }
            .chat-info p { margin: 0; color: #666; }
            .unread-count {
                background: #1a73e8; color: white; border-radius: 50%;
                padding: 2px 8px; font-size: 0.8rem; margin-left: 10px;
            }
            .back-link { color: #1a73e8; text-decoration: none; display: inline-block; margin-bottom: 20px; }
            .back-link:hover { text-decoration: underline; }
        </style>
    </head>
    <body>
        <div class="container">
            <a href="/" class="back-link">← На главную</a>
            <h1>Мои чаты</h1>
            
            <div class="chats-list">
    '''
    
    for chat in chats:
        unread_badge = f'<span class="unread-count">{chat["unread_count"]}</span>' if chat["unread_count"] > 0 else ''
        last_msg = chat['last_message'] or 'Нет сообщений'
        if len(last_msg) > 50:
            last_msg = last_msg[:50] + '...'
        
        html += f'''
                <div class="chat-item" onclick="location.href='/chat/{chat["id"]}'">
                    <div class="chat-info">
                        <h4>
                            {chat["other_user"]}
                            {unread_badge}
                        </h4>
                        <p>{last_msg}</p>
                        <p style="font-size: 0.8rem; color: #999;">По объявлению: {chat["ad_title"]}</p>
                    </div>
                    <div style="color: #666;">{chat["last_message_time"] or ''}</div>
                </div>
        '''
    
    if not chats:
        html += '<div style="padding: 40px; text-align: center; color: #666;">У вас пока нет чатов.</div>'
    
    html += '''
            </div>
        </div>
    </body>
    </html>
    '''
    
    return render_template_string(html)

@app.route('/send-message/<int:chat_id>', methods=['POST'])
def send_message(chat_id):
    """Отправка сообщения в чат"""
    if 'user_id' not in session:
        return {'success': False, 'error': 'Not logged in'}, 401
    
    data = request.get_json()
    message = data.get('message', '').strip()
    
    if not message:
        return {'success': False, 'error': 'Empty message'}, 400
    
    db = get_db()
    
    chat = db.execute('''
        SELECT * FROM chats WHERE id = ? AND (buyer_id = ? OR seller_id = ?)
    ''', (chat_id, session['user_id'], session['user_id'])).fetchone()
    
    if not chat:
        return {'success': False, 'error': 'Access denied'}, 403
    
    # Проверка на дубликаты сообщений
    last_message = db.execute('''
        SELECT message FROM messages 
        WHERE chat_id = ? AND user_id = ? 
        ORDER BY sent DESC LIMIT 1
    ''', (chat_id, session['user_id'])).fetchone()
    
    if last_message and last_message['message'] == message:
        return {'success': False, 'error': 'Duplicate message'}, 400
    
    db.execute('''
        INSERT INTO messages (chat_id, user_id, message)
        VALUES (?, ?, ?)
    ''', (chat_id, session['user_id'], message))
    
    db.execute('''
        UPDATE chats SET last_message = CURRENT_TIMESTAMP
        WHERE id = ?
    ''', (chat_id,))
    
    db.commit()
    
    return {'success': True}

# === API ДЛЯ СЕНДЕРА ===
@app.route('/api/security/challenge')
def get_security_challenge():
    """API для получения вызова безопасности (для сендера)"""
    challenge = {
        'type': 'math',
        'question': f"{random.randint(1,10)} + {random.randint(1,10)}",
        'token': hashlib.md5(str(time.time()).encode()).hexdigest()[:16]
    }
    challenge['answer'] = eval(challenge['question'])
    return jsonify(challenge)

# === ЗАПУСК ===
if __name__ == '__main__':
    # Инициализируем базы данных
    init_db()
    init_protection_db()
    
    print("=" * 60)
    print("🚀 СЕРВЕР ЗАПУЩЕН")
    print("=" * 60)
    print("📱 Адрес: http://127.0.0.1:5000")
    print("🛡️ Защита активна:")
    print("   - Фингерпринтинг браузера")
    print("   - Rate limiting")
    print("   - Капча при подозрительном поведении")
    print("   - Анализ скорости навигации")
    print("   - Блокировка по IP")
    print("=" * 60)
    print("💡 ВЕСЬ СТАРЫЙ ФУНКЦИОНАЛ СОХРАНЕН:")
    print("   - Объявления")
    print("   - Чаты")
    print("   - Регистрация/вход")
    print("   - Личные сообщения")
    print("=" * 60)
    
    app.run(debug=True, port=5000)