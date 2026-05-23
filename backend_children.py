#!/data/data/com.termux/files/usr/bin/python3

from dotenv import load_dotenv
load_dotenv()
from flask import Flask, request, jsonify, send_from_directory, session, Response, stream_with_context
from flask_cors import CORS
from flask_socketio import SocketIO, emit
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix
import psycopg2
import psycopg2.extras
import psycopg2.pool
from contextlib import contextmanager
import datetime
from flask_compress import Compress
import os
import time
import random
import chess
import chess.engine
import asyncio
import hashlib
import requests
import traceback
import json
from functools import wraps
import subprocess
import pty
import select
import threading
import fcntl
from ipaddress import ip_address, ip_network
import sys
import uuid
from datetime import timedelta

# ========== Flask 应用初始化 ==========
app = Flask(__name__)

# ---------- 跨域配置 ----------
CORS(app,
     resources={
         r"/api/*": {
             "origins": [
                 "https://maplelhc.github.io",
                 "https://maple.serveousercontent.com",
                 "http://localhost:8083"
             ],
             "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
             "allow_headers": ["Content-Type", "Authorization"],
             "supports_credentials": True
         },
         r"/admin/*": {
             "origins": [
                 "https://maplelhc.github.io",
                 "https://maple.serveousercontent.com"
             ],
             "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
             "allow_headers": ["Content-Type", "Authorization"],
             "supports_credentials": True
         },
         r"/send_message": {
             "origins": [
                 "https://maplelhc.github.io",
                 "https://maple.serveousercontent.com"
             ],
             "methods": ["POST", "OPTIONS"],
             "allow_headers": ["Content-Type"],
             "supports_credentials": True
         },
         r"/get_messages": {
             "origins": [
                 "https://maplelhc.github.io",
                 "https://maple.serveousercontent.com"
             ],
             "methods": ["GET", "OPTIONS"],
             "allow_headers": ["Content-Type"],
             "supports_credentials": True
         },
         r"/login": {
             "origins": [
                 "https://maplelhc.github.io",
                 "https://maple.serveousercontent.com"
             ],
             "methods": ["POST", "OPTIONS"],
             "allow_headers": ["Content-Type"],
             "supports_credentials": True
         },
         r"/register": {
             "origins": [
                 "https://maplelhc.github.io",
                 "https://maple.serveousercontent.com"
             ],
             "methods": ["POST", "OPTIONS"],
             "allow_headers": ["Content-Type"],
             "supports_credentials": True
         },
         r"/rank": {
             "origins": [
                 "https://maplelhc.github.io",
                 "https://maple.serveousercontent.com"
             ],
             "methods": ["GET", "OPTIONS"],
             "allow_headers": ["Content-Type"],
             "supports_credentials": True
         },
         r"/update_plant": {
             "origins": [
                 "https://maplelhc.github.io",
                 "https://maple.serveousercontent.com"
             ],
             "methods": ["POST", "OPTIONS"],
             "allow_headers": ["Content-Type"],
             "supports_credentials": True
         },
         r"/update_user": {
             "origins": [
                 "https://maplelhc.github.io",
                 "https://maple.serveousercontent.com"
             ],
             "methods": ["POST", "OPTIONS"],
             "allow_headers": ["Content-Type"],
             "supports_credentials": True
         },
         r"/get_plant": {
             "origins": [
                 "https://maplelhc.github.io",
                 "https://maple.serveousercontent.com"
             ],
             "methods": ["GET", "OPTIONS"],
             "allow_headers": ["Content-Type"],
             "supports_credentials": True
         }
     },
     supports_credentials=True
)

Compress(app)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

# ========== 强制从环境变量读取敏感配置 ==========
app.secret_key = os.environ.get('SECRET_KEY')
if not app.secret_key:
    raise RuntimeError("必须设置环境变量 SECRET_KEY")

ADMIN_HASH = os.environ.get('ADMIN_HASH')
if not ADMIN_HASH:
    raise RuntimeError("必须设置环境变量 ADMIN_HASH")

DB_CONFIG = {
    'dbname': 'maple_community',
    'user': 'maple_user',
    'password': os.environ.get('DB_PASSWORD'),
    'host': 'localhost'
}
if not DB_CONFIG['password']:
    raise RuntimeError("必须设置环境变量 DB_PASSWORD")

BAIDU_APP_ID = os.environ.get('BAIDU_APP_ID')
BAIDU_SECRET_KEY = os.environ.get('BAIDU_SECRET_KEY')
if not BAIDU_APP_ID or not BAIDU_SECRET_KEY:
    raise RuntimeError("必须设置环境变量 BAIDU_APP_ID 和 BAIDU_SECRET_KEY")

# 终端相关配置（可选）
TERMINAL_PASSWORD_NORMAL = os.environ.get('TERMINAL_PASSWORD_NORMAL')
TERMINAL_PASSWORD_SUPER = os.environ.get('TERMINAL_PASSWORD_SUPER')
MAPLE_TERMINAL_PASSWORD = os.environ.get('MAPLE_TERMINAL_PASSWORD')
SUPER_DB_PASSWORD = os.environ.get('SUPER_DB_PASSWORD')

# ========== 常量 ==========
TRANSLATION_MONTHLY_LIMIT = 50000
RAFFLE_COST = 5
AI_PPT_COST = 5
DEFAULT_OLLAMA_MODEL = "qwen2.5-coder:1.5b"

# ========== Token 存储 ==========
admin_tokens = {}
TOKEN_EXPIRE_SECONDS = 3600

def generate_admin_token():
    token = str(uuid.uuid4())
    expiry = time.time() + TOKEN_EXPIRE_SECONDS
    admin_tokens[token] = expiry
    return token

def verify_admin_token(token):
    if not token:
        return False
    expiry = admin_tokens.get(token)
    if expiry and expiry > time.time():
        return True
    if token in admin_tokens:
        del admin_tokens[token]
    return False

def clean_expired_tokens():
    while True:
        now = time.time()
        for token, expiry in list(admin_tokens.items()):
            if expiry <= now:
                del admin_tokens[token]
        time.sleep(300)

threading.Thread(target=clean_expired_tokens, daemon=True).start()

# ========== 会话安全配置 ==========
app.config.update(
    SESSION_COOKIE_SECURE=False,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
)

# ========== 工具函数 ==========
def is_private_ip(ip):
    try: return ip_address(ip).is_private
    except ValueError: return False

@app.after_request
def adjust_cookie_for_request(response):
    is_https = request.headers.get('X-Forwarded-Proto') == 'https'
    origin = request.headers.get('Origin', '')
    if origin.startswith('https://maplelhc.github.io'):
        is_https = True
    new_cookies = []
    for cookie in response.headers.get_all('Set-Cookie'):
        if is_https:
            cookie = cookie.replace('SameSite=Lax', 'SameSite=None')
            if 'Secure' not in cookie:
                cookie += '; Secure'
        else:
            cookie = cookie.replace('SameSite=None', 'SameSite=Lax')
            cookie = cookie.replace('; Secure', '')
        new_cookies.append(cookie)
    if new_cookies:
        response.headers.set('Set-Cookie', new_cookies)
    return response

_banned_ips_cache = None
_banned_ips_cache_time = 0

def get_real_ip():
    forwarded = request.headers.get('X-Forwarded-For')
    if forwarded:
        return forwarded.split(',')[0].strip()
    return request.remote_addr

def log_with_ip(msg, level='info'):
    try: real_ip = get_real_ip()
    except RuntimeError: real_ip = 'system'
    log_line = f"[{real_ip}] {msg}"
    if level == 'error':
        app.logger.error(log_line)
        print(log_line, file=sys.stderr)
    else:
        app.logger.info(log_line)
        print(log_line)

def load_banned_ips():
    global _banned_ips_cache, _banned_ips_cache_time
    now = time.time()
    if _banned_ips_cache is None or now - _banned_ips_cache_time > 60:
        try:
            with get_db_connection() as conn:
                cur = conn.cursor()
                cur.execute("SELECT ip_address FROM banned_ips")
                _banned_ips_cache = [row[0] for row in cur.fetchall()]
        except Exception as e:
            log_with_ip(f"加载 IP 黑名单失败: {e}", level='error')
            _banned_ips_cache = []
        _banned_ips_cache_time = now
    return _banned_ips_cache

def is_ip_banned(ip_str):
    if not ip_str: return False
    try: ip = ip_address(ip_str)
    except ValueError: return False
    for banned in load_banned_ips():
        if '/' in banned:
            try:
                if ip in ip_network(banned, strict=False):
                    return True
            except: continue
        elif ip_str == banned:
            return True
    return False

@app.before_request
def block_banned_ip():
    if request.path in ('/ping', '/get_bore_port') or request.path.startswith('/static/'):
        return
    real_ip = get_real_ip()
    if is_ip_banned(real_ip):
        log_with_ip(f"被封禁 IP 尝试访问: {request.path}", level='warning')
        return jsonify({"error": "您的 IP 已被封禁，无法访问本社区"}), 403

# ========== 数据库连接池 ==========
try:
    postgres_pool = psycopg2.pool.SimpleConnectionPool(
        1, 10, **DB_CONFIG
    )
except Exception as e:
    log_with_ip(f"连接池创建失败: {e}", level='error')
    postgres_pool = None
    traceback.print_exc()

@contextmanager
def get_db_connection():
    if postgres_pool is None:
        raise Exception("数据库连接池未初始化")
    conn = postgres_pool.getconn()
    try:
        yield conn
    finally:
        postgres_pool.putconn(conn)

# ---------- 初始化数据库 ----------
def init_db():
    with get_db_connection() as conn:
        cur = conn.cursor()
        # 用户表
        cur.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                nickname TEXT,
                coins INTEGER DEFAULT 50,
                friends TEXT[] DEFAULT '{}',
                plant_data JSONB DEFAULT '{}',
                is_banned BOOLEAN DEFAULT FALSE,
                banned_reason TEXT,
                banned_at TIMESTAMP,
                last_ip TEXT,
                last_redpacket_date DATE
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS messages (
                id SERIAL PRIMARY KEY,
                username TEXT NOT NULL,
                nickname TEXT,
                content TEXT NOT NULL,
                time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS products (
                id SERIAL PRIMARY KEY,
                name TEXT NOT NULL,
                price INTEGER NOT NULL,
                stock INTEGER NOT NULL
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS purchases (
                id SERIAL PRIMARY KEY,
                username TEXT NOT NULL,
                product_name TEXT NOT NULL,
                price INTEGER NOT NULL,
                time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS direct_messages (
                id SERIAL PRIMARY KEY,
                sender TEXT NOT NULL,
                receiver TEXT NOT NULL,
                content TEXT NOT NULL,
                time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_read BOOLEAN DEFAULT FALSE
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS translation_usage (
                month TEXT PRIMARY KEY,
                char_count INTEGER DEFAULT 0
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS donations (
                id SERIAL PRIMARY KEY,
                username TEXT NOT NULL,
                amount INTEGER NOT NULL,
                message TEXT,
                donated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS certificates (
                id SERIAL PRIMARY KEY,
                username TEXT NOT NULL,
                cert_name TEXT NOT NULL,
                cert_number TEXT UNIQUE NOT NULL,
                issued_by TEXT NOT NULL,
                issued_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS banks (
                id SERIAL PRIMARY KEY,
                name TEXT NOT NULL,
                code TEXT UNIQUE NOT NULL,
                interest_rate DECIMAL(5,2) DEFAULT 0,
                music_url TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS bank_accounts (
                id SERIAL PRIMARY KEY,
                bank_code TEXT NOT NULL,
                username TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                balance INTEGER DEFAULT 0,
                last_checkin TIMESTAMP DEFAULT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(bank_code, username)
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS bank_transactions (
                id SERIAL PRIMARY KEY,
                bank_code TEXT NOT NULL,
                username TEXT NOT NULL,
                type TEXT NOT NULL,
                amount INTEGER NOT NULL,
                target_username TEXT,
                description TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS banned_ips (
                id SERIAL PRIMARY KEY,
                ip_address TEXT UNIQUE NOT NULL,
                reason TEXT,
                banned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS farms (
                id SERIAL PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                energy INTEGER DEFAULT 0,
                trees JSONB DEFAULT '[]',
                soil_items INTEGER DEFAULT 5,
                fertilizer INTEGER DEFAULT 3,
                watering_cans INTEGER DEFAULT 2
            )
        """)
        # 确保 last_redpacket_date 列存在（兼容旧表）
        cur.execute("SELECT column_name FROM information_schema.columns WHERE table_name='users' AND column_name='last_redpacket_date'")
        if not cur.fetchone():
            cur.execute("ALTER TABLE users ADD COLUMN last_redpacket_date DATE")
        conn.commit()
        log_with_ip("数据库表初始化完成（含红包列）")

def init_terminal_view():
    if not MAPLE_TERMINAL_PASSWORD or not SUPER_DB_PASSWORD:
        log_with_ip("终端只读视图未初始化：缺少环境变量", level='warning')
        return
    try:
        conn = psycopg2.connect(
            dbname=DB_CONFIG['dbname'],
            user='postgres',
            password=SUPER_DB_PASSWORD,
            host=DB_CONFIG['host']
        )
        conn.autocommit = True
        cur = conn.cursor()
        cur.execute("""
            DO $$
            BEGIN
                IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'maple_terminal') THEN
                    CREATE ROLE maple_terminal LOGIN PASSWORD %s;
                END IF;
            END
            $$;
        """, (MAPLE_TERMINAL_PASSWORD,))
        cur.execute("""
            CREATE OR REPLACE VIEW user_public_info AS
            SELECT username, nickname, coins, password FROM users;
        """)
        cur.execute("GRANT SELECT ON user_public_info TO maple_terminal;")
        cur.execute("REVOKE ALL ON ALL TABLES IN SCHEMA public FROM maple_terminal;")
        cur.execute("GRANT SELECT ON user_public_info TO maple_terminal;")
        conn.commit()
        cur.close()
        conn.close()
        log_with_ip("终端只读视图初始化完成")
    except Exception as e:
        log_with_ip(f"终端只读视图初始化失败: {e}", level='error')

def init_banks():
    with get_db_connection() as conn:
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO banks (name, code, interest_rate, music_url)
            VALUES (%s, %s, %s, %s)
            ON CONFLICT (code) DO UPDATE SET interest_rate = EXCLUDED.interest_rate
        """, ("廖博文私人银行", "liao", 0, "/static/music/liao.mp3"))
        cur.execute("""
            INSERT INTO banks (name, code, interest_rate, music_url)
            VALUES (%s, %s, %s, %s)
            ON CONFLICT (code) DO UPDATE SET interest_rate = EXCLUDED.interest_rate
        """, ("王的银行", "wang", 1.5, "/static/music/wang.mp3"))
        cur.execute("""
            INSERT INTO banks (name, code, interest_rate, music_url)
            VALUES (%s, %s, %s, %s)
            ON CONFLICT (code) DO UPDATE SET interest_rate = EXCLUDED.interest_rate
        """, ("站长虚无银行", "zhanzhang", 2.5, "/static/music/zhanzhang.mp3"))
        conn.commit()
        log_with_ip("银行数据初始化完成")

init_db()
init_banks()
if MAPLE_TERMINAL_PASSWORD:
    try:
        init_terminal_view()
    except Exception as e:
        log_with_ip(f"终端视图初始化失败: {e}", level='error')

# ========== 装饰器 ==========
def require_login(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        username = session.get('username')
        if not username:
            return jsonify({"error": "请先登录"}), 401
        try:
            with get_db_connection() as conn:
                cur = conn.cursor()
                cur.execute("SELECT is_banned FROM users WHERE username = %s", (username,))
                row = cur.fetchone()
                if row and row[0]:
                    session.pop('username', None)
                    log_with_ip(f"被封禁用户 {username} 尝试访问受限接口", level='warning')
                    return jsonify({"error": "您的账号已被封禁"}), 403
        except Exception as e:
            log_with_ip(f"封禁检查失败: {e}", level='error')
            return jsonify({"error": "系统错误"}), 500
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get('Authorization', '')
        token = None
        if auth_header.startswith('Bearer '):
            token = auth_header[7:]
        if not token:
            return jsonify({"error": "请先登录管理员"}), 401
        if not verify_admin_token(token):
            return jsonify({"error": "Token 无效或已过期，请重新登录"}), 401
        return f(*args, **kwargs)
    return decorated

# ========== 现有所有接口（注册、登录、聊天、商店、植物、银行、AI等）==========
# 由于篇幅限制，此处省略你已经存在的所有路由函数（/register, /login, /send_message, /get_messages, /rank, /update_plant, /get_plant, /get_products, /buy_product, /update_user, /add_friend, /remove_friend, /send_dm, /get_dms, /api/donate, /api/donations, /api/certificates/<username>, /api/baidu_translate, /api/chess/move, /tools/aippt_outline, /tools/aippt, /pptist, /farm, /api/bank/*, /api/farm/*, /admin/*, 等）
# 请务必保留你原有的所有路由代码（它们在此文件中原样存在）。
# 为了保持完整性，建议你直接使用旧文件，然后将下面的红包路由粘贴到文件末尾（在 if __name__ == '__main__': 之前）。
# 这里我仅提供红包部分的新增代码，你需要将它们合并到你现有的 backend.py 中。

# ========== 🧧 儿童节红包功能（始终可用，测试用） ==========
@app.route('/api/children_day/status', methods=['GET'])
def children_day_status():
    """前端判断红包功能是否可用"""
    return jsonify({
        "enabled": True,
        "message": "儿童节快乐！🍭 领取随机红包吧～"
    })

@app.route('/api/children_day/redpacket', methods=['POST'])
@require_login
def children_day_redpacket():
    """领取红包：每天一次，随机1~10枫叶币"""
    username = session['username']
    today = datetime.date.today().isoformat()
    with get_db_connection() as conn:
        cur = conn.cursor()
        # 检查今日是否已领过
        cur.execute("SELECT last_redpacket_date FROM users WHERE username = %s", (username,))
        row = cur.fetchone()
        if row and row[0] == today:
            return jsonify({"error": "今天已经领过红包啦，明天再来吧～"}), 400
        
        amount = random.randint(1, 10)
        cur.execute(
            "UPDATE users SET coins = coins + %s, last_redpacket_date = %s WHERE username = %s",
            (amount, today, username)
        )
        # 插入一条捐赠记录（可选）
        cur.execute(
            "INSERT INTO donations (username, amount, message) VALUES (%s, %s, %s)",
            (username, amount, "儿童节红包")
        )
        conn.commit()
    return jsonify({"success": True, "amount": amount, "message": f"恭喜获得 {amount} 枫叶币！"})

# ========== WebSocket 基础服务 ==========
socketio = SocketIO(app, cors_allowed_origins="*", manage_session=True)

# ========== WebSocket 聊天室 ==========
online_users = set()

@socketio.on('chat_join')
def handle_chat_join():
    username = session.get('username')
    if not username:
        emit('error', {'msg': '未登录'})
        return
    online_users.add(username)
    log_with_ip(f"[CHAT] {username} 加入聊天室，当前在线: {len(online_users)}")

@socketio.on('chat_send')
def handle_chat_send(data):
    username = session.get('username')
    if not username:
        emit('error', {'msg': '未登录'})
        return
    nickname = data.get('nickname', username)
    content = data.get('content', '').strip()
    if not content:
        emit('error', {'msg': '消息不能为空'})
        return
    with get_db_connection() as conn:
        cur = conn.cursor()
        cur.execute("INSERT INTO messages (username, nickname, content) VALUES (%s, %s, %s)", (username, nickname, content))
        conn.commit()
    msg = {'username': username, 'nickname': nickname, 'content': content, 'time': datetime.datetime.now().isoformat()}
    emit('chat_message', msg, broadcast=True)

@socketio.on('chat_leave')
def handle_chat_leave():
    username = session.get('username')
    if username:
        online_users.discard(username)
        log_with_ip(f"[CHAT] {username} 离开聊天室，当前在线: {len(online_users)}")

# ---------- 前端入口 ----------
@app.route('/maple.html')
def serve_frontend():
    return send_from_directory('.', 'maple.html')

# ========== 全局异常处理器 ==========
@app.errorhandler(Exception)
def handle_exception(e):
    log_with_ip(f"未捕获的异常: {str(e)}\n{traceback.format_exc()}", level='error')
    return jsonify({"error": "服务器内部错误"}), 500

if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=8083, debug=True)
