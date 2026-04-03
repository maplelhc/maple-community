#!/data/data/com.termux/files/usr/bin/python3

from dotenv import load_dotenv
load_dotenv()
from flask import Flask, request, jsonify, send_from_directory, session, Response, stream_with_context
from flask_cors import CORS
from flask_socketio import SocketIO, emit
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix   # 新增
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

# ========== Flask 应用初始化 ==========
app = Flask(__name__)
CORS(app, supports_credentials=True)
Compress(app)

# 添加 ProxyFix 中间件，让 Flask 识别 X-Forwarded-Proto
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

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

# 终端相关配置（可选，缺失时终端功能不可用）
TERMINAL_PASSWORD_NORMAL = os.environ.get('TERMINAL_PASSWORD_NORMAL')
TERMINAL_PASSWORD_SUPER = os.environ.get('TERMINAL_PASSWORD_SUPER')
MAPLE_TERMINAL_PASSWORD = os.environ.get('MAPLE_TERMINAL_PASSWORD')
SUPER_DB_PASSWORD = os.environ.get('SUPER_DB_PASSWORD')

# ========== 常量定义 ==========
TRANSLATION_MONTHLY_LIMIT = 50000
RAFFLE_COST = 5
AI_PPT_COST = 5
DEFAULT_OLLAMA_MODEL = "qwen2.5-coder:1.5b"

# ========== 会话安全配置（基础 Secure=False，动态添加）==========
app.config.update(
    SESSION_COOKIE_SECURE=False,      # 基础设为 False，由 after_request 动态添加
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
)

# ========== 动态添加 Secure 标志（如果请求来自 HTTPS 代理）==========
@app.after_request
def add_secure_cookie_for_https(response):
    if request.headers.get('X-Forwarded-Proto') == 'https':
        # 遍历所有 Set-Cookie 头，添加 Secure 标志
        new_cookies = []
        for cookie in response.headers.get_all('Set-Cookie'):
            if 'Secure' not in cookie:
                cookie += '; Secure'
            new_cookies.append(cookie)
        if new_cookies:
            response.headers.set('Set-Cookie', new_cookies)
    return response

# ========== 数据库连接池 ==========
try:
    postgres_pool = psycopg2.pool.SimpleConnectionPool(
        1, 10,
        dbname=DB_CONFIG['dbname'],
        user=DB_CONFIG['user'],
        password=DB_CONFIG['password'],
        host=DB_CONFIG['host']
    )
except Exception as e:
    print("连接池创建失败:", e)
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

# ---------- 初始化数据库（不含邮箱字段）----------
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
                plant_data JSONB DEFAULT '{}'
            )
        """)
        # 公共聊天消息表
        cur.execute("""
            CREATE TABLE IF NOT EXISTS messages (
                id SERIAL PRIMARY KEY,
                username TEXT NOT NULL,
                nickname TEXT,
                content TEXT NOT NULL,
                time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        # 商品表
        cur.execute("""
            CREATE TABLE IF NOT EXISTS products (
                id SERIAL PRIMARY KEY,
                name TEXT NOT NULL,
                price INTEGER NOT NULL,
                stock INTEGER NOT NULL
            )
        """)
        # 购买记录表
        cur.execute("""
            CREATE TABLE IF NOT EXISTS purchases (
                id SERIAL PRIMARY KEY,
                username TEXT NOT NULL,
                product_name TEXT NOT NULL,
                price INTEGER NOT NULL,
                time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        # 私聊消息表
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
        # 翻译使用量统计表
        cur.execute("""
            CREATE TABLE IF NOT EXISTS translation_usage (
                month TEXT PRIMARY KEY,
                char_count INTEGER DEFAULT 0
            )
        """)
        # 捐赠表
        cur.execute("""
            CREATE TABLE IF NOT EXISTS donations (
                id SERIAL PRIMARY KEY,
                username TEXT NOT NULL,
                amount INTEGER NOT NULL,
                message TEXT,
                donated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        # 证书表
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
        # 银行相关表
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

        # 修复缺失列
        cur.execute("SELECT column_name FROM information_schema.columns WHERE table_name='banks'")
        existing_columns = [row[0] for row in cur.fetchall()]
        if 'interest_rate' not in existing_columns:
            cur.execute("ALTER TABLE banks ADD COLUMN interest_rate DECIMAL(5,2) DEFAULT 0")
            print("banks 表添加 interest_rate 列")

        cur.execute("SELECT column_name FROM information_schema.columns WHERE table_name='bank_accounts'")
        existing_account_columns = [row[0] for row in cur.fetchall()]
        if 'last_checkin' not in existing_account_columns:
            cur.execute("ALTER TABLE bank_accounts ADD COLUMN last_checkin TIMESTAMP DEFAULT NULL")
            print("bank_accounts 表添加 last_checkin 列")

        conn.commit()
        print("数据库表初始化完成")

def init_terminal_view():
    """创建终端只读视图（如果不存在）"""
    if not MAPLE_TERMINAL_PASSWORD or not SUPER_DB_PASSWORD:
        print("终端只读视图未初始化：缺少 MAPLE_TERMINAL_PASSWORD 或 SUPER_DB_PASSWORD")
        return

    try:
        conn = psycopg2.connect(
            dbname=DB_CONFIG['dbname'],
            user='u0_a167',
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
            SELECT username, nickname, coins, password
            FROM users;
        """)
        cur.execute("GRANT SELECT ON user_public_info TO maple_terminal;")
        cur.execute("REVOKE ALL ON ALL TABLES IN SCHEMA public FROM maple_terminal;")
        cur.execute("GRANT SELECT ON user_public_info TO maple_terminal;")
        conn.commit()
        cur.close()
        conn.close()
        print("终端只读视图初始化完成")
    except Exception as e:
        print(f"终端只读视图初始化失败: {e}")

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
        print("银行数据初始化完成")

init_db()
init_banks()
if MAPLE_TERMINAL_PASSWORD:
    try:
        init_terminal_view()
    except Exception as e:
        print("终端视图初始化失败，可能是缺少环境变量:", e)

# ========== 辅助函数 ==========
def dict_fetchall(cursor):
    columns = [col[0] for col in cursor.description]
    return [dict(zip(columns, row)) for row in cursor.fetchall()]

def require_login(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('username'):
            return jsonify({"error": "请先登录"}), 401
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('admin_logged_in'):
            return jsonify({"error": "请先登录管理员"}), 401
        return f(*args, **kwargs)
    return decorated

# ========== 管理员登录接口 ==========
@app.route('/admin/login', methods=['POST'])
def admin_login():
    print(f"[LOG] /admin/login 被调用，来自 {request.remote_addr}")
    data = request.json
    print(f"[LOG] 请求数据: {data}")
    password = data.get('password')
    if not password:
        return jsonify({"error": "密码不能为空"}), 400
    if check_password_hash(ADMIN_HASH, password):
        session['admin_logged_in'] = True
        print(f"[LOG] 管理员登录成功")
        return jsonify({"success": True})
    else:
        print(f"[LOG] 管理员登录失败：密码错误")
        return jsonify({"error": "密码错误"}), 401

@app.route('/admin/logout', methods=['POST'])
def admin_logout():
    print(f"[LOG] /admin/logout 被调用，来自 {request.remote_addr}")
    session.pop('admin_logged_in', None)
    return jsonify({"success": True})

@app.route('/admin/status', methods=['GET'])
def admin_status():
    print(f"[LOG] /admin/status 被调用，来自 {request.remote_addr}")
    return jsonify({"logged_in": session.get('admin_logged_in', False)})

# ========== 公共接口 ==========
@app.route('/')
def index():
    print(f"[LOG] / 被调用，来自 {request.remote_addr}")
    return jsonify({"message": "枫叶社区后端 API 运行中"})

@app.route('/ping')
def ping():
    print(f"[LOG] /ping 被调用，来自 {request.remote_addr}")
    return jsonify({"pong": "ok"})

@app.route('/get_bore_port')
def get_bore_port():
    print(f"[LOG] /get_bore_port 被调用，来自 {request.remote_addr}")
    try:
        with open(os.path.expanduser('~/current_bore_port'), 'r') as f:
            port = f.read().strip()
        return jsonify({"port": port})
    except FileNotFoundError:
        return jsonify({"error": "Port file not found"}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/register', methods=['POST'])
def register():
    print(f"[LOG] /register 被调用，来自 {request.remote_addr}")
    data = request.json
    username = data.get('username')
    password = data.get('password')
    nickname = data.get('nickname', username)
    if not username or not password:
        return jsonify({"success": False, "error": "用户名和密码不能为空"})
    try:
        hashed = generate_password_hash(password)
        with get_db_connection() as conn:
            cur = conn.cursor()
            cur.execute(
                "INSERT INTO users (username, password, nickname, coins) VALUES (%s, %s, %s, %s)",
                (username, hashed, nickname, 50)
            )
            conn.commit()
        print(f"[LOG] 用户 {username} 注册成功")
        return jsonify({"success": True})
    except psycopg2.IntegrityError:
        print(f"[LOG] 用户 {username} 注册失败：用户名已存在")
        return jsonify({"success": False, "error": "用户名已存在"})
    except Exception as e:
        print(f"[LOG] 用户 {username} 注册异常: {e}")
        return jsonify({"success": False, "error": str(e)})

@app.route('/login', methods=['POST'])
def login():
    print(f"[LOG] /login 被调用，来自 {request.remote_addr}")
    data = request.json
    username = data.get('username')
    password = data.get('password')
    with get_db_connection() as conn:
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute(
            "SELECT id, username, nickname, coins, plant_data, friends, password FROM users WHERE username=%s",
            (username,)
        )
        user = cur.fetchone()
        if not user:
            print(f"[LOG] 用户 {username} 登录失败：用户不存在")
            return jsonify({"success": False, "error": "用户名或密码错误"})

        stored_pw = user['password']
        if stored_pw.startswith(('scrypt:', 'pbkdf2:', 'bcrypt:')) or len(stored_pw) > 60:
            valid = check_password_hash(stored_pw, password)
        else:
            valid = (stored_pw == password)
            if valid:
                hashed = generate_password_hash(password)
                cur.execute(
                    "UPDATE users SET password = %s WHERE username = %s",
                    (hashed, username)
                )
                conn.commit()

        if valid:
            session['username'] = username
            del user['password']
            print(f"[LOG] 用户 {username} 登录成功")
            return jsonify({"success": True, "user": user})
        else:
            print(f"[LOG] 用户 {username} 登录失败：密码错误")
            return jsonify({"success": False, "error": "用户名或密码错误"})

# ---------- 国际象棋 AI ----------
@app.route('/api/chess/move', methods=['POST'])
def chess_move():
    print(f"[LOG] /api/chess/move 被调用，来自 {request.remote_addr}")
    data = request.json
    fen = data.get('fen')
    difficulty = data.get('difficulty', 8)
    if not fen:
        return jsonify({"error": "Missing fen"}), 400
    try:
        move = get_ai_move_sync(fen, difficulty)
        print(f"[LOG] 国际象棋AI返回: {move}")
        return jsonify({"move": move})
    except Exception as e:
        print(f"[LOG] 国际象棋AI错误: {e}")
        return jsonify({"error": str(e)}), 500

def get_ai_move_sync(fen: str, difficulty: int):
    async def _async_get():
        engine_path = '/data/data/com.termux/files/usr/bin/stockfish'
        transport, engine = await chess.engine.popen_uci(engine_path)
        board = chess.Board(fen)
        skill_level = max(0, min(20, int(difficulty * 20 / 15)))
        await engine.configure({"Skill Level": skill_level})
        limit = chess.engine.Limit(time=0.2)
        result = await engine.play(board, limit)
        await engine.quit()
        move = result.move
        return {"from": move.uci()[:2], "to": move.uci()[2:4]}
    try:
        loop = asyncio.get_event_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
    return loop.run_until_complete(_async_get())

# ---------- 聊天室 ----------
@app.route('/send_message', methods=['POST'])
@require_login
def send_message():
    current_user = session['username']
    print(f"[LOG] /send_message 被调用，来自 {request.remote_addr}，用户 {current_user}")
    data = request.json
    username = data.get('username')
    if username != current_user:
        return jsonify({"success": False, "error": "无权替他人发送消息"}), 403
    nickname = data.get('nickname', username)
    content = data.get('content')
    if not content:
        return jsonify({"success": False, "error": "消息内容不能为空"})
    with get_db_connection() as conn:
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO messages (username, nickname, content) VALUES (%s, %s, %s)",
            (username, nickname, content)
        )
        conn.commit()
    print(f"[LOG] 用户 {username} 发送消息成功")
    return jsonify({"success": True})

@app.route('/get_messages', methods=['GET'])
def get_messages():
    print(f"[LOG] /get_messages 被调用，来自 {request.remote_addr}")
    limit = request.args.get('limit', 20, type=int)
    with get_db_connection() as conn:
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute(
            "SELECT username, nickname, content, time FROM messages ORDER BY time DESC LIMIT %s",
            (limit,)
        )
        messages = cur.fetchall()
        for msg in messages:
            msg['time'] = msg['time'].isoformat() if msg['time'] else None
    return jsonify(messages)

# ---------- 排行榜 ----------
@app.route('/rank', methods=['GET'])
def rank():
    print(f"[LOG] /rank 被调用，来自 {request.remote_addr}")
    with get_db_connection() as conn:
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute("SELECT username, nickname, coins FROM users ORDER BY coins DESC LIMIT 20")
        rank_list = cur.fetchall()
    return jsonify(rank_list)

# ---------- 植物园 ----------
@app.route('/update_plant', methods=['POST'])
@require_login
def update_plant():
    current_user = session['username']
    print(f"[LOG] /update_plant 被调用，来自 {request.remote_addr}，用户 {current_user}")
    data = request.json
    username = data.get('username')
    if username != current_user:
        return jsonify({"success": False, "error": "无权修改他人植物数据"}), 403
    plant_data = data.get('plant_data')
    with get_db_connection() as conn:
        cur = conn.cursor()
        cur.execute(
            "UPDATE users SET plant_data = %s WHERE username = %s",
            (psycopg2.extras.Json(plant_data), username)
        )
        conn.commit()
    print(f"[LOG] 用户 {username} 植物数据更新成功")
    return jsonify({"success": True})

@app.route('/get_plant', methods=['GET'])
def get_plant():
    print(f"[LOG] /get_plant 被调用，来自 {request.remote_addr}")
    username = request.args.get('username')
    with get_db_connection() as conn:
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute("SELECT plant_data FROM users WHERE username = %s", (username,))
        row = cur.fetchone()
        if row:
            return jsonify(row['plant_data'])
        else:
            return jsonify({})

# ---------- 商店 ----------
@app.route('/get_products', methods=['GET'])
def get_products():
    print(f"[LOG] /get_products 被调用，来自 {request.remote_addr}")
    with get_db_connection() as conn:
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute("SELECT id, name, price, stock FROM products")
        products = cur.fetchall()
    return jsonify(products)

@app.route('/buy_product', methods=['POST'])
@require_login
def buy_product():
    current_user = session['username']
    print(f"[LOG] /buy_product 被调用，来自 {request.remote_addr}，用户 {current_user}")
    data = request.json
    username = data.get('username')
    if username != current_user:
        return jsonify({"success": False, "error": "无权替他人购买"}), 403
    product_id = data.get('product_id')
    with get_db_connection() as conn:
        cur = conn.cursor()
        cur.execute("SELECT name, price, stock FROM products WHERE id = %s", (product_id,))
        product = cur.fetchone()
        if not product:
            return jsonify({"success": False, "error": "商品不存在"})
        name, price, stock = product
        if stock <= 0:
            return jsonify({"success": False, "error": "库存不足"})
        cur.execute("SELECT coins FROM users WHERE username = %s", (username,))
        user_coins = cur.fetchone()[0]
        if user_coins < price:
            return jsonify({"success": False, "error": "枫叶币不足"})
        cur.execute("UPDATE users SET coins = coins - %s WHERE username = %s", (price, username))
        cur.execute("UPDATE products SET stock = stock - 1 WHERE id = %s", (product_id,))
        cur.execute(
            "INSERT INTO purchases (username, product_name, price) VALUES (%s, %s, %s)",
            (username, name, price)
        )
        conn.commit()
    print(f"[LOG] 用户 {username} 购买商品 {name} 成功")
    return jsonify({"success": True, "price": price})

@app.route('/update_user', methods=['POST'])
@require_login
def update_user():
    current_user = session['username']
    print(f"[LOG] /update_user 被调用，来自 {request.remote_addr}，用户 {current_user}")
    data = request.json
    username = data.get('username')
    if username != current_user:
        return jsonify({"success": False, "error": "无权修改他人信息"}), 403
    coins = data.get('mapleCoins')
    if coins is not None:
        with get_db_connection() as conn:
            cur = conn.cursor()
            cur.execute("UPDATE users SET coins = %s WHERE username = %s", (coins, username))
            conn.commit()
    return jsonify({"success": True})

# ---------- 好友管理 ----------
@app.route('/add_friend', methods=['POST'])
@require_login
def add_friend():
    current_user = session['username']
    print(f"[LOG] /add_friend 被调用，来自 {request.remote_addr}，用户 {current_user}")
    data = request.json
    username = data.get('username')
    if username != current_user:
        return jsonify({"success": False, "error": "无权替他人添加好友"}), 403
    friend = data.get('friend')
    if not username or not friend:
        return jsonify({"success": False, "error": "缺少参数"})
    if username == friend:
        return jsonify({"success": False, "error": "不能添加自己为好友"})
    with get_db_connection() as conn:
        cur = conn.cursor()
        cur.execute("SELECT 1 FROM users WHERE username = %s", (friend,))
        if not cur.fetchone():
            return jsonify({"success": False, "error": "对方用户不存在"})
        cur.execute(
            "UPDATE users SET friends = array_append(friends, %s) WHERE username = %s AND NOT (%s = ANY(friends))",
            (friend, username, friend)
        )
        conn.commit()
    print(f"[LOG] 用户 {username} 添加好友 {friend} 成功")
    return jsonify({"success": True})

@app.route('/remove_friend', methods=['POST'])
@require_login
def remove_friend():
    current_user = session['username']
    print(f"[LOG] /remove_friend 被调用，来自 {request.remote_addr}，用户 {current_user}")
    data = request.json
    username = data.get('username')
    if username != current_user:
        return jsonify({"success": False, "error": "无权替他人删除好友"}), 403
    friend = data.get('friend')
    if not username or not friend:
        return jsonify({"success": False, "error": "缺少参数"})
    with get_db_connection() as conn:
        cur = conn.cursor()
        cur.execute(
            "UPDATE users SET friends = array_remove(friends, %s) WHERE username = %s",
            (friend, username)
        )
        conn.commit()
    print(f"[LOG] 用户 {username} 删除好友 {friend} 成功")
    return jsonify({"success": True})

# ---------- 私聊 ----------
@app.route('/send_dm', methods=['POST'])
@require_login
def send_dm():
    current_user = session['username']
    print(f"[LOG] /send_dm 被调用，来自 {request.remote_addr}，用户 {current_user}")
    data = request.json
    sender = data.get('sender')
    if sender != current_user:
        return jsonify({"success": False, "error": "无权替他人发送私聊"}), 403
    receiver = data.get('receiver')
    content = data.get('content')
    if not sender or not receiver or not content:
        return jsonify({"success": False, "error": "缺少参数"})
    with get_db_connection() as conn:
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO direct_messages (sender, receiver, content) VALUES (%s, %s, %s)",
            (sender, receiver, content)
        )
        conn.commit()
    print(f"[LOG] 用户 {sender} 发送私聊给 {receiver} 成功")
    return jsonify({"success": True})

@app.route('/get_dms', methods=['GET'])
def get_dms():
    print(f"[LOG] /get_dms 被调用，来自 {request.remote_addr}")
    user1 = request.args.get('user1')
    user2 = request.args.get('user2')
    if not user1 or not user2:
        return jsonify({"success": False, "error": "缺少参数"})
    with get_db_connection() as conn:
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute(
            "SELECT sender, receiver, content, time FROM direct_messages WHERE (sender=%s AND receiver=%s) OR (sender=%s AND receiver=%s) ORDER BY time ASC",
            (user1, user2, user2, user1)
        )
        messages = cur.fetchall()
        for msg in messages:
            msg['time'] = msg['time'].isoformat() if msg['time'] else None
    return jsonify(messages)

# ========== 管理员接口 ==========
@app.route('/admin/users', methods=['GET'])
@admin_required
def admin_users():
    print(f"[LOG] /admin/users 被调用，来自 {request.remote_addr}")
    with get_db_connection() as conn:
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute("SELECT id, username, nickname, coins, plant_data FROM users")
        users = cur.fetchall()
    return jsonify(users)

@app.route('/admin/grant', methods=['POST'])
@admin_required
def admin_grant():
    print(f"[LOG] /admin/grant 被调用，来自 {request.remote_addr}")
    real_ip = request.headers.get('Cf-Connecting-Ip') or request.remote_addr
    data = request.json
    log_entry = {
        'time': datetime.datetime.now().isoformat(),
        'real_ip': real_ip,
        'cloudflare_ip': request.remote_addr,
        'headers': dict(request.headers),
        'data': data
    }
    print("GRANT REQUEST:", json.dumps(log_entry, indent=2))
    with open('grant.log', 'a') as f:
        f.write(json.dumps(log_entry) + '\n')
    if data is None:
        return jsonify({"success": False, "error": "Missing JSON body"}), 400
    username = data.get('username')
    amount = data.get('amount')
    if not username or amount is None:
        return jsonify({"success": False, "error": "Missing parameters"}), 400
    try:
        amount = int(amount)
        if amount <= 0:
            raise ValueError
    except:
        return jsonify({"success": False, "error": "Amount must be a positive integer"}), 400
    with get_db_connection() as conn:
        cur = conn.cursor()
        cur.execute("UPDATE users SET coins = coins + %s WHERE username = %s", (amount, username))
        if cur.rowcount == 0:
            return jsonify({"success": False, "error": "User not found"}), 404
        conn.commit()
    print(f"[LOG] 管理员发放 {amount} 枫叶币给 {username} 成功")
    return jsonify({"success": True, "amount": amount, "username": username})

@app.route('/admin/deduct', methods=['POST'])
@admin_required
def admin_deduct():
    print(f"[LOG] /admin/deduct 被调用，来自 {request.remote_addr}")
    data = request.json
    username = data.get('username')
    amount = data.get('amount')
    if not username or amount is None:
        return jsonify({"success": False, "error": "Missing parameters"})
    with get_db_connection() as conn:
        cur = conn.cursor()
        cur.execute("UPDATE users SET coins = coins - %s WHERE username = %s AND coins >= %s", (amount, username, amount))
        if cur.rowcount == 0:
            return jsonify({"success": False, "error": "Insufficient coins or user not found"})
        conn.commit()
    print(f"[LOG] 管理员扣除 {amount} 枫叶币从 {username} 成功")
    return jsonify({"success": True})

@app.route('/admin/delete', methods=['POST'])
@admin_required
def admin_delete():
    print(f"[LOG] /admin/delete 被调用，来自 {request.remote_addr}")
    data = request.json
    username = data.get('username')
    if not username:
        return jsonify({"success": False, "error": "Missing username"})
    with get_db_connection() as conn:
        cur = conn.cursor()
        try:
            cur.execute("DELETE FROM messages WHERE username = %s", (username,))
            cur.execute("DELETE FROM purchases WHERE username = %s", (username,))
            cur.execute("DELETE FROM direct_messages WHERE sender = %s OR receiver = %s", (username, username))
            cur.execute("DELETE FROM users WHERE username = %s", (username,))
            conn.commit()
            print(f"[LOG] 管理员删除用户 {username} 成功")
            return jsonify({"success": True})
        except Exception as e:
            conn.rollback()
            print(f"[LOG] 删除用户 {username} 失败: {e}")
            return jsonify({"success": False, "error": str(e)})

@app.route('/admin/add_product', methods=['POST'])
@admin_required
def admin_add_product():
    print(f"[LOG] /admin/add_product 被调用，来自 {request.remote_addr}")
    data = request.json
    name = data.get('name')
    price = data.get('price')
    stock = data.get('stock')
    if not name or price is None or stock is None:
        return jsonify({"success": False, "error": "Missing parameters"})
    with get_db_connection() as conn:
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO products (name, price, stock) VALUES (%s, %s, %s)",
            (name, price, stock)
        )
        conn.commit()
    print(f"[LOG] 管理员添加商品 {name} 成功")
    return jsonify({"success": True})

@app.route('/admin/delete_product', methods=['POST'])
@admin_required
def admin_delete_product():
    print(f"[LOG] /admin/delete_product 被调用，来自 {request.remote_addr}")
    data = request.json
    product_id = data.get('product_id')
    if not product_id:
        return jsonify({"success": False, "error": "Missing product_id"})
    with get_db_connection() as conn:
        cur = conn.cursor()
        cur.execute("DELETE FROM products WHERE id = %s", (product_id,))
        conn.commit()
    print(f"[LOG] 管理员删除商品 ID {product_id} 成功")
    return jsonify({"success": True})

@app.route('/admin/issue_certificate', methods=['POST'])
@admin_required
def admin_issue_certificate():
    print(f"[LOG] /admin/issue_certificate 被调用，来自 {request.remote_addr}")
    data = request.json
    username = data.get('username')
    cert_name = data.get('cert_name')
    admin_user = data.get('admin_user')
    if not username or not cert_name or not admin_user:
        return jsonify({"success": False, "error": "缺少参数"}), 400
    cert_number = f"CERT-{int(time.time())}-{random.randint(1000,9999)}"
    with get_db_connection() as conn:
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO certificates (username, cert_name, cert_number, issued_by)
            VALUES (%s, %s, %s, %s)
        """, (username, cert_name, cert_number, admin_user))
        conn.commit()
    print(f"[LOG] 管理员 {admin_user} 为用户 {username} 发放证书 {cert_name}，编号 {cert_number}")
    return jsonify({"success": True, "cert_number": cert_number})

@app.route('/admin/donations', methods=['GET'])
@admin_required
def admin_get_donations():
    print(f"[LOG] /admin/donations 被调用，来自 {request.remote_addr}")
    limit = request.args.get('limit', 50, type=int)
    with get_db_connection() as conn:
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute("""
            SELECT id, username, amount, message, donated_at
            FROM donations
            ORDER BY donated_at DESC
            LIMIT %s
        """, (limit,))
        donations = cur.fetchall()
        for d in donations:
            d['donated_at'] = d['donated_at'].isoformat() if d['donated_at'] else None
    return jsonify(donations)

# ---------- 捐赠 ----------
@app.route('/api/donate', methods=['POST'])
@require_login
def donate():
    current_user = session['username']
    print(f"[LOG] /api/donate 被调用，来自 {request.remote_addr}，用户 {current_user}")
    data = request.json
    username = data.get('username')
    if username != current_user:
        return jsonify({"success": False, "error": "只能捐赠自己的枫叶币"}), 403
    amount = data.get('amount')
    message = data.get('message', '')
    if not username or not amount:
        return jsonify({"success": False, "error": "缺少参数"}), 400
    try:
        amount = int(amount)
        if amount <= 0:
            raise ValueError
    except:
        return jsonify({"success": False, "error": "金额必须为正整数"}), 400
    with get_db_connection() as conn:
        cur = conn.cursor()
        cur.execute("SELECT coins FROM users WHERE username = %s", (username,))
        row = cur.fetchone()
        if not row:
            return jsonify({"success": False, "error": "用户不存在"}), 404
        if row[0] < amount:
            return jsonify({"success": False, "error": "枫叶币不足"}), 400
        cur.execute("UPDATE users SET coins = coins - %s WHERE username = %s", (amount, username))
        cur.execute(
            "INSERT INTO donations (username, amount, message) VALUES (%s, %s, %s)",
            (username, amount, message)
        )
        conn.commit()
    print(f"[LOG] 用户 {username} 捐赠 {amount} 枫叶币成功")
    return jsonify({"success": True})

@app.route('/api/donations', methods=['GET'])
def get_donations():
    print(f"[LOG] /api/donations 被调用，来自 {request.remote_addr}")
    limit = request.args.get('limit', 20, type=int)
    with get_db_connection() as conn:
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute("""
            SELECT username, amount, message, donated_at
            FROM donations
            ORDER BY donated_at DESC
            LIMIT %s
        """, (limit,))
        recent = cur.fetchall()
        for r in recent:
            r['donated_at'] = r['donated_at'].isoformat() if r['donated_at'] else None
        cur.execute("""
            SELECT username, SUM(amount) as total
            FROM donations
            GROUP BY username
            ORDER BY total DESC
            LIMIT 20
        """)
        ranking = cur.fetchall()
        cur.execute("SELECT SUM(amount) as total_funds FROM donations")
        total = cur.fetchone()['total_funds'] or 0
    return jsonify({
        "recent": recent,
        "ranking": ranking,
        "total_funds": total
    })

# ---------- 证书 ----------
@app.route('/api/certificates/<username>', methods=['GET'])
def get_user_certificates(username):
    print(f"[LOG] /api/certificates/{username} 被调用，来自 {request.remote_addr}")
    with get_db_connection() as conn:
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute("""
            SELECT id, cert_name, cert_number, issued_by, issued_at
            FROM certificates
            WHERE username = %s
            ORDER BY issued_at DESC
        """, (username,))
        certs = cur.fetchall()
        for c in certs:
            c['issued_at'] = c['issued_at'].isoformat() if c['issued_at'] else None
    return jsonify(certs)

# ---------- 百度翻译 ----------
def get_month_str():
    return datetime.datetime.now().strftime("%Y%m")

def get_monthly_usage():
    month = get_month_str()
    with get_db_connection() as conn:
        cur = conn.cursor()
        cur.execute("SELECT char_count FROM translation_usage WHERE month = %s", (month,))
        row = cur.fetchone()
        return row[0] if row else 0

def increment_monthly_usage(added):
    month = get_month_str()
    with get_db_connection() as conn:
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO translation_usage (month, char_count)
            VALUES (%s, %s)
            ON CONFLICT (month) DO UPDATE
            SET char_count = translation_usage.char_count + EXCLUDED.char_count
        """, (month, added))
        conn.commit()

@app.route('/api/baidu_translate', methods=['POST'])
def baidu_translate():
    print(f"[LOG] /api/baidu_translate 被调用，来自 {request.remote_addr}")
    data = request.json
    text = data.get('text', '').strip()
    if not text:
        return jsonify({"error": "No text provided"}), 400
    char_len = len(text)
    current_usage = get_monthly_usage()
    if current_usage + char_len > TRANSLATION_MONTHLY_LIMIT - 15:
        return jsonify({
            "error": "本月翻译额度即将用尽，暂停翻译",
            "used": current_usage,
            "limit": TRANSLATION_MONTHLY_LIMIT
        }), 429
    salt = str(random.randint(32768, 65536))
    sign_str = BAIDU_APP_ID + text + salt + BAIDU_SECRET_KEY
    sign = hashlib.md5(sign_str.encode('utf-8')).hexdigest()
    params = {
        'q': text,
        'from': 'zh',
        'to': 'en',
        'appid': BAIDU_APP_ID,
        'salt': salt,
        'sign': sign
    }
    url = 'https://fanyi-api.baidu.com/api/trans/vip/translate'
    try:
        response = requests.get(url, params=params, timeout=5)
        result = response.json()
        if 'trans_result' in result:
            increment_monthly_usage(char_len)
            translated = ''.join([item['dst'] for item in result['trans_result']])
            print(f"[LOG] 翻译成功，字符数 {char_len}")
            return jsonify({"translated": translated})
        else:
            error_msg = result.get('error_msg', '翻译失败')
            print(f"[LOG] 翻译失败: {error_msg}")
            return jsonify({"error": error_msg}), 500
    except Exception as e:
        print(f"[LOG] 翻译异常: {e}")
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500

# ========== 本地 Ollama 模型接口 ==========
OLLAMA_URL = "http://localhost:11434/api/generate"

def call_ollama(prompt, model=DEFAULT_OLLAMA_MODEL, temperature=0.7):
    payload = {
        "model": model,
        "prompt": prompt,
        "stream": False,
        "options": {"temperature": temperature}
    }
    try:
        resp = requests.post(OLLAMA_URL, json=payload, timeout=120)
        resp.raise_for_status()
        return resp.json()["response"]
    except Exception as e:
        raise Exception(f"Ollama 调用失败: {str(e)}")

def call_ollama_stream(prompt, model=DEFAULT_OLLAMA_MODEL, temperature=0.7):
    payload = {
        "model": model,
        "prompt": prompt,
        "stream": True,
        "options": {"temperature": temperature}
    }
    response = requests.post(OLLAMA_URL, json=payload, stream=True)
    for line in response.iter_lines():
        if line:
            data = json.loads(line)
            if 'response' in data:
                yield data['response']

@app.route('/tools/aippt_outline', methods=['POST'])
@require_login
def aippt_outline():
    username = session['username']
    print(f"[LOG] /tools/aippt_outline 被调用，来自 {request.remote_addr}，用户 {username}")
    data = request.json
    content = data.get('content')
    language = data.get('language', 'zh')
    model = data.get('model', DEFAULT_OLLAMA_MODEL)
    if not content:
        return jsonify({"error": "缺少 content 参数"}), 400
    with get_db_connection() as conn:
        cur = conn.cursor()
        cur.execute("UPDATE users SET coins = coins - %s WHERE username = %s AND coins >= %s", (AI_PPT_COST, username, AI_PPT_COST))
        if cur.rowcount == 0:
            return jsonify({"error": f"枫叶币不足，需要{AI_PPT_COST}个"}), 400
        conn.commit()
    prompt = f"请根据以下内容生成一份PPT大纲，使用{language}语言：\n{content}\n大纲格式要求：返回JSON数组，每个元素包含title和content字段。"
    def generate():
        for chunk in call_ollama_stream(prompt, model):
            yield chunk
    return Response(stream_with_context(generate()), mimetype='text/plain')

@app.route('/tools/aippt', methods=['POST'])
@require_login
def aippt():
    username = session['username']
    print(f"[LOG] /tools/aippt 被调用，来自 {request.remote_addr}，用户 {username}")
    data = request.json
    content = data.get('content')
    language = data.get('language', 'zh')
    style = data.get('style', '默认')
    model = data.get('model', DEFAULT_OLLAMA_MODEL)
    if not content:
        return jsonify({"error": "缺少 content 参数"}), 400
    with get_db_connection() as conn:
        cur = conn.cursor()
        cur.execute("UPDATE users SET coins = coins - %s WHERE username = %s AND coins >= %s", (AI_PPT_COST, username, AI_PPT_COST))
        if cur.rowcount == 0:
            return jsonify({"error": f"枫叶币不足，需要{AI_PPT_COST}个"}), 400
        conn.commit()
    prompt = f"请根据以下内容生成一份完整的PPT，使用{language}语言，风格为{style}。要求返回JSON数组，数组的每个元素代表一页幻灯片，每个幻灯片对象应包含id和elements字段。\n内容：{content}"
    try:
        full_text = call_ollama(prompt, model)
        import re
        json_match = re.search(r'```(?:json)?\s*(\[.*?\])\s*```', full_text, re.DOTALL)
        if json_match:
            json_str = json_match.group(1)
        else:
            json_str = full_text
        try:
            slides = json.loads(json_str)
            if not isinstance(slides, list):
                slides = [{"id": "1", "elements": [{"type": "text", "content": full_text}]}]
        except json.JSONDecodeError:
            slides = [{"id": "1", "elements": [{"type": "text", "content": full_text}]}]
        def generate():
            for slide in slides:
                yield json.dumps(slide, ensure_ascii=False) + "\n"
        return Response(stream_with_context(generate()), mimetype='text/plain')
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/tools/ai_writing', methods=['POST'])
def ai_writing():
    return jsonify({"result": "写作功能待实现"})

# ---------- PPTist 静态文件 ----------
@app.route('/pptist')
@app.route('/pptist/<path:filename>')
def serve_pptist(filename='index.html'):
    print(f"[LOG] /pptist 被调用，来自 {request.remote_addr}，文件 {filename}")
    return send_from_directory('static/pptist', filename)

@app.route('/mocks/slides.json')
def mock_slides():
    print(f"[LOG] /mocks/slides.json 被调用，来自 {request.remote_addr}")
    default_slides = [
        {
            "id": "cover",
            "elements": [
                {
                    "type": "text",
                    "content": "欢迎使用枫叶社区 AI PPT",
                    "style": {"fontSize": 48, "bold": True, "color": "#2c3e50"}
                },
                {
                    "type": "text",
                    "content": "智能生成，一键创作",
                    "style": {"fontSize": 24, "color": "#34495e"}
                }
            ]
        },
        {
            "id": "page1",
            "elements": [
                {
                    "type": "text",
                    "content": "功能介绍",
                    "style": {"fontSize": 36, "bold": True}
                },
                {
                    "type": "text",
                    "content": "• 支持多种模板\n• 实时预览\n• 导出PPTX",
                    "style": {"fontSize": 24, "lineHeight": 1.5}
                }
            ]
        }
    ]
    return jsonify(default_slides)

# ========== 银行 API ==========
@app.route('/api/bank/info/<bank_code>', methods=['GET'])
def bank_info(bank_code):
    print(f"[LOG] /api/bank/info/{bank_code} 被调用，来自 {request.remote_addr}")
    with get_db_connection() as conn:
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute("SELECT name, interest_rate, music_url FROM banks WHERE code=%s", (bank_code,))
        bank = cur.fetchone()
        if not bank:
            return jsonify({"error": "银行不存在"}), 404
        return jsonify(bank)

@app.route('/api/bank/register', methods=['POST'])
def bank_register():
    print(f"[LOG] /api/bank/register 被调用，来自 {request.remote_addr}")
    data = request.json
    bank_code = data.get('bank_code')
    username = data.get('username')
    password = data.get('password')
    if not bank_code or not username or not password:
        return jsonify({"error": "缺少参数"}), 400
    with get_db_connection() as conn:
        cur = conn.cursor()
        cur.execute("SELECT 1 FROM users WHERE username=%s", (username,))
        if not cur.fetchone():
            return jsonify({"error": "枫叶社区用户不存在"}), 400
        cur.execute("SELECT 1 FROM bank_accounts WHERE bank_code=%s AND username=%s", (bank_code, username))
        if cur.fetchone():
            return jsonify({"error": "该银行账户已注册"}), 400
        hashed = generate_password_hash(password)
        cur.execute(
            "INSERT INTO bank_accounts (bank_code, username, password_hash) VALUES (%s, %s, %s)",
            (bank_code, username, hashed)
        )
        conn.commit()
    print(f"[LOG] 用户 {username} 在银行 {bank_code} 注册成功")
    return jsonify({"success": True})

@app.route('/api/bank/login', methods=['POST'])
def bank_login():
    print(f"[LOG] /api/bank/login 被调用，来自 {request.remote_addr}")
    data = request.json
    bank_code = data.get('bank_code')
    username = data.get('username')
    password = data.get('password')
    if not bank_code or not username or not password:
        return jsonify({"error": "缺少参数"}), 400
    with get_db_connection() as conn:
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute(
            "SELECT id, username, password_hash, balance FROM bank_accounts WHERE bank_code=%s AND username=%s",
            (bank_code, username)
        )
        account = cur.fetchone()
        if not account or not check_password_hash(account['password_hash'], password):
            return jsonify({"error": "用户名或密码错误"}), 401
        session['bank_logged_in'] = True
        session['bank_username'] = username
        session['bank_code'] = bank_code
        del account['password_hash']
        print(f"[LOG] 用户 {username} 在银行 {bank_code} 登录成功")
        return jsonify({"success": True, "account": account})

@app.route('/api/bank/logout', methods=['POST'])
def bank_logout():
    print(f"[LOG] /api/bank/logout 被调用，来自 {request.remote_addr}")
    session.pop('bank_logged_in', None)
    session.pop('bank_username', None)
    session.pop('bank_code', None)
    return jsonify({"success": True})

@app.route('/api/bank/balance', methods=['GET'])
def bank_balance():
    print(f"[LOG] /api/bank/balance 被调用，来自 {request.remote_addr}")
    if not session.get('bank_logged_in'):
        return jsonify({"error": "未登录银行"}), 401
    bank_code = session['bank_code']
    username = session['bank_username']
    with get_db_connection() as conn:
        cur = conn.cursor()
        cur.execute("SELECT balance FROM bank_accounts WHERE bank_code=%s AND username=%s", (bank_code, username))
        balance = cur.fetchone()[0]
        return jsonify({"balance": balance})

@app.route('/api/bank/deposit', methods=['POST'])
def bank_deposit():
    print(f"[LOG] /api/bank/deposit 被调用，来自 {request.remote_addr}")
    if not session.get('bank_logged_in'):
        return jsonify({"error": "未登录银行"}), 401
    bank_code = session['bank_code']
    username = session['bank_username']
    data = request.json
    amount = data.get('amount')
    if not amount or amount <= 0:
        return jsonify({"error": "金额必须为正整数"}), 400
    with get_db_connection() as conn:
        cur = conn.cursor()
        cur.execute("SELECT coins FROM users WHERE username=%s", (username,))
        user_coins = cur.fetchone()[0]
        if user_coins < amount:
            return jsonify({"error": "枫叶币不足"}), 400
        cur.execute("UPDATE users SET coins = coins - %s WHERE username=%s", (amount, username))
        cur.execute("UPDATE bank_accounts SET balance = balance + %s WHERE bank_code=%s AND username=%s", (amount, bank_code, username))
        cur.execute(
            "INSERT INTO bank_transactions (bank_code, username, type, amount) VALUES (%s, %s, 'deposit', %s)",
            (bank_code, username, amount)
        )
        conn.commit()
    print(f"[LOG] 用户 {username} 在银行 {bank_code} 存款 {amount} 成功")
    return jsonify({"success": True})

@app.route('/api/bank/withdraw', methods=['POST'])
def bank_withdraw():
    print(f"[LOG] /api/bank/withdraw 被调用，来自 {request.remote_addr}")
    if not session.get('bank_logged_in'):
        return jsonify({"error": "未登录银行"}), 401
    bank_code = session['bank_code']
    username = session['bank_username']
    data = request.json
    amount = data.get('amount')
    if not amount or amount <= 0:
        return jsonify({"error": "金额必须为正整数"}), 400
    with get_db_connection() as conn:
        cur = conn.cursor()
        cur.execute("SELECT balance FROM bank_accounts WHERE bank_code=%s AND username=%s", (bank_code, username))
        balance = cur.fetchone()[0]
        if balance < amount:
            return jsonify({"error": "银行存款不足"}), 400
        cur.execute("UPDATE bank_accounts SET balance = balance - %s WHERE bank_code=%s AND username=%s", (amount, bank_code, username))
        cur.execute("UPDATE users SET coins = coins + %s WHERE username=%s", (amount, username))
        cur.execute(
            "INSERT INTO bank_transactions (bank_code, username, type, amount) VALUES (%s, %s, 'withdraw', %s)",
            (bank_code, username, amount)
        )
        conn.commit()
    print(f"[LOG] 用户 {username} 在银行 {bank_code} 取款 {amount} 成功")
    return jsonify({"success": True})

@app.route('/api/bank/transfer', methods=['POST'])
def bank_transfer():
    print(f"[LOG] /api/bank/transfer 被调用，来自 {request.remote_addr}")
    if not session.get('bank_logged_in'):
        return jsonify({"error": "未登录银行"}), 401
    bank_code = session['bank_code']
    from_user = session['bank_username']
    data = request.json
    to_user = data.get('to')
    amount = data.get('amount')
    if not to_user or not amount or amount <= 0:
        return jsonify({"error": "参数错误"}), 400
    if to_user == from_user:
        return jsonify({"error": "不能给自己转账"}), 400
    with get_db_connection() as conn:
        cur = conn.cursor()
        cur.execute("SELECT 1 FROM bank_accounts WHERE bank_code=%s AND username=%s", (bank_code, to_user))
        if not cur.fetchone():
            return jsonify({"error": "目标用户未在该银行开户"}), 400
        cur.execute("SELECT balance FROM bank_accounts WHERE bank_code=%s AND username=%s", (bank_code, from_user))
        balance = cur.fetchone()[0]
        if balance < amount:
            return jsonify({"error": "存款余额不足"}), 400
        cur.execute("UPDATE bank_accounts SET balance = balance - %s WHERE bank_code=%s AND username=%s", (amount, bank_code, from_user))
        cur.execute("UPDATE bank_accounts SET balance = balance + %s WHERE bank_code=%s AND username=%s", (amount, bank_code, to_user))
        cur.execute(
            "INSERT INTO bank_transactions (bank_code, username, type, amount, target_username) VALUES (%s, %s, 'transfer_out', %s, %s)",
            (bank_code, from_user, amount, to_user)
        )
        cur.execute(
            "INSERT INTO bank_transactions (bank_code, username, type, amount, target_username) VALUES (%s, %s, 'transfer_in', %s, %s)",
            (bank_code, to_user, amount, from_user)
        )
        conn.commit()
    print(f"[LOG] 用户 {from_user} 在银行 {bank_code} 转账 {amount} 给 {to_user} 成功")
    return jsonify({"success": True})

@app.route('/api/bank/transactions', methods=['GET'])
def bank_transactions():
    print(f"[LOG] /api/bank/transactions 被调用，来自 {request.remote_addr}")
    if not session.get('bank_logged_in'):
        return jsonify({"error": "未登录银行"}), 401
    bank_code = session['bank_code']
    username = session['bank_username']
    limit = request.args.get('limit', 20, type=int)
    with get_db_connection() as conn:
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute("""
            SELECT type, amount, target_username, created_at
            FROM bank_transactions
            WHERE bank_code=%s AND username=%s
            ORDER BY created_at DESC
            LIMIT %s
        """, (bank_code, username, limit))
        transactions = cur.fetchall()
        for t in transactions:
            t['created_at'] = t['created_at'].isoformat()
        return jsonify(transactions)

@app.route('/api/bank/checkin', methods=['POST'])
def bank_checkin():
    print(f"[LOG] /api/bank/checkin 被调用，来自 {request.remote_addr}")
    if not session.get('bank_logged_in'):
        return jsonify({"error": "未登录银行"}), 401
    bank_code = session['bank_code']
    username = session['bank_username']
    with get_db_connection() as conn:
        cur = conn.cursor()
        cur.execute("SELECT interest_rate FROM banks WHERE code=%s", (bank_code,))
        row = cur.fetchone()
        if not row or row[0] == 0:
            return jsonify({"error": "该银行不支持签到"}), 400
        interest_rate = row[0] / 100
        cur.execute("SELECT last_checkin FROM bank_accounts WHERE bank_code=%s AND username=%s", (bank_code, username))
        last_checkin = cur.fetchone()[0]
        today = datetime.datetime.now().date()
        if last_checkin and last_checkin.date() == today:
            return jsonify({"error": "今日已签到"}), 400
        cur.execute("SELECT balance FROM bank_accounts WHERE bank_code=%s AND username=%s", (bank_code, username))
        balance = cur.fetchone()[0]
        interest = int(balance * interest_rate)
        new_balance = balance + interest
        cur.execute("UPDATE bank_accounts SET balance = %s, last_checkin = NOW() WHERE bank_code=%s AND username=%s", (new_balance, bank_code, username))
        cur.execute(
            "INSERT INTO bank_transactions (bank_code, username, type, amount) VALUES (%s, %s, 'checkin', %s)",
            (bank_code, username, interest)
        )
        conn.commit()
    print(f"[LOG] 用户 {username} 在银行 {bank_code} 签到，获得利息 {interest}")
    return jsonify({"success": True, "interest": interest, "balance": new_balance})

@app.route('/api/bank/raffle', methods=['POST'])
def bank_raffle():
    print(f"[LOG] /api/bank/raffle 被调用，来自 {request.remote_addr}")
    if not session.get('bank_logged_in'):
        return jsonify({"error": "未登录银行"}), 401
    bank_code = session['bank_code']
    username = session['bank_username']
    with get_db_connection() as conn:
        cur = conn.cursor()
        cur.execute("SELECT balance FROM bank_accounts WHERE bank_code=%s AND username=%s", (bank_code, username))
        balance = cur.fetchone()[0]
        if balance < RAFFLE_COST:
            return jsonify({"error": f"存款余额不足 {RAFFLE_COST} 枫叶币，无法抽奖"}), 400
        reward = random.randint(10, 20)
        new_balance = balance - RAFFLE_COST + reward
        cur.execute("UPDATE bank_accounts SET balance = %s WHERE bank_code=%s AND username=%s", (new_balance, bank_code, username))
        cur.execute("""
            INSERT INTO bank_transactions (bank_code, username, type, amount, description)
            VALUES (%s, %s, 'raffle', %s, %s)
        """, (bank_code, username, reward - RAFFLE_COST, f"抽奖消耗{RAFFLE_COST}，获得{reward}，净收益{reward - RAFFLE_COST}"))
        conn.commit()
    print(f"[LOG] 用户 {username} 在银行 {bank_code} 抽奖，获得 {reward}，净收益 {reward - RAFFLE_COST}")
    return jsonify({
        "success": True,
        "reward": reward,
        "cost": RAFFLE_COST,
        "net": reward - RAFFLE_COST,
        "balance": new_balance
    })

# ========== WebSocket 基础服务 ==========
# 创建 SocketIO 实例（不依赖终端环境变量，确保聊天室等功能可用）
socketio = SocketIO(app, cors_allowed_origins="*", manage_session=True)

# ========== WebSocket 数据库终端（依赖环境变量）==========
if MAPLE_TERMINAL_PASSWORD and TERMINAL_PASSWORD_NORMAL and TERMINAL_PASSWORD_SUPER:
    processes = {}

    def _cleanup(sid):
        proc_info = processes.pop(sid, None)
        if proc_info:
            proc_info['proc'].terminate()
            os.close(proc_info['master'])
            os.close(proc_info['slave'])

    def _read_output(sid, master_fd):
        buffer = ""
        while True:
            rlist, _, _ = select.select([master_fd], [], [], 0.5)
            if rlist:
                try:
                    data = os.read(master_fd, 4096)
                    if not data:
                        break
                    decoded = data.decode('utf-8', errors='replace')
                    buffer += decoded
                    if '\n' in buffer:
                        lines = buffer.split('\n')
                        for line in lines[:-1]:
                            socketio.emit('terminal_output', {'data': line + '\n'}, room=sid)
                        buffer = lines[-1]
                except Exception as e:
                    print(f"[LOG] 读取输出错误: {e}")
                    break
        if buffer:
            socketio.emit('terminal_output', {'data': buffer}, room=sid)
        _cleanup(sid)

    @socketio.on('connect_sql_terminal')
    def handle_connect(data):
        print(f"[LOG] WebSocket 连接请求: {data}")
        if not session.get('admin_logged_in'):
            emit('error', {'msg': '请先登录管理员'})
            print("[LOG] 拒绝连接：管理员未登录")
            return

        user_type = data.get('user_type')
        second_pass = data.get('second_pass')
        db_password = data.get('db_password')

        if user_type == 'normal':
            expected = TERMINAL_PASSWORD_NORMAL
            db_user = 'maple_terminal'
        elif user_type == 'super':
            expected = TERMINAL_PASSWORD_SUPER
            db_user = 'u0_a167'
        else:
            emit('error', {'msg': '无效的用户类型'})
            print("[LOG] 拒绝连接：无效用户类型")
            return

        if not expected or second_pass != expected:
            emit('error', {'msg': '二次口令错误'})
            print("[LOG] 拒绝连接：二次口令错误")
            return

        if not db_password:
            emit('error', {'msg': '数据库密码不能为空'})
            print("[LOG] 拒绝连接：数据库密码为空")
            return

        env = os.environ.copy()
        env['PGPASSWORD'] = db_password
        master_fd, slave_fd = pty.openpty()
        # 设置非阻塞模式
        flags = fcntl.fcntl(master_fd, fcntl.F_GETFL)
        fcntl.fcntl(master_fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)

        cmd = ['psql', '-U', db_user, '-d', 'maple_community', '-h', 'localhost']
        proc = subprocess.Popen(cmd, stdin=slave_fd, stdout=slave_fd, stderr=slave_fd,
                                env=env, universal_newlines=False)

        sid = request.sid
        processes[sid] = {
            'proc': proc,
            'master': master_fd,
            'slave': slave_fd,
            'last_activity': time.time()
        }

        socketio.start_background_task(target=_read_output, sid=sid, master_fd=master_fd)

        def monitor():
            proc.wait()
            print(f"[LOG] 子进程 {proc.pid} 已退出，返回码: {proc.returncode}")
            socketio.emit('terminal_output', {'data': f'\n[进程退出，返回码: {proc.returncode}]\n'}, room=sid)
            _cleanup(sid)

        socketio.start_background_task(target=monitor)
        print(f"[LOG] 终端已启动，用户类型: {user_type}, 数据库用户: {db_user}, PID: {proc.pid}")

    @socketio.on('terminal_input')
    def handle_input(data):
        sid = request.sid
        if sid in processes:
            processes[sid]['last_activity'] = time.time()
        proc_info = processes.get(sid)
        if proc_info:
            try:
                os.write(proc_info['master'], data['data'].encode())
            except BlockingIOError:
                print(f"[WARN] 终端写入缓冲区满，丢弃输入: {data['data'].strip()}")
            except BrokenPipeError:
                print(f"[ERROR] 终端管道已损坏，断开连接")
                _cleanup(sid)
            except Exception as e:
                print(f"[ERROR] 写入终端失败: {e}")
                _cleanup(sid)

    @socketio.on('heartbeat')
    def handle_heartbeat():
        sid = request.sid
        if sid in processes:
            processes[sid]['last_activity'] = time.time()

    @socketio.on('disconnect')
    def handle_disconnect():
        print(f"[LOG] WebSocket 断开连接: {request.sid}")
        _cleanup(request.sid)

    # 会话超时监控线程
    def monitor_sessions():
        while True:
            time.sleep(30)
            now = time.time()
            for sid, info in list(processes.items()):
                if now - info['last_activity'] > 600:
                    print(f"[LOG] 会话 {sid} 超时，主动断开")
                    socketio.emit('terminal_output', {'data': '\n[连接超时，已断开]\n'}, room=sid)
                    _cleanup(sid)

    socketio.start_background_task(target=monitor_sessions)

else:
    print("数据库终端功能未启用，请设置所需的环境变量 (MAPLE_TERMINAL_PASSWORD, TERMINAL_PASSWORD_NORMAL, TERMINAL_PASSWORD_SUPER)")

# ========== WebSocket 聊天室 ==========
online_users = set()

@socketio.on('chat_join')
def handle_chat_join():
    username = session.get('username')
    if not username:
        emit('error', {'msg': '未登录'})
        return
    online_users.add(username)
    print(f"[CHAT] {username} 加入聊天室，当前在线: {len(online_users)}")

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
        cur.execute(
            "INSERT INTO messages (username, nickname, content) VALUES (%s, %s, %s)",
            (username, nickname, content)
        )
        conn.commit()

    msg = {
        'username': username,
        'nickname': nickname,
        'content': content,
        'time': datetime.datetime.now().isoformat()
    }
    emit('chat_message', msg, broadcast=True)

@socketio.on('chat_leave')
def handle_chat_leave():
    username = session.get('username')
    if username:
        online_users.discard(username)
        print(f"[CHAT] {username} 离开聊天室，当前在线: {len(online_users)}")

# ---------- 前端入口 ----------
@app.route('/maple.html')
def serve_frontend():
    print(f"[LOG] /maple.html 被调用，来自 {request.remote_addr}")
    return send_from_directory('.', 'maple.html')

if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=8083, debug=True)
