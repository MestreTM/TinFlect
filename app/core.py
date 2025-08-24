import sqlite3
from flask import Flask, request, Response, g, abort, stream_with_context
import json
import os
import hashlib
import base64
from datetime import datetime
import threading
import time
from urllib.parse import quote
import requests
from waitress import serve

from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA256

PUBLIC_KEY_PEM = b"""-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvPdrJigQ0rZAy+jla7hS
jwen8gkF0gjtl+lZGY59KatNd9Kj2gfY7dTMM+5M2tU4Wr3nk8KWr5qKm3hzo/2C
Gbc55im3tlRl6yuFxWQ+c/I2SM5L3xp6eiLUcumMsEo0B7ELmtnHTGCCNAIzTFzV
4XcWGVbkZj83rTFxpLsa1oArTdcz5CG6qgyVe7KbPsft76DAEkV8KaWgnQiG0Dps
INFy4vISmf6L1TgAryJ8l2K4y8QbymyLeMsABdlEI3yRHAm78PSezU57XtQpHW5I
aupup8Es6bcDZQKkRsbOeR9T74tkj+k44QrjZo8xpX9tlJAKEEmwDlyAg0O5CLX3
CQIDAQAB
-----END PUBLIC KEY-----"""

def encrypt_for_tinfoil_legacy(json_string: str) -> bytes:
    """Legacy Tinfoil format: TINFOIL || 0xF0 || RSA_OAEP(aes_key_16) || orig_size_le_8bytes || AES_ECB_ZERO_PAD(json)"""
    data = json_string.encode('utf-8')
    orig_size = len(data)
    aes_key = os.urandom(16)
    padding_length = 16 - (orig_size % 16)
    padded = data + (b'\x00' * padding_length)
    aes = AES.new(aes_key, AES.MODE_ECB)
    ciphertext = aes.encrypt(padded)
    rsa_key = RSA.import_key(PUBLIC_KEY_PEM)
    oaep = PKCS1_OAEP.new(rsa_key, hashAlgo=SHA256)
    enc_key = oaep.encrypt(aes_key)
    return b'TINFOIL' + bytes([0xF0]) + enc_key + orig_size.to_bytes(8, 'little') + ciphertext

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
CONFIG = {}
MESSAGES = {}

def load_config():
    global CONFIG
    config_path = os.path.join(PROJECT_ROOT, 'config.json')
    try:
        with open(config_path, 'r', encoding='utf-8') as f:
            CONFIG = json.load(f)
        print("Core configurations loaded from config.json.")
    except Exception as e:
        print(f"WARNING: Failed to read config.json ({e}). Using defaults.")
        CONFIG = {"HOST": "0.0.0.0", "CORE_PORT": 15975, "ADMIN_PORT": 5000, "DEBUG_MODE": True}
    default_db_dir = os.path.join(PROJECT_ROOT, 'db')
    os.makedirs(default_db_dir, exist_ok=True)
    user_db_path = CONFIG.get('USER_DB')
    CONFIG['USER_DB'] = os.path.abspath(user_db_path) if user_db_path else os.path.join(default_db_dir, CONFIG.get('USER_DB_NAME', 'users.db'))
    os.makedirs(os.path.dirname(CONFIG['USER_DB']), exist_ok=True)
    downloads_db_path = CONFIG.get('DOWNLOADS_DB')
    CONFIG['DOWNLOADS_DB'] = os.path.abspath(downloads_db_path) if downloads_db_path else os.path.join(default_db_dir, CONFIG.get('DOWNLOADS_DB_NAME', 'users_downloads.db'))
    os.makedirs(os.path.dirname(CONFIG['DOWNLOADS_DB']), exist_ok=True)
    db_file_cfg = CONFIG.get('DB_FILE', 'games.db')
    CONFIG['DB_FILE'] = db_file_cfg if os.path.isabs(db_file_cfg) else os.path.join(PROJECT_ROOT, db_file_cfg)
    CONFIG['LOG_DIR'] = os.path.join(PROJECT_ROOT, "logs")
    os.makedirs(CONFIG['LOG_DIR'], exist_ok=True)
    CONFIG.setdefault('DAILY_DOWNLOAD_LIMIT', 0)
    CONFIG.setdefault('SHOP_TITLE', 'My Tinfoil Shop')
    CONFIG.setdefault('DOWNLOAD_GRACE_MS', 300)
    CONFIG.setdefault('DIRECT_LINKS', False)
    CONFIG.setdefault('ENABLE_DRM', True)

def load_messages():
    global MESSAGES
    messages_path = os.path.join(PROJECT_ROOT, 'messages.json')
    try:
        with open(messages_path, 'r', encoding='utf-8') as f:
            MESSAGES = json.load(f)
        print("Messages loaded from messages.json.")
    except Exception as e:
        print(f"ERROR: Could not read messages.json ({e}). Exiting.")
        exit(1)

load_config()
load_messages()
app = Flask(__name__)

def today_str():
    return datetime.now().strftime("%Y-%m-%d")

def setup_databases():
    def setup_user_database():
        with sqlite3.connect(CONFIG['USER_DB']) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    nickname TEXT UNIQUE NOT NULL,
                    password TEXT NOT NULL,
                    uid TEXT UNIQUE,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    uid_linked_at TIMESTAMP
                )
            """)
    def setup_downloads_database():
        with sqlite3.connect(CONFIG['DOWNLOADS_DB']) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS download_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_uid TEXT,
                    game_name TEXT NOT NULL,
                    file_size INTEGER NOT NULL DEFAULT 0,
                    downloaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    completed BOOLEAN DEFAULT 0
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS download_parts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    log_id INTEGER NOT NULL,
                    user_uid TEXT NOT NULL,
                    game_id INTEGER NOT NULL,
                    start INTEGER NOT NULL,
                    end INTEGER NOT NULL,
                    bytes_sent INTEGER NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS quote (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    date TEXT NOT NULL,
                    user_uid TEXT NOT NULL,
                    nickname TEXT,
                    download_count INTEGER NOT NULL DEFAULT 0,
                    last_login TIMESTAMP,
                    last_update TIMESTAMP,
                    UNIQUE(date, user_uid)
                )
            """)
    def check_and_add_column(db_path, table, column, coltype):
        try:
            with sqlite3.connect(db_path) as conn:
                cur = conn.cursor()
                cur.execute(f"PRAGMA table_info({table})")
                cols = [c[1] for c in cur.fetchall()]
                if column not in cols:
                    print(f"Adding column '{column}' to '{table}'...")
                    cur.execute(f"ALTER TABLE {table} ADD COLUMN {column} {coltype}")
                    conn.commit()
        except sqlite3.OperationalError as e:
            print(f"Warning: error updating table '{table}': {e}")
    def ensure_columns(conn, table, needed: dict):
        cur = conn.cursor()
        cur.execute(f"PRAGMA table_info({table})")
        cols = {c[1] for c in cur.fetchall()}
        for name, ddl in needed.items():
            if name not in cols:
                print(f"[MIGRATION] Adding column '{name}' to '{table}'...")
                cur.execute(f"ALTER TABLE {table} ADD COLUMN {name} {ddl}")
        conn.commit()
    def migrate_downloads_table():
        db = CONFIG['DOWNLOADS_DB']
        with sqlite3.connect(db) as conn:
            ensure_columns(conn, 'download_history', {
                'user_uid': 'TEXT',
                'game_name': 'TEXT',
                'file_size': 'INTEGER NOT NULL DEFAULT 0',
                'downloaded_at': 'TIMESTAMP DEFAULT CURRENT_TIMESTAMP',
                'completed': 'BOOLEAN DEFAULT 0'
            })
            cur = conn.cursor()
            cur.execute("PRAGMA table_info(download_history)")
            cols = {c[1] for c in cur.fetchall()}
            if 'uid' in cols:
                print("[MIGRATION] Copying values from 'uid' to 'user_uid'.")
                cur.execute("""
                    UPDATE download_history
                        SET user_uid = COALESCE(user_uid, uid)
                     WHERE (user_uid IS NULL OR user_uid = '')
                """)
                conn.commit()
    setup_user_database()
    setup_downloads_database()
    check_and_add_column(CONFIG['DB_FILE'], 'games', 'filepath', 'TEXT')
    check_and_add_column(CONFIG['DB_FILE'], 'games', 'filename', 'TEXT')
    check_and_add_column(CONFIG['DB_FILE'], 'games', 'download_count', 'INTEGER DEFAULT 0')
    check_and_add_column(CONFIG['DB_FILE'], 'games', 'url', 'TEXT')
    migrate_downloads_table()
    quote_purge_if_day_changed()
    print("Databases checked and configured.")

def send_log_entry(log_type, log_level, message, ip, user=None, source='core'):
    entry = {
        'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        'type': log_type, 'level': log_level, 'message': message,
        'ip': ip, 'user': user or 'Unknown', 'source': source
    }
    admin_host = CONFIG.get('ADMIN_HOST', '127.0.0.1')
    admin_port = CONFIG.get('ADMIN_PORT')
    if not admin_port:
        return
    target = f"http://{admin_host}:{admin_port}/api/core_log"
    try:
        requests.post(target, json=entry, timeout=2)
        if CONFIG.get('DEBUG_MODE'):
            print(f"Log sent: [{log_level}] {message}")
    except requests.exceptions.RequestException as e:
        if CONFIG.get('DEBUG_MODE'):
            print(f"Failed to send log: {e}")

def notify_main_online():
    send_log_entry('core', 'SUCCESS', 'Tinfoil server online', 'localhost', 'system')

def authenticate_user(nickname, password, uid):
    with sqlite3.connect(CONFIG['USER_DB']) as conn:
        cur = conn.cursor()
        cur.execute("SELECT password, uid FROM users WHERE nickname = ?", (nickname,))
        row = cur.fetchone()
        if not row:
            return 'FAILURE', "User not found."
        stored_pwd, stored_uid = row
        if stored_pwd != hashlib.sha256(password.encode()).hexdigest():
            return 'FAILURE', "Incorrect password."
        if stored_uid and stored_uid != uid:
            return 'WARNING', "Console UID does not match."
        return 'SUCCESS', "OK"

def get_nickname_by_uid(uid: str):
    if not uid:
        return None
    try:
        with sqlite3.connect(CONFIG['USER_DB']) as conn:
            cur = conn.cursor()
            cur.execute("SELECT nickname FROM users WHERE uid = ? LIMIT 1", (uid,))
            row = cur.fetchone()
            return row[0] if row else None
    except Exception as e:
        if CONFIG.get('DEBUG_MODE'):
            print(f"Error fetching nickname by UID: {e}")
        return None

def uid_exists_in_user_db(uid: str) -> bool:
    return get_nickname_by_uid(uid) is not None

def quote_purge_if_day_changed():
    try:
        with sqlite3.connect(CONFIG['DOWNLOADS_DB']) as conn:
            conn.execute("DELETE FROM quote WHERE date != ?", (today_str(),))
            conn.commit()
    except Exception:
        pass

def quote_touch_login(uid: str, nickname: str = None):
    if not uid:
        return
    quote_purge_if_day_changed()
    with sqlite3.connect(CONFIG['DOWNLOADS_DB']) as conn:
        conn.execute("""
            INSERT INTO quote (date, user_uid, nickname, download_count, last_login, last_update)
            VALUES (?, ?, ?, 0, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
            ON CONFLICT(date, user_uid) DO UPDATE SET
              nickname = COALESCE(quote.nickname, excluded.nickname),
              last_login = CURRENT_TIMESTAMP,
              last_update = CURRENT_TIMESTAMP
        """, (today_str(), uid, nickname))
        conn.commit()

def quote_increment_download(uid: str, nickname: str = None):
    if not uid:
        return
    quote_purge_if_day_changed()
    with sqlite3.connect(CONFIG['DOWNLOADS_DB']) as conn:
        conn.execute("""
            INSERT INTO quote (date, user_uid, nickname, download_count, last_update)
            VALUES (?, ?, ?, 1, CURRENT_TIMESTAMP)
            ON CONFLICT(date, user_uid) DO UPDATE SET
              download_count = COALESCE(quote.download_count,0) + 1,
              nickname = COALESCE(quote.nickname, excluded.nickname),
              last_update = CURRENT_TIMESTAMP
        """, (today_str(), uid, nickname))
        conn.commit()

def quote_get_count(uid: str) -> int:
    if not uid:
        return 0
    quote_purge_if_day_changed()
    with sqlite3.connect(CONFIG['DOWNLOADS_DB']) as conn:
        cur = conn.cursor()
        cur.execute("SELECT COALESCE(download_count,0) FROM quote WHERE date = ? AND user_uid = ?", (today_str(), uid))
        row = cur.fetchone()
        return int(row[0]) if row else 0

@app.before_request
def auth_middleware():
    if request.path.startswith('/api/download/'):
        return
    auth_header = request.headers.get('Authorization')
    uid = request.headers.get('UID', 'Unknown')
    if not auth_header or not auth_header.startswith('Basic '):
        abort(401)
    try:
        nick, pwd = base64.b64decode(auth_header[6:]).decode('utf-8').split(':', 1)
    except Exception:
        abort(401)
    status, _ = authenticate_user(nick, pwd, uid)
    if status != 'SUCCESS':
        abort(403)
    g.user_nickname = nick
    g.user_uid = uid
    if uid and uid_exists_in_user_db(uid):
        quote_touch_login(uid, nick)

@app.errorhandler(401)
def handle_unauthorized(e):
    msg = MESSAGES.get('BROWSER_FORBIDDEN', 'Unauthorized')
    return Response(msg, status=401, mimetype='text/html; charset=utf-8')

@app.errorhandler(403)
def handle_forbidden(e):
    msg = MESSAGES.get('BROWSER_FORBIDDEN', 'Unauthorized')
    return Response(msg, status=403, mimetype='text/html; charset=utf-8')

def check_download_limit(uid):
    limit = CONFIG.get('DAILY_DOWNLOAD_LIMIT', 0)
    if limit == 0:
        return True, 0, 0
    used = quote_get_count(uid)
    return (used < limit), used, limit

def log_download(uid, game_name, file_size):
    with sqlite3.connect(CONFIG['DOWNLOADS_DB']) as conn:
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO download_history (user_uid, game_name, file_size) VALUES (?, ?, ?)",
            (uid, game_name, file_size or 0)
        )
        conn.commit()
        return cur.lastrowid

def update_download_status(log_id, completed, uid=None, nickname=None):
    with sqlite3.connect(CONFIG['DOWNLOADS_DB']) as conn:
        cur = conn.cursor()
        new_val = int(bool(completed))
        cur.execute(
            "UPDATE download_history SET completed = ? WHERE id = ? AND completed != ?",
            (new_val, log_id, new_val)
        )
        changed = (cur.rowcount or 0) > 0
        conn.commit()
    if changed and new_val == 1 and uid:
        quote_increment_download(uid, nickname)
    return changed

def increment_download_count(game_id):
    with sqlite3.connect(CONFIG['DB_FILE']) as conn:
        conn.execute("UPDATE games SET download_count = COALESCE(download_count,0) + 1 WHERE id = ?", (game_id,))
        conn.commit()

def parse_range_header(range_header: str, file_size: int):
    if not range_header or not range_header.startswith("bytes="):
        return None
    try:
        spec = range_header.split("=", 1)[1].strip()
        part = spec.split(",")[0].strip()
        if "-" not in part:
            return None
        start_s, end_s = part.split("-", 1)
        if start_s == "":
            length = int(end_s)
            if length <= 0:
                return None
            start = max(0, file_size - length)
            end = file_size - 1
        else:
            start = int(start_s)
            end = file_size - 1 if end_s == "" else int(end_s)
            if start > end:
                return None
        if start < 0 or end >= file_size:
            return None
        return (start, end)
    except Exception:
        return None

def record_part_and_check_complete(log_id: int, uid: str, game_id: int, start: int, end: int, bytes_sent: int, total_size: int, nickname: str):
    try:
        if bytes_sent <= 0 or end < start:
            return
        with sqlite3.connect(CONFIG['DOWNLOADS_DB']) as conn:
            cur = conn.cursor()
            cur.execute("""
                INSERT INTO download_parts (log_id, user_uid, game_id, start, end, bytes_sent)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (log_id, uid, game_id, int(start), int(end), int(bytes_sent)))
            conn.commit()
            cur.execute("""
                SELECT start, end FROM download_parts
                 WHERE user_uid = ?
                   AND game_id = ?
                   AND DATE(created_at, 'localtime') = DATE('now', 'localtime')
                 ORDER BY start ASC
            """, (uid, game_id))
            parts = cur.fetchall()
        merged = []
        for s, e in parts:
            if not merged or s > merged[-1][1] + 1:
                merged.append([s, e])
            else:
                if e > merged[-1][1]:
                    merged[-1][1] = e
        coverage = sum(e - s + 1 for s, e in merged) if merged else 0
        if total_size and coverage >= total_size:
            if update_download_status(log_id, True, uid, nickname):
                send_log_entry('download', 'SUCCESS',
                               f"Download completed for '{game_id}' (full coverage).",
                               request.remote_addr, user=nickname)
    except Exception as e:
        send_log_entry('download', 'ERROR', f"Failed to record/check coverage: {e}", request.remote_addr, user=nickname)

def generate_file_listing(uid_for_urls: str = None):
    final = {"files": [], "directories": []}
    with sqlite3.connect(CONFIG['DB_FILE']) as conn:
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        cur.execute("""
            SELECT id, name, size, version, tid, cover, icon, type, search, url, filepath, filename
            FROM games
        """)
        rows = cur.fetchall()
    direct = bool(CONFIG.get('DIRECT_LINKS', False))
    for row in rows:
        d = dict(row)
        if direct:
            if not d.get('url'):
                continue
            file_url = d['url']
        else:
            safe_filename = quote(d.get('filename') or f"{d.get('name','file')}.nsp")
            if uid_for_urls:
                file_url = f"/api/download/{uid_for_urls}/{d['id']}/{safe_filename}"
            else:
                file_url = f"/api/download/{{uid}}/{d['id']}/{safe_filename}"
        final["files"].append({
            "url": file_url,
            "size": d.get('size'),
            "title": d.get('name'),
            "version": d.get('version'),
            "id": d.get('tid'),
            "cover": d.get('cover'),
            "icon": d.get('icon'),
            "type": d.get('type'),
            "search": d.get('search')
        })
    return final

@app.route('/')
def shop_index():
    uid_for_urls = getattr(g, 'user_uid', None)
    if uid_for_urls and not uid_exists_in_user_db(uid_for_urls):
        uid_for_urls = None
    final = generate_file_listing(uid_for_urls if not CONFIG.get('DIRECT_LINKS', False) else None)
    count = len(final["files"])
    motd_tpl = MESSAGES.get('SHOP_MOTD_PLURAL') if count != 1 else MESSAGES.get('SHOP_MOTD_SINGULAR')
    tpl_data = {
        "shop_title": CONFIG.get("SHOP_TITLE"),
        "user": getattr(g, 'user_nickname', 'guest'),
        "count": count,
        "datetime": datetime.now().strftime("%d/%m/%Y %H:%M:%S")
    }
    final["success"] = motd_tpl.format(**tpl_data) if motd_tpl else "Welcome!"
    send_log_entry('access', 'SUCCESS', f"Game list sent to '{tpl_data['user']}'.", request.remote_addr, tpl_data['user'])
    if CONFIG.get('ENABLE_DRM', True):
        payload = json.dumps(final, ensure_ascii=False, separators=(",", ":"))
        blob = encrypt_for_tinfoil_legacy(payload)
        return Response(blob, mimetype='application/octet-stream')
    return Response(json.dumps(final), mimetype='application/json')

@app.route('/api/download/<string:uid>/<int:game_id>/<path:filename>', methods=['GET', 'HEAD'])
def download_api(uid, game_id, filename):
    nickname = get_nickname_by_uid(uid)
    if not nickname:
        abort(403)
    quote_touch_login(uid, nickname)
    with sqlite3.connect(CONFIG['DB_FILE']) as conn:
        conn.row_factory = sqlite3.Row
        game = conn.execute("SELECT * FROM games WHERE id = ?", (game_id,)).fetchone()
    if not game:
        abort(404, "Item not found.")
    display_filename = game['filename'] or filename
    game_name = game['name'] or filename
    local_path = game['filepath']
    external_url = game['url']
    file_size = game['size'] or (os.path.getsize(local_path) if local_path and os.path.exists(local_path) else None)
    if request.method == 'HEAD':
        if local_path and os.path.exists(local_path):
            size = os.path.getsize(local_path)
            headers = {
                "Content-Type": "application/octet-stream",
                "Content-Disposition": f"attachment; filename*=UTF-8''{quote(display_filename)}",
                "Content-Length": str(size),
                "Accept-Ranges": "bytes"
            }
            return Response(b"", headers=headers, status=200)
        elif external_url:
            try:
                head = requests.head(external_url, timeout=10)
                if head.status_code >= 400 or 'Content-Length' not in head.headers:
                    head = requests.get(external_url, headers={"Range": "bytes=0-0"}, stream=True, timeout=10)
                headers = {
                    "Content-Type": head.headers.get('Content-Type', 'application/octet-stream'),
                    "Content-Disposition": f"attachment; filename*=UTF-8''{quote(display_filename)}",
                }
                if head.headers.get('Content-Length'):
                    headers["Content-Length"] = head.headers['Content-Length']
                headers["Accept-Ranges"] = head.headers.get('Accept-Ranges', 'bytes')
                return Response(b"", headers=headers, status=200)
            except Exception:
                abort(502, "Failed to get metadata from external file.")
        else:
            abort(404, "No download source available.")
    allowed, used, limit = check_download_limit(uid)
    if not allowed:
        send_log_entry('download', 'WARNING',
                       f"User '{nickname}' exceeded daily limit ({used}/{limit}).",
                       request.remote_addr, user=nickname)
        abort(429, "Daily download limit reached.")
    log_id = log_download(uid, game_name, file_size or 0)
    increment_download_count(game_id)
    grace = max(0, int(CONFIG.get('DOWNLOAD_GRACE_MS', 300))) / 1000.0
    def stream_local_with_range(path):
        total_size = os.path.getsize(path)
        req_range = parse_range_header(request.headers.get('Range'), total_size)
        status = 200
        headers = {
            "Content-Type": "application/octet-stream",
            "Content-Disposition": f"attachment; filename*=UTF-8''{quote(display_filename)}",
            "Accept-Ranges": "bytes"
        }
        if req_range:
            start, end = req_range
            length = end - start + 1
            status = 206
            headers["Content-Range"] = f"bytes {start}-{end}/{total_size}"
            headers["Content-Length"] = str(length)
        else:
            start, end = 0, total_size - 1
            length = total_size
            headers["Content-Length"] = str(total_size)
        send_log_entry('download', 'SUCCESS',
                       f"User '{nickname}' started local download of '{display_filename}'.",
                       request.remote_addr, user=nickname)
        bytes_sent = 0
        def _gen():
            nonlocal bytes_sent
            try:
                with open(path, 'rb') as f:
                    f.seek(start)
                    remaining = length
                    chunk = 1024 * 64
                    while remaining > 0:
                        to_read = chunk if remaining >= chunk else remaining
                        data = f.read(to_read)
                        if not data:
                            break
                        remaining -= len(data)
                        bytes_sent += len(data)
                        yield data
            except (BrokenPipeError, ConnectionResetError, GeneratorExit):
                pass
            finally:
                actual_end = start + max(0, bytes_sent) - 1 if bytes_sent > 0 else start - 1
                try:
                    record_part_and_check_complete(log_id, uid, game_id, start, actual_end, bytes_sent, total_size, nickname)
                except Exception as e:
                    send_log_entry('download', 'ERROR', f"Failed to record local part: {e}", request.remote_addr, user=nickname)
                stream_complete = (bytes_sent == length) and ((not req_range) or (end == total_size - 1))
                if stream_complete:
                    if grace > 0:
                        time.sleep(grace)
                    if update_download_status(log_id, True, uid, nickname):
                        send_log_entry('download', 'SUCCESS',
                                       f"Download completed (local) '{display_filename}'.",
                                       request.remote_addr, user=nickname)
        return Response(stream_with_context(_gen()), headers=headers, status=status, direct_passthrough=True)
    def stream_external_with_range(url):
        hdrs = {}
        if request.headers.get('Range'):
            hdrs['Range'] = request.headers.get('Range')
        upstream = requests.get(url, headers=hdrs, stream=True, timeout=20)
        upstream.raise_for_status()
        status = upstream.status_code
        headers = {
            "Content-Type": upstream.headers.get('Content-Type', 'application/octet-stream'),
            "Content-Disposition": f"attachment; filename*=UTF-8''{quote(display_filename)}",
            "Accept-Ranges": upstream.headers.get('Accept-Ranges', 'bytes')
        }
        if upstream.headers.get('Content-Length'):
            headers["Content-Length"] = upstream.headers['Content-Length']
        if upstream.headers.get('Content-Range'):
            headers["Content-Range"] = upstream.headers['Content-Range']
        total = None
        if upstream.headers.get('Content-Range'):
            try:
                cr = upstream.headers['Content-Range']
                total = int(cr.split("/")[1])
            except Exception:
                total = None
        if total is None and file_size:
            total = int(file_size)
        req_range = None
        if request.headers.get('Range') and total is not None:
            req_range = parse_range_header(request.headers.get('Range'), total)
        if req_range is None and status == 206 and upstream.headers.get('Content-Range') and total is not None:
            try:
                cr = upstream.headers['Content-Range']
                rng = cr.split()[1]
                a_s, b_s = rng.split("/")[0].split("-")
                req_range = (int(a_s), int(b_s))
            except Exception:
                req_range = None
        if total is None and local_path and os.path.exists(local_path):
            total = os.path.getsize(local_path)
        if total is None:
            total = 0
        if req_range is None:
            if total > 0 and status == 200:
                start, end = 0, total - 1
            else:
                start, end = 0, 0
        else:
            start, end = req_range
        send_log_entry('download', 'SUCCESS',
                       f"User '{nickname}' started external (proxy) download of '{display_filename}'.",
                       request.remote_addr, user=nickname)
        bytes_sent = 0
        length_expected = (end - start + 1) if (total and end >= start) else None
        def _gen():
            nonlocal bytes_sent
            try:
                for data in upstream.iter_content(chunk_size=1024 * 64):
                    if data:
                        bytes_sent += len(data)
                        yield data
            except (BrokenPipeError, ConnectionResetError, GeneratorExit):
                pass
            finally:
                upstream.close()
                actual_end = start + max(0, bytes_sent) - 1 if bytes_sent > 0 else start - 1
                try:
                    if total and total > 0:
                        record_part_and_check_complete(log_id, uid, game_id, start, actual_end, bytes_sent, total, nickname)
                except Exception as e:
                    send_log_entry('download', 'ERROR', f"Failed to record proxy part: {e}", request.remote_addr, user=nickname)
                stream_complete = False
                if length_expected is not None:
                    stream_complete = (bytes_sent == length_expected) and (end == (total - 1 if total else end))
                else:
                    stream_complete = (status == 200 and bytes_sent > 0)
                if stream_complete:
                    if grace > 0:
                        time.sleep(grace)
                    if update_download_status(log_id, True, uid, nickname):
                        send_log_entry('download', 'SUCCESS',
                                       f"Download completed (proxy) '{display_filename}'.",
                                       request.remote_addr, user=nickname)
        return Response(stream_with_context(_gen()), headers=headers, status=status, direct_passthrough=True)
    try:
        if local_path and os.path.exists(local_path):
            return stream_local_with_range(local_path)
        if external_url:
            return stream_external_with_range(external_url)
        abort(404, "No download source available for this item.")
    except requests.exceptions.RequestException as e:
        update_download_status(log_id, False, uid, nickname)
        send_log_entry('download', 'ERROR', f"Proxy failed for '{display_filename}': {e}", request.remote_addr, user=nickname)
        abort(502, "Failed to get the external file.")
    except Exception as e:
        update_download_status(log_id, False, uid, nickname)
        send_log_entry('download', 'ERROR', f"Error serving '{display_filename}': {e}", request.remote_addr, user=nickname)
        abort(500, "Internal error.")

if __name__ == "__main__":
    for d in ['db', 'logs']:
        os.makedirs(os.path.join(PROJECT_ROOT, d), exist_ok=True)
    setup_databases()
    host = CONFIG.get('HOST', '0.0.0.0')
    port = CONFIG.get('CORE_PORT')
    if not port:
        print("\033[91mERROR: 'CORE_PORT' not defined. Aborting.\033[0m")
        exit(1)
    threading.Timer(2.0, lambda: send_log_entry('core', 'SUCCESS', 'Tinfoil server online', 'localhost', 'system')).start()
    print("-> Core (Tinfoil) server started.")
    print(f"-> Listening on: http://{host}:{port}")
    print(f"-> Daily user limit: {CONFIG.get('DAILY_DOWNLOAD_LIMIT') or 'Unlimited'}")
    direct = "enabled" if CONFIG.get('DIRECT_LINKS', False) else "disabled"
    print(f"-> DIRECT_LINKS mode: {direct}")
    drm = "enabled" if CONFIG.get('ENABLE_DRM', True) else "disabled"
    print(f"-> DRM (legacy TINFOIL format): {drm}")
    print("-> Waiting for Tinfoil connections...")
    serve(app, host=host, port=port)