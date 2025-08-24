# -*- coding: utf-8 -*-
import os
import sqlite3
import json
import uuid
import hashlib
import math
import re
import time
import shutil
import threading
from datetime import datetime as dt
from flask import render_template, request, redirect, url_for, flash, session, Response, jsonify, send_file, make_response, abort
from functools import wraps
import queue
from flask_babel import _
from app import app, event_manager, add_log_entry
from .utils import format_bytes, get_update_number, format_date, generate_password, get_pagination_range
from .models import (
    get_related_content, check_content_in_db, get_games_count,
    get_db_connection, get_log_files, get_log_content,
    load_all_databases
)
from .core_manager import check_core_status, restart_core, toggle_core
from .watcher_manager import WatcherManager
from . import library
config_file_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'config.json'))

def watcher_logger(type, message, data=None):
    """Bridge function to the Flask logging system."""
    add_log_entry(
        type,
        message,
        ip='N/A',
        user='system',
        source='watcher',
        extra_data=data or {}
    )

watcher = WatcherManager(
    config_path=config_file_path,
    logger_callback=watcher_logger
)

def ensure_users_banned_column():
    """Ensures the 'banned' column exists in the users table (users.db)."""
    try:
        conn = sqlite3.connect(app.config['USER_DB'])
        cur = conn.cursor()
        cur.execute("PRAGMA table_info(users)")
        cols = {r[1] for r in cur.fetchall()}
        if 'banned' not in cols:
            cur.execute("ALTER TABLE users ADD COLUMN banned INTEGER DEFAULT 0")
            conn.commit()
    except Exception as e:
        app.logger.warning(f"[migrate] Failed to ensure 'banned' column in users: {e}")
    finally:
        try:
            conn.close()
        except Exception:
            pass

def ensure_quote_table():
    """Ensures the 'quote' table exists in users_downloads.db."""
    downloads_db = app.config.get('DOWNLOADS_DB')
    if not downloads_db:
        return
    os.makedirs(os.path.dirname(downloads_db), exist_ok=True)
    try:
        conn = sqlite3.connect(downloads_db)
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS quote (
                date TEXT NOT NULL,
                user_uid TEXT NOT NULL,
                download_count INTEGER DEFAULT 0,
                last_update TIMESTAMP,
                PRIMARY KEY(date, user_uid)
            )
        """)
        conn.commit()
    except Exception as e:
        app.logger.warning(f"[migrate] Failed to ensure 'quote' table: {e}")
    finally:
        try:
            conn.close()
        except Exception:
            pass

def reset_user_daily_quota(uid: str):
    """Resets a user's daily quota (quote table in users_downloads.db)."""
    ensure_quote_table()
    downloads_db = app.config.get('DOWNLOADS_DB') or os.path.join(os.path.dirname(app.root_path), 'db', 'users_downloads.db')
    today = dt.now().strftime("%Y-%m-%d")
    try:
        conn = sqlite3.connect(downloads_db)
        cur = conn.cursor()
        cur.execute("UPDATE quote SET download_count = 0, last_update = CURRENT_TIMESTAMP WHERE date = ? AND user_uid = ?", (today, uid))
        if cur.rowcount == 0:
            cur.execute("""
                INSERT INTO quote (date, user_uid, download_count, last_update)
                VALUES (?, ?, 0, CURRENT_TIMESTAMP)
            """, (today, uid))
        conn.commit()
        return True, None
    except Exception as e:
        return False, str(e)
    finally:
        try:
            conn.close()
        except Exception:
            pass

def setup_logs_db():
    log_db_path = app.config['LOG_DB']
    log_dir = os.path.dirname(log_db_path)
    if log_dir:
        os.makedirs(log_dir, exist_ok=True)
    conn = sqlite3.connect(log_db_path)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS logs (id INTEGER PRIMARY KEY, timestamp TEXT, type TEXT, level TEXT, message TEXT, ip TEXT, user TEXT, source TEXT, data TEXT)''')
    conn.commit()
    conn.close()

def setup_database():
    if not os.path.exists(app.config['USER_DB']):
        conn = sqlite3.connect(app.config['USER_DB'])
        cursor = conn.cursor()
        cursor.execute("""CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, nickname TEXT UNIQUE NOT NULL, password TEXT NOT NULL, uid TEXT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, uid_linked_at TIMESTAMP)""")
        try:
            cursor.execute("ALTER TABLE users ADD COLUMN banned INTEGER DEFAULT 0")
        except Exception:
            pass
        admin_password = generate_password()
        hashed_pw = hashlib.sha256(admin_password.encode()).hexdigest()
        cursor.execute("INSERT INTO users (nickname, password) VALUES (?, ?)", ('admin', hashed_pw))
        conn.commit()
        conn.close()
        app.logger.info(f"\033[92mUser 'admin' created with password: {admin_password}\033[0m")
        app.logger.warning(f"\033[91mSAVE THIS PASSWORD AS IT WILL NOT BE SHOWN AGAIN!\033[0m")
        add_log_entry('system', _('Admin user created'), 'localhost', 'system')
    else:
        ensure_users_banned_column()

def setup_logging():
    from logging.handlers import RotatingFileHandler
    import logging
    log_dir = "logs"
    os.makedirs(log_dir, exist_ok=True)
    log_handler = RotatingFileHandler(os.path.join(log_dir, 'admin.log'), maxBytes=1024 * 1024 * 5, backupCount=5)
    log_handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
    app.logger.addHandler(log_handler)
    app.logger.setLevel(logging.DEBUG if app.config['DEBUG_MODE'] else logging.INFO)

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session:
            add_log_entry('warning', f'Route access denied {request.path}: Unauthenticated session', request.remote_addr, 'N/A')
            flash(_('Please log in to access this page'), 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.context_processor
def inject_global_vars():
    return dict(current_year=dt.now().year, datetime=dt, format_bytes=format_bytes, get_update_number=get_update_number, format_date=format_date)

@app.route('/lang/<language>')
def set_language(language=None):
    response = make_response(redirect(request.referrer or url_for('dashboard')))
    if language in app.config['LANGUAGES']:
        response.set_cookie('language', language, max_age=365 * 24 * 60 * 60)
        current_user = session.get('username', 'system')
        ip_addr = request.remote_addr
        try:
            with open(config_file_path, 'r', encoding='utf-8') as f:
                current_config = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            current_config = {}
        old_language = current_config.get('LANGUAGE')
        if old_language != language:
            current_config['LANGUAGE'] = language
            try:
                with open(config_file_path, 'w', encoding='utf-8') as f:
                    json.dump(current_config, f, indent=2)
                app.config.update(current_config)
                app.logger.info(f"Global language changed to '{language}' via menu. Reloading databases.")
                if load_all_databases():
                    add_log_entry('system', _('Global language changed and data reloaded.'), ip_addr, current_user)
                else:
                    add_log_entry('error', _('Failed to reload data after language change.'), ip_addr, current_user)
                    flash(_('Language changed, but failed to reload data. Please restart the application.'), 'danger')
                restart_core()
            except Exception as e:
                app.logger.error(f"Error saving config.json in set_language route: {e}")
                add_log_entry('error', f"Failed to save config.json: {e}", ip_addr, current_user)
                flash(_('An error occurred while trying to change the global language.'), 'danger')
    return response

@app.route('/login', methods=['GET', 'POST'])
def login():
    ensure_users_banned_column()
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE nickname = ?', (username,)).fetchone()
        conn.close()
        if user and user['password'] == password_hash:
            if 'banned' in user.keys() and int(user['banned'] or 0) == 1:
                add_log_entry('login', _('Banned user attempted login'), request.remote_addr, username)
                flash(_('Your account is banned.'), 'danger')
                return render_template('admin/login.html')
            session.clear()
            session.permanent = True
            session['logged_in'] = True
            session['username'] = username
            session['session_id'] = str(uuid.uuid4())
            add_log_entry('login', _('Login successful'), request.remote_addr, username)
            return redirect(url_for('dashboard'))
        else:
            add_log_entry('login', _('Failed login attempt'), request.remote_addr, username)
            flash(_('Invalid credentials. Please try again.'), 'danger')
    return render_template('admin/login.html')

@app.route('/logout')
@login_required
def logout():
    username = session.get('username', 'Unknown')
    add_log_entry('logout', _('User logged out'), request.remote_addr, username)
    session.clear()
    flash(_('You have been successfully logged out.'), 'success')
    return redirect(url_for('login'))

@app.route('/')
@login_required
def dashboard():
    conn = get_db_connection()
    user_count = conn.execute('SELECT COUNT(*) FROM users').fetchone()[0]
    conn.close()
    games_count = get_games_count()
    check_core_status()
    add_log_entry('system', 'Accessed the dashboard', request.remote_addr, session.get('username', 'unknown'))
    log_files = get_log_files()[:5]
    return render_template('admin/dashboard.html', user_count=user_count, games_count=games_count, core_status=app.config['CORE_STATUS'], core_port=app.config['CORE_PORT'], log_files=log_files)

@app.route('/profile')
@login_required
def profile():
    conn = get_db_connection()
    ensure_users_banned_column()
    users = conn.execute('SELECT * FROM users').fetchall()
    conn.close()
    return render_template('admin/profile.html', users=users)

@app.route('/profile/ban', methods=['POST'])
@login_required
def ban_user():
    """Ban user (banned=1). Accepts user_id or nickname."""
    user_id = request.form.get('user_id')
    nickname = request.form.get('nickname')
    current_user = session.get('username', 'admin')
    if not user_id and not nickname:
        flash(_('User identifier is required.'), 'danger')
        return redirect(url_for('profile'))
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        if user_id:
            cur.execute("UPDATE users SET banned = 1 WHERE id = ?", (user_id,))
        else:
            cur.execute("UPDATE users SET banned = 1 WHERE nickname = ?", (nickname,))
        conn.commit()
        conn.close()
        add_log_entry('user', _('User banned'), request.remote_addr, current_user)
        flash(_('User has been banned.'), 'success')
    except Exception as e:
        app.logger.error(f"Error banning user: {e}")
        flash(_('Error banning user: %(error)s', error=str(e)), 'danger')
    return redirect(url_for('profile'))

@app.route('/profile/unban', methods=['POST'])
@login_required
def unban_user():
    """Unban user (banned=0). Accepts user_id or nickname."""
    user_id = request.form.get('user_id')
    nickname = request.form.get('nickname')
    current_user = session.get('username', 'admin')
    if not user_id and not nickname:
        flash(_('User identifier is required.'), 'danger')
        return redirect(url_for('profile'))
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        if user_id:
            cur.execute("UPDATE users SET banned = 0 WHERE id = ?", (user_id,))
        else:
            cur.execute("UPDATE users SET banned = 0 WHERE nickname = ?", (nickname,))
        conn.commit()
        conn.close()
        add_log_entry('user', _('User unbanned'), request.remote_addr, current_user)
        flash(_('User has been unbanned.'), 'success')
    except Exception as e:
        app.logger.error(f"Error unbanning user: {e}")
        flash(_('Error unbanning user: %(error)s', error=str(e)), 'danger')
    return redirect(url_for('profile'))

@app.route('/profile/clear_quota', methods=['POST'])
@login_required
def clear_user_quota():
    """Clears the daily download quota for a user (resets download_count for today in 'quote')."""
    user_id = request.form.get('user_id')
    nickname = request.form.get('nickname')
    current_user = session.get('username', 'admin')
    if not user_id and not nickname:
        flash(_('User identifier is required.'), 'danger')
        return redirect(url_for('profile'))
    try:
        conn = get_db_connection()
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        if user_id:
            user = cur.execute("SELECT nickname, uid FROM users WHERE id = ?", (user_id,)).fetchone()
        else:
            user = cur.execute("SELECT nickname, uid FROM users WHERE nickname = ?", (nickname,)).fetchone()
        conn.close()
        if not user:
            flash(_('User not found.'), 'danger')
            return redirect(url_for('profile'))
        target_nick = user['nickname']
        uid = user['uid']
        if not uid:
            flash(_('User does not have a linked UID. Cannot clear quota.'), 'danger')
            return redirect(url_for('profile'))
        ok, err = reset_user_daily_quota(uid)
        if ok:
            add_log_entry('user', _('Daily download quota reset for "%(nickname)s"', nickname=target_nick), request.remote_addr, current_user)
            flash(_('Daily quota reset for "%(nickname)s".', nickname=target_nick), 'success')
        else:
            flash(_('Failed to reset quota: %(error)s', error=err or 'unknown'), 'danger')
    except Exception as e:
        app.logger.error(f"Error clearing quota: {e}")
        flash(_('Error clearing quota: %(error)s', error=str(e)), 'danger')
    return redirect(url_for('profile'))

@app.route('/create_user', methods=['POST'])
@login_required
def create_user():
    username = request.form['username']
    current_user = session.get('username', 'admin')
    if not username:
        flash(_('Username is required.'), 'danger')
        return redirect(url_for('profile'))
    password = generate_password()
    password_hash = hashlib.sha256(password.encode()).hexdigest()
    try:
        conn = get_db_connection()
        conn.execute('INSERT INTO users (nickname, password, banned) VALUES (?, ?, 0)', (username, password_hash))
        conn.commit()
        conn.close()
        add_log_entry('user', _('User "%(username)s" created', username=username), request.remote_addr, current_user)
        flash(_('User "%(username)s" created successfully! Password: %(password)s', username=username, password=password), 'success')
    except sqlite3.IntegrityError:
        flash(_('User "%(username)s" already exists.', username=username), 'danger')
    return redirect(url_for('profile'))

@app.route('/change_password', methods=['POST'])
@login_required
def change_password():
    user_id = request.form['user_id']
    new_password = request.form['new_password']
    current_user = session.get('username', 'admin')
    if not new_password:
        flash(_('New password is required.'), 'danger')
        return redirect(url_for('profile'))
    password_hash = hashlib.sha256(new_password.encode()).hexdigest()
    conn = get_db_connection()
    conn.execute('UPDATE users SET password = ? WHERE id = ?', (password_hash, user_id))
    conn.commit()
    user = conn.execute('SELECT nickname FROM users WHERE id = ?', (user_id,)).fetchone()
    conn.close()
    if user:
        add_log_entry('user', _('Password changed for "%(nickname)s"', nickname=user["nickname"]), request.remote_addr, current_user)
        flash(_('Password for "%(nickname)s" changed successfully.', nickname=user["nickname"]), 'success')
    return redirect(url_for('profile'))

@app.route('/delete_user', methods=['POST'])
@login_required
def delete_user():
    user_id = request.form['user_id']
    if int(user_id) == 1:
        flash(_('The "admin" user (ID 1) cannot be deleted.'), 'danger')
        return redirect(url_for('profile'))
    current_user = session.get('username', 'admin')
    conn = get_db_connection()
    user = conn.execute('SELECT nickname FROM users WHERE id = ?', (user_id,)).fetchone()
    if user:
        conn.execute('DELETE FROM users WHERE id = ?', (user_id,))
        conn.commit()
        add_log_entry('user', _('User "%(nickname)s" deleted', nickname=user["nickname"]), request.remote_addr, current_user)
        flash(_('User "%(nickname)s" deleted successfully.', nickname=user["nickname"]), 'success')
    else:
        flash(_('User not found.'), 'danger')
    conn.close()
    return redirect(url_for('profile'))

@app.route('/view_log/<path:filename>')
@login_required
def view_log(filename):
    log_path = os.path.join('logs', filename)
    if not os.path.exists(log_path):
        flash(_('Log file not found.'), 'danger')
        return redirect(url_for('dashboard'))
    log_content = get_log_content(log_path)
    return render_template('admin/log_view.html', filename=filename, log_content=log_content)

@app.route('/restart_core', endpoint='restart_core')
@login_required
def restart_core_route():
    current_user = session.get('username', 'admin')
    restart_core()
    add_log_entry('system', _('Shop core restarted'), request.remote_addr, current_user)
    flash(_('Shop core restarted successfully.'), 'success')
    return redirect(url_for('dashboard'))

@app.route('/toggle_core', endpoint='toggle_core')
@login_required
def toggle_core_route():
    current_user = session.get('username', 'admin')
    message, status = toggle_core()
    add_log_entry('system', message, request.remote_addr, current_user)
    if status == 'started':
        flash(_('Tinfoil server started successfully.'), 'success')
    elif status == 'stopped':
        flash(_('Tinfoil server stopped successfully.'), 'success')
    else:
        flash(_('Tinfoil server status changed.'), 'success')
    return redirect(url_for('dashboard'))

@app.route('/realtime_logs')
@login_required
def realtime_logs():
    def event_stream():
        q = event_manager.subscribe()
        try:
            history = event_manager.get_recent_history()
            for entry in history:
                if entry.get('type') not in ['scan_progress', 'scan_complete']:
                    yield f"data: {json.dumps(entry)}\n\n"
            while True:
                try:
                    entry = q.get(timeout=15)
                    if entry.get('type') not in ['scan_progress', 'scan_complete']:
                        yield f"data: {json.dumps(entry)}\n\n"
                except queue.Empty:
                    yield ":keepalive\n\n"
        finally:
            event_manager.unsubscribe(q)
    return Response(event_stream(), mimetype='text/event-stream', headers={'Cache-Control': 'no-cache', 'X-Accel-Buffering': 'no'})

@app.route('/api/core_status')
@login_required
def api_core_status():
    check_core_status()
    return jsonify({'status': app.config['CORE_STATUS'], 'port': app.config['CORE_PORT']})

@app.route('/api/core_log', methods=['POST'])
def receive_core_log():
    try:
        log_data = request.json
        event_type = log_data.get('level', 'info').lower()
        add_log_entry(
            event_type,
            log_data.get('message', ''),
            ip=log_data.get('ip', 'N/A'),
            user=log_data.get('user', 'N/A'),
            source='core',
            extra_data=log_data.get('data', {})
        )
        return '', 200
    except Exception as e:
        app.logger.error(f"Error processing log from core: {str(e)}")
        return '', 500

@app.route('/stored_logs')
@login_required
def stored_logs():
    search_query = request.args.get('search', ''); log_type = request.args.get('type', ''); source_filter = request.args.get('source', ''); user_filter = request.args.get('user', ''); start_date = request.args.get('start_date', ''); end_date = request.args.get('end_date', ''); page = request.args.get('page', 1, type=int); per_page = request.args.get('per_page', 50, type=int)
    try:
        conn = sqlite3.connect(app.config['LOG_DB']); conn.row_factory = sqlite3.Row; c = conn.cursor()
        count_query = "SELECT COUNT(*) FROM logs WHERE 1=1"; query = "SELECT * FROM logs WHERE 1=1"; params = []
        if search_query: query += " AND message LIKE ?"; count_query += " AND message LIKE ?"; params.append(f'%{search_query}%')
        if log_type: query += " AND type = ?"; count_query += " AND type = ?"; params.append(log_type.lower())
        if source_filter: query += " AND source = ?"; count_query += " AND source = ?"; params.append(source_filter)
        if user_filter: query += " AND user = ?"; count_query += " AND user = ?"; params.append(user_filter)
        if start_date: query += " AND timestamp >= ?"; count_query += " AND timestamp >= ?"; params.append(start_date)
        if end_date: query += " AND timestamp <= ?"; count_query += " AND timestamp <= ?"; params.append(end_date)
        c.execute(count_query, params); total_logs = c.fetchone()[0]
        query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"; params.extend([per_page, (page - 1) * per_page])
        c.execute(query, params); logs = c.fetchall()
        c.execute("SELECT DISTINCT type FROM logs"); log_types = [row[0] for row in c.fetchall()]
        c.execute("SELECT DISTINCT source FROM logs"); sources = [row[0] for row in c.fetchall()]
        conn_users = sqlite3.connect(app.config['USER_DB']); conn_users.row_factory = sqlite3.Row; c_users = conn_users.cursor()
        c_users.execute("SELECT DISTINCT nickname FROM users"); users = [row['nickname'] for row in c_users.fetchall()]
        conn_users.close(); conn.close()
        total_pages = (total_logs + per_page - 1) // per_page
        return render_template('admin/stored_logs.html', logs=logs, search_query=search_query, log_types=log_types, sources=sources, users=users, selected_type=log_type, selected_source=source_filter, selected_user=user_filter, start_date=start_date, end_date=end_date, page=page, per_page=per_page, total_pages=total_pages, total_logs=total_logs)
    except Exception as e:
        app.logger.error(f"Error accessing stored logs: {str(e)}")
        return render_template('admin/stored_logs.html', error=str(e))

@app.route('/games')
@login_required
def manage_games():
    search_query = request.args.get('search', ''); title_filter = request.args.get('name', ''); tid_filter = request.args.get('tid', '')
    try:
        conn = sqlite3.connect(app.config['DB_FILE']); conn.row_factory = sqlite3.Row; c = conn.cursor()
        query = "SELECT * FROM games WHERE 1=1"; params = []
        if search_query: query += " AND (name LIKE ? OR tid LIKE ?)"; params.extend([f'%{search_query}%', f'%{search_query}%'])
        if title_filter: query += " AND name LIKE ?"; params.append(f'%{title_filter}%')
        if tid_filter: query += " AND tid LIKE ?"; params.append(f'%{tid_filter}%')
        c.execute(query, params); games = c.fetchall(); conn.close()
        return render_template('admin/games.html', games=games, search_query=search_query, title_filter=title_filter, tid_filter=tid_filter)
    except Exception as e:
        app.logger.error(f"Error accessing games: {str(e)}")
        return render_template('admin/games.html', error=str(e))

@app.route('/download_game/<string:tid>')
@login_required
def download_game(tid):
    try:
        conn = sqlite3.connect(app.config['DB_FILE']); c = conn.cursor(); c.execute("SELECT url FROM games WHERE tid = ?", (tid,)); game = c.fetchone(); conn.close()
        if game and game[0]:
            file_path = game[0]
            if os.path.exists(file_path): return send_file(file_path, as_attachment=True)
        flash(_('Game file not found.'), 'danger'); return redirect(url_for('manage_games'))
    except Exception as e:
        app.logger.error(f"Error downloading game {tid}: {str(e)}"); flash(_('Error downloading game: %(error)s', error=str(e)), 'danger'); return redirect(url_for('manage_games'))

@app.route('/delete_game', methods=['POST'])
@login_required
def delete_game():
    tid = request.form.get('tid')
    current_user = session.get('username', 'admin')
    try:
        conn = sqlite3.connect(app.config['DB_FILE']); c = conn.cursor()
        c.execute("SELECT name, url FROM games WHERE tid = ?", (tid,)); game = c.fetchone()
        if game:
            game_name, game_url = game
            c.execute("DELETE FROM games WHERE tid = ?", (tid,)); conn.commit()
            if game_url and os.path.exists(game_url):
                try: os.remove(game_url); app.logger.info(f"File removed: {game_url}")
                except Exception as e: app.logger.error(f"Error removing file {game_url}: {str(e)}")
            add_log_entry('game', _('Game removed: %(name)s (TID: %(tid)s)', name=game_name, tid=tid), request.remote_addr, current_user)
            flash(_('Game "%(name)s" removed successfully.', name=game_name), 'success')
        else: flash(_('Game not found.'), 'danger')
        conn.close(); return redirect(url_for('manage_games'))
    except Exception as e:
        app.logger.error(f"Error removing game {tid}: {str(e)}"); flash(_('Error removing game: %(error)s', error=str(e)), 'danger'); return redirect(url_for('manage_games'))

@app.route('/library', methods=['GET'], endpoint='library')
@login_required
def library_route():
    return library.show_library_page()

@app.route('/library/game/<game_id>', endpoint='library_game_details')
@login_required
def library_game_details_route(game_id):
    return library.show_game_details_page(game_id)

@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    if request.method == 'POST':
        current_user = session.get('username')
        try:
            with open(config_file_path, 'r', encoding='utf-8') as f:
                current_config = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            current_config = {}
        current_config.update({
            'CORE_PORT': int(request.form.get('CORE_PORT')),
            'CORE_PUBLIC_URL': request.form.get('CORE_PUBLIC_URL').strip(),
            'SHOP_TITLE': request.form.get('SHOP_TITLE', 'Tinfoil Shop').strip()
        })
        try:
            with open(config_file_path, 'w', encoding='utf-8') as f:
                json.dump(current_config, f, indent=2)
            app.config.update(current_config)
            add_log_entry('system', _('Core settings changed. Restarting core...'), request.remote_addr, current_user)
            restart_core()
            flash(_('Settings saved successfully! The core server is being restarted.'), 'success')
        except Exception as e:
            add_log_entry('error', _('Failed to save settings: %(error)s', error=str(e)), request.remote_addr, current_user)
            flash(_('Error saving settings: %(error)s', error=str(e)), 'danger')
        return redirect(url_for('settings'))
    return render_template('admin/settings.html', config=app.config)

@app.route('/messages', methods=['GET', 'POST'], endpoint='edit_messages')
@login_required
def edit_messages():
    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
    messages_path = os.path.join(project_root, 'messages.json')
    backup_path = messages_path + '.bak'
    if request.method == 'POST':
        current_user = session.get('username')
        if os.path.exists(messages_path):
            try:
                shutil.copy2(messages_path, backup_path)
            except Exception as e:
                flash(_('Error creating backup file: %(error)s', error=str(e)), 'danger')
                return redirect(url_for('edit_messages'))
        new_messages = {}
        for key, value in request.form.items():
            new_messages[key] = value
        try:
            with open(messages_path, 'w', encoding='utf-8') as f:
                json.dump(new_messages, f, indent=2, ensure_ascii=False)
            add_log_entry('system', _('Message file updated. Restarting core...'), request.remote_addr, current_user)
            restart_core()
            flash(_('Messages saved successfully! The core server is being restarted automatically.'), 'success')
        except Exception as e:
            add_log_entry('error', _('Failed to save message file: %(error)s', error=str(e)), request.remote_addr, current_user)
            flash(_('Error saving messages: %(error)s', error=str(e)), 'danger')
        return redirect(url_for('edit_messages'))
    try:
        with open(messages_path, 'r', encoding='utf-8') as f:
            messages = json.load(f)
    except FileNotFoundError:
        flash(_('Message file (messages.json) not found in the project root.'), 'danger')
        messages = {}
    except json.JSONDecodeError:
        flash(_('Error reading messages.json. The file might be corrupted. Check the file format.'), 'danger')
        messages = {}
    return render_template('admin/edit_messages.html', messages=messages)

@app.route('/watcher')
@login_required
def manage_watcher():
    return render_template('admin/watcher.html', title=_('File Watcher'))

@app.route('/api/watcher/status', methods=['GET'])
@login_required
def get_watcher_status():
    return jsonify(watcher.get_status())

@app.route('/api/watcher/start', methods=['POST'])
@login_required
def start_watcher():
    watcher.start()
    add_log_entry('system', _('File watcher service started.'), request.remote_addr, session.get('username'))
    return jsonify({"message": _("Watcher started successfully.")})

@app.route('/api/watcher/stop', methods=['POST'])
@login_required
def stop_watcher():
    watcher.stop()
    add_log_entry('system', _('File watcher service stopped.'), request.remote_addr, session.get('username'))
    return jsonify({"message": _("Watcher stopped successfully.")})

@app.route('/api/watcher/add_path', methods=['POST'])
@login_required
def add_watcher_path():
    data = request.get_json()
    path_to_add = data.get('path')
    if not path_to_add:
        return jsonify({"error": _("Path is required.")}), 400
    if watcher.add_directory(path_to_add):
        add_log_entry('system', f"{_('Directory added to watcher:')} {path_to_add}", request.remote_addr, session.get('username'))
        return jsonify({"message": f"{_('Directory added:')} {path_to_add}"})
    else:
        return jsonify({"error": _("Failed to add directory. Check console logs for details.")}), 400

@app.route('/api/watcher/remove_path', methods=['POST'])
@login_required
def remove_watcher_path():
    data = request.get_json()
    path_to_remove = data.get('path')
    if not path_to_remove:
        return jsonify({"error": _("Path is required.")}), 400
    if watcher.remove_directory(path_to_remove):
        add_log_entry('system', f"{_('Directory removed from watcher:')} {path_to_remove}", request.remote_addr, session.get('username'))
        return jsonify({"message": f"{_('Directory removed:')} {path_to_remove}"})
    else:
        return jsonify({"error": _("Directory not found in watch list.")}), 404
        
@app.route('/api/watcher/full_scan', methods=['POST'])
@login_required
def full_scan_watcher():
    if watcher.scan_status['is_scanning']:
        return jsonify({"message": _("A scan is already in progress.")}), 409
    add_log_entry('system', _('Full library scan started in the background.'), request.remote_addr, session.get('username'))
    threading.Thread(target=watcher.run_full_scan, daemon=True).start()
    return jsonify({"message": _("Full scan started. Progress will be shown below.")}), 202

@app.route('/api/watcher/progress_stream')
@login_required
def watcher_progress_stream():
    def event_stream():
        q = event_manager.subscribe()
        try:
            while True:
                try:
                    entry = q.get(timeout=20)
                    event_type = entry.get('type')
                    if event_type in ['scan_progress', 'scan_complete']:
                        event_data = json.dumps(entry.get('data', {}))
                        yield f"event: {event_type}\ndata: {event_data}\n\n"
                except queue.Empty:
                    yield ":keepalive\n\n"
        finally:
            event_manager.unsubscribe(q)
    return Response(event_stream(), mimetype='text/event-stream', headers={'Cache-Control': 'no-cache', 'X-Accel-Buffering': 'no'})

@app.route('/api/quote/list')
@login_required
def api_quote_list():
    """Returns today's download count for users with a UID: { items: [ { id, nickname, uid, count } ] }"""
    ensure_quote_table()
    today = dt.now().strftime("%Y-%m-%d")
    downloads_db = app.config.get('DOWNLOADS_DB')
    items = []
    try:
        conn_u = sqlite3.connect(app.config['USER_DB'])
        conn_u.row_factory = sqlite3.Row
        users = conn_u.execute("SELECT id, nickname, uid FROM users WHERE uid IS NOT NULL AND uid != ''").fetchall()
        conn_u.close()
        conn_d = sqlite3.connect(downloads_db)
        conn_d.row_factory = sqlite3.Row
        for u in users:
            row = conn_d.execute(
                "SELECT download_count FROM quote WHERE date = ? AND user_uid = ?",
                (today, u['uid'])
            ).fetchone()
            items.append({
                "id": u['id'],
                "nickname": u['nickname'],
                "uid": u['uid'],
                "count": int(row['download_count']) if row and row['download_count'] is not None else 0
            })
        conn_d.close()
    except Exception as e:
        app.logger.error(f"/api/quote/list error: {e}")
        return jsonify({"items": [], "error": str(e)}), 500
    return jsonify({"items": items})

@app.route('/api/quote/details')
@login_required
def api_quote_details():
    """Returns today's downloads for a UID: { items: [ { game_name, file_size, file_size_human, downloaded_at, completed } ] }"""
    uid = request.args.get('uid', '').strip()
    if not uid:
        return jsonify({"items": [], "error": "uid required"}), 400
    downloads_db = app.config.get('DOWNLOADS_DB')
    items = []
    def _fmt_size(n):
        try:
            n = int(n or 0)
        except Exception:
            return str(n or 0)
        units = ['B','KB','MB','GB','TB']
        s = 0
        f = float(n)
        while f >= 1024 and s < len(units)-1:
            f /= 1024.0
            s += 1
        return f"{f:.2f} {units[s]}"
    try:
        conn = sqlite3.connect(downloads_db)
        conn.row_factory = sqlite3.Row
        rows = conn.execute("""
            SELECT game_name, file_size, downloaded_at, completed
              FROM download_history
             WHERE user_uid = ?
               AND DATE(downloaded_at, 'localtime') = DATE('now', 'localtime')
             ORDER BY downloaded_at DESC
        """, (uid,)).fetchall()
        conn.close()
        for r in rows:
            items.append({
                "game_name": r["game_name"],
                "file_size": r["file_size"],
                "file_size_human": _fmt_size(r["file_size"]),
                "downloaded_at": r["downloaded_at"],
                "completed": bool(r["completed"])
            })
    except Exception as e:
        app.logger.error(f"/api/quote/details error: {e}")
        return jsonify({"items": [], "error": str(e)}), 500
    return jsonify({"items": items})