import os
import json
import subprocess
import sys
import time
from flask import Flask, session, request
from flask_babel import Babel
from datetime import datetime as dt
from collections import deque
import threading
import queue
import asyncio

app = Flask(__name__, template_folder='../templates', static_folder='../static')


# --- LOAD CONFIGURATION FROM config.json ---
try:
    with open('config.json', 'r', encoding='utf-8') as config_file:
        app.config.update(json.load(config_file))
    print("Configurations loaded successfully from config.json.")
except FileNotFoundError:
    raise RuntimeError("Configuration file 'config.json' not found in the project root.")
except json.JSONDecodeError:
    raise RuntimeError("Error reading 'config.json'. Check if the JSON format is valid.")


# --- ADDITIONAL CONFIGURATION AND GLOBAL STATE ---
app.secret_key = os.urandom(24)
app.permanent_session_lifetime = 3600

app.config.update(
    SESSION_COOKIE_SECURE=False,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=3600,
    SESSION_REFRESH_EACH_REQUEST=True
)

app.config['LANGUAGES'] = {
    'en': 'English',
    'pt_BR': 'Português (Brasil)',
    'es': 'Español',
    'ru': 'Русский',
    'zh': '中文'
}
app.config['BABEL_DEFAULT_LOCALE'] = 'pt_BR'
app.config['BABEL_TRANSLATION_DIRECTORIES'] = '../langs'

def get_locale():
    lang_cookie = request.cookies.get('language')
    if lang_cookie in app.config['LANGUAGES']:
        return lang_cookie

    if 'LANGUAGE' in app.config and app.config['LANGUAGE'] in app.config['LANGUAGES']:
        return app.config['LANGUAGE']

    return request.accept_languages.best_match(app.config['LANGUAGES'].keys())

babel = Babel(app, locale_selector=get_locale)

@app.context_processor
def inject_global_variables():
    return dict(
        babel=babel,
        app=app
    )

# --- TRANSLATION AUTOMATION FUNCTION ---
def setup_translations():
    """
    Executes pybabel commands to extract, update, and compile
    translation files, with a summarized log output.
    """
    print("Starting automatic translation setup...")
    
    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
    langs_dir = os.path.join(project_root, 'langs')
    babel_cfg_path = os.path.join(project_root, 'babel.cfg')
    pot_file_path = os.path.join(langs_dir, 'messages.pot')
    
    os.makedirs(langs_dir, exist_ok=True)

    if not os.path.exists(babel_cfg_path):
        print(" -> 'babel.cfg' file not found. Creating...")
        with open(babel_cfg_path, 'w', encoding='utf-8') as f:
            f.write('[python: app/**.py]\n[jinja2: templates/**.html]\n')

    try:
        pybabel_path = os.path.join(os.path.dirname(sys.executable), 'pybabel')
        
        print(" -> Extracting translation strings...")
        subprocess.run(
            [pybabel_path, 'extract', '-F', babel_cfg_path, '-k', '_', '-k', 'ngettext:1,2', '-o', pot_file_path, '.'],
            cwd=project_root, check=True, capture_output=True, text=True
        )

        langs_to_update = []
        for lang in app.config['LANGUAGES'].keys():
            po_file_path = os.path.join(langs_dir, lang, 'LC_MESSAGES', 'messages.po')
            command = 'update' if os.path.exists(po_file_path) else 'init'
            
            subprocess.run(
                [pybabel_path, command, '-i', pot_file_path, '-d', langs_dir, '-l', lang],
                cwd=project_root, check=True, capture_output=True, text=True
            )
            langs_to_update.append(lang)

        if langs_to_update:
              print(f" -> Updating/Initializing: {', '.join(langs_to_update)}")

        print(" -> Compiling translation files...")
        subprocess.run(
            [pybabel_path, 'compile', '-d', langs_dir, '-f'],
            cwd=project_root, check=True, capture_output=True, text=True
        )

    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        print(f"\nERROR: Failed to execute pybabel. Check if Flask-Babel is installed.")
        if isinstance(e, subprocess.CalledProcessError):
            print(f"    Command with error: {' '.join(e.cmd)}")
            print(f"    Error output: {e.stderr.strip()}")
        return

    print("Translation setup complete.")

# --- GLOBAL APPLICATION STATE ---
app.config['CORE_PROCESS'] = None
app.config['CORE_STATUS'] = "Offline"
app.config['MAX_HISTORY'] = 100
app.config['SYSTEM_START_TIME'] = dt.now().strftime('%Y-%m-%d %H:%M:%S')
app.config['ITEMS_PER_PAGE'] = 30
app.config['_titles_db'] = None
app.config['_cnmts_db'] = None
app.config['_versions_db'] = None

# --- EVENT AND LOG MANAGER ---
class EventManager:
    def __init__(self):
        self.history = deque(maxlen=app.config['MAX_HISTORY'])
        self.subscribers = []
        self.lock = threading.Lock()
    
    def subscribe(self):
        with self.lock:
            q = queue.Queue(maxsize=100)
            self.subscribers.append(q)
            return q
    
    def unsubscribe(self, q):
        with self.lock:
            if q in self.subscribers:
                self.subscribers.remove(q)
    
    def add_event(self, event):
        from .models import store_log_entry # Local import to avoid circular dependencies
        with self.lock:
            store_log_entry(event)
            self.history.append(event)
            for q in self.subscribers:
                try:
                    q.put_nowait(event)
                except queue.Full:
                    pass
    
    def get_recent_history(self):
        with self.lock:
            return [entry for entry in self.history if entry['timestamp'] >= app.config['SYSTEM_START_TIME']]

event_manager = EventManager()

# --- CENTRALIZED LOG FUNCTION ---
# Moved from routes.py to __init__.py to break a circular import.
def add_log_entry(event_type, message, ip=None, user=None, source='admin', extra_data=None):
    """
    Adds a log entry and updates the core status if the message is relevant.
    """
    timestamp = dt.now().strftime('%Y-%m-%d %H:%M:%S')
    entry = {
        'id': int(time.time() * 1000), 'timestamp': timestamp, 'type': event_type,
        'level': event_type.upper(), 'message': message, 'ip': ip or 'N/A',
        'user': user or 'N/A', 'source': source, 'data': extra_data or {}
    }
    event_manager.add_event(entry)

    # Status update logic based on the log level from the core
    if source == 'core' and entry['level'] == 'SUCCESS':
        app.config['CORE_STATUS'] = "Online"
    elif source == 'core' and message == 'Shop core terminated':
        app.config['CORE_STATUS'] = "Offline"


loop = asyncio.new_event_loop()
threading.Thread(target=loop.run_forever, daemon=True).start()


# --- AUTOMATION EXECUTION AND ROUTE IMPORT ---
if os.environ.get('WERKZEUG_RUN_MAIN') != 'true':
    setup_translations()

# The route import MUST remain at the end to avoid other circular dependencies.
from app import routes