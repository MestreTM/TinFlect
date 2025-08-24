import sqlite3
import json
import re
import os
from urllib.parse import unquote
from datetime import datetime as dt
from flask_babel import _
from app import app

# --- DATABASE INTERACTION AND LIBRARY LOGIC FUNCTIONS ---

def get_db_connection(db_name='USER_DB'):
    """Returns a connection to the database specified in the configuration."""
    db_path = app.config[db_name]
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn

# --- load_all_databases FUNCTION (MODIFIED FOR DYNAMIC LOADING) ---
def load_all_databases():
    """
    Loads reference databases (TitleDB, cnmts, versions).
    The TitleDB is loaded dynamically based on the application's language configuration.
    """
    try:
        app.logger.info("Loading reference databases...")

        app.logger.info("Determining TitleDB file based on language configuration...")
        lang_config = app.config.get('LANGUAGE', 'en_US')
        
        lang_to_region_map = {
            'en': 'US', 'es': 'ES', 'de': 'DE', 'fr': 'FR', 'it': 'IT',
            'pt': 'PT', 'ja': 'JP', 'ko': 'KR', 'ru': 'RU', 'zh': 'CN'
        }

        lang_parts = lang_config.split('_')
        lang = lang_parts[0].lower()
        region = lang_parts[1].upper() if len(lang_parts) > 1 else lang_to_region_map.get(lang, 'US').upper()

        titles_dir = 'titledb'
        primary_filename = f"titles.{region}.{lang}.json"
        primary_path = os.path.join(titles_dir, primary_filename)
        fallback_path = os.path.join(titles_dir, 'titles.US.en.json')

        titles_db_path_to_load = None

        if os.path.exists(primary_path):
            titles_db_path_to_load = primary_path
        else:
            app.logger.warning(f"Title file for '{lang_config}' ('{primary_path}') not found.")
            app.logger.info(f"Using fallback file: '{fallback_path}'.")
            titles_db_path_to_load = fallback_path
        
        with open(titles_db_path_to_load, 'r', encoding='utf-8') as f:
            app.config['_titles_db'] = json.load(f)
        app.logger.info(f"Title file '{titles_db_path_to_load}' loaded successfully.")

        with open('titledb/cnmts.json', 'r', encoding='utf-8') as f:
            app.config['_cnmts_db'] = json.load(f)
        with open('titledb/versions.json', 'r', encoding='utf-8') as f:
            app.config['_versions_db'] = json.load(f)
        
        app.logger.info("Reference databases loaded successfully.")
        return True

    except FileNotFoundError as e:
        app.logger.error(f"Fatal error: Reference database file not found: {e}.")
        return False
    except Exception as e:
        app.logger.error(f"Error loading JSON from reference databases: {e}")
        return False

def check_content_in_db(tid):
    """Checks if a generic TID exists in the local 'games' table."""
    if not tid: return False
    try:
        conn = get_db_connection('DB_FILE')
        cursor = conn.cursor()
        cursor.execute("SELECT 1 FROM games WHERE tid = ?", (tid,))
        exists = cursor.fetchone() is not None
        conn.close()
        return exists
    except sqlite3.Error as e:
        app.logger.error(f"Error checking TID {tid} in the database: {str(e)}")
        return False

def check_specific_update_in_db(update_tid, version_int):
    """
    Reliably checks if a specific version of an update exists in the local DB.
    """
    if not update_tid or version_int is None: return False
    try:
        conn = get_db_connection('DB_FILE')
        cursor = conn.cursor()
        cursor.execute("SELECT 1 FROM games WHERE tid = ? AND version = ?", (update_tid, str(version_int)))
        exists = cursor.fetchone() is not None
        conn.close()
        return exists
    except sqlite3.Error as e:
        app.logger.error(f"Error checking update {update_tid} v{version_int}: {str(e)}")
        return False

def get_main_title_id(app_id):
    """Determines the base game Title ID for a given update or DLC App ID."""
    app_id_lower = app_id.lower()
    if app_id_lower.endswith('000'):
        return app_id.upper()
        
    cnmts_db = app.config.get('_cnmts_db', {})
    if cnmts_db and app_id_lower in cnmts_db:
        version_keys = list(cnmts_db[app_id_lower].keys())
        if version_keys:
            latest_version_info = cnmts_db[app_id_lower][version_keys[-1]]
            if 'otherApplicationId' in latest_version_info:
                return latest_version_info['otherApplicationId'].upper()
                
    app.logger.warning(f"Could not find 'otherApplicationId' for {app_id}. Using prefix fallback.")
    return app_id[:-3].upper() + '000'

def get_related_content(start_id):
    """
    Fetches the complete list of updates and DLCs from the reference databases
    and, for each one, checks if it exists in the LOCAL database (games.db).
    """
    from .utils import get_update_number
    titles_db = app.config.get('_titles_db', {})
    cnmts_db = app.config.get('_cnmts_db', {})
    versions_db = app.config.get('_versions_db', {})

    if not all([titles_db, cnmts_db, versions_db]):
        return {'main_game': None, 'updates': [], 'dlcs': []}

    main_game_id = get_main_title_id(start_id)
    main_game_id_lower = main_game_id.lower()
    
    main_game_data = titles_db.get(main_game_id, {})
    if not main_game_data:
        main_game_data = {'name': _('Unknown Base Game'), 'id': main_game_id}
    main_game_data['exists_in_db'] = check_content_in_db(main_game_id)

    updates = []
    dlcs = []

    if main_game_id_lower in versions_db:
        update_tid = main_game_id[:-3] + '800'
        for version_int_str, release_date in versions_db[main_game_id_lower].items():
            version_int = int(version_int_str)
            version_str = get_update_number(version_int)
            
            exists_locally = check_specific_update_in_db(update_tid, version_int)
            
            updates.append({
                'id': update_tid,
                'name': _('Update %(version)s', version=version_str),
                'version_int': version_int,
                'version_str': version_str,
                'exists_in_db': exists_locally
            })
    
    for app_id, app_info in cnmts_db.items():
        if not app_info: continue
        version_keys = list(app_info.keys())
        last_version_info = app_info[version_keys[-1]]
        
        if last_version_info.get('otherApplicationId') == main_game_id_lower and last_version_info.get('titleType') == 130:
            content_data = titles_db.get(app_id.upper(), {})
            
            exists_locally = check_content_in_db(app_id.upper())
            
            dlcs.append({
                'id': app_id.upper(),
                'name': content_data.get('name', _('Unknown DLC (%(id)s)', id=app_id.upper())),
                'iconUrl': content_data.get('iconUrl', ''),
                'exists_in_db': exists_locally
            })

    updates.sort(key=lambda x: x['version_int'], reverse=True)
    dlcs.sort(key=lambda x: x['name'])
    
    return {'main_game': main_game_data, 'updates': updates, 'dlcs': dlcs}

def preprocess_game_links():
    """Checks and populates the 'base_game_tid' column for all games in the DB."""
    app.logger.info("Starting verification and preprocessing of game links...")
    conn = None
    try:
        conn = get_db_connection('DB_FILE')
        cursor = conn.cursor()
        cursor.execute("PRAGMA table_info(games)")
        columns = [info[1] for info in cursor.fetchall()]
        
        if 'base_game_tid' not in columns:
            app.logger.warning("Column 'base_game_tid' not found. Creating column...")
            cursor.execute("ALTER TABLE games ADD COLUMN base_game_tid TEXT")
            conn.commit()
            app.logger.info("Column 'base_game_tid' created successfully.")

        cursor.execute("SELECT id, tid FROM games WHERE base_game_tid IS NULL OR base_game_tid = ''")
        unprocessed_games = cursor.fetchall()
        
        if not unprocessed_games:
            app.logger.info("No new games to process. Links are up to date.")
            return

        app.logger.info(f"Found {len(unprocessed_games)} unprocessed games. Linking...")
        update_data = []
        for row_id, tid in unprocessed_games:
            base_tid = get_main_title_id(tid)
            update_data.append((base_tid, row_id))

        cursor.executemany("UPDATE games SET base_game_tid = ? WHERE id = ?", update_data)
        conn.commit()
        app.logger.info(f"{len(unprocessed_games)} games linked successfully.")
    except sqlite3.Error as e:
        app.logger.error(f"Error during link preprocessing: {e}")
    finally:
        if conn:
            conn.close()

def get_games_count():
    """Returns the total count of games in the database."""
    try:
        conn = get_db_connection('DB_FILE')
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM games")
        count = cursor.fetchone()[0]
        conn.close()
        return count
    except sqlite3.Error as e:
        app.logger.error(f"Error counting games: {str(e)}")
        return 0

def store_log_entry(entry):
    """Stores a log entry in the logs database."""
    try:
        conn = sqlite3.connect(app.config['LOG_DB'])
        c = conn.cursor()
        c.execute('''INSERT INTO logs (timestamp, type, level, message, ip, user, source, data) VALUES (?, ?, ?, ?, ?, ?, ?, ?)''', 
                  (entry['timestamp'], entry['type'], entry['level'], entry['message'], entry['ip'], entry['user'], entry['source'], json.dumps(entry['data'])))
        conn.commit()
        conn.close()
    except Exception as e:
        app.logger.error(f"Error storing log entry: {str(e)}")

def get_log_files():
    """Returns a list of physical log files."""
    log_dir = "logs"
    if not os.path.exists(log_dir): return []
    log_files = []
    for file in os.listdir(log_dir):
        if file.endswith('.log'):
            file_path = os.path.join(log_dir, file)
            file_size = os.path.getsize(file_path)
            file_date = dt.fromtimestamp(os.path.getmtime(file_path))
            log_files.append({'name': file, 'path': file_path, 'size': file_size, 'date': file_date.strftime("%d/%m/%Y %H:%M")})
    return sorted(log_files, key=lambda x: x['date'], reverse=True)

def get_log_content(log_path):
    """Reads and formats the content of a log file."""
    try:
        with open(log_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
    except UnicodeDecodeError:
        app.logger.warning(f"Failed to decode '{os.path.basename(log_path)}' as UTF-8. Trying as Latin-1.")
        try:
            with open(log_path, 'r', encoding='latin-1') as f:
                lines = f.readlines()
        except Exception as e:
            return [{'timestamp': '', 'level': 'ERROR', 'source': 'system', 'message': f'Critical failure reading log file: {e}'}]
    except Exception as e:
        return [{'timestamp': '', 'level': 'ERROR', 'source': 'system', 'message': f'Failed to read log file: {e}'}]

    parsed_logs = []
    log_pattern = re.compile(
        r'^(?P<timestamp>\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2},\d{3})\s+-\s+'
        r'(?P<source>.+?)\s+-\s+'
        r'(?P<level>DEBUG|INFO|WARNING|ERROR|CRITICAL)\s+-\s+'
        r'(?P<message>.*)$'
    )
    for line in lines:
        match = log_pattern.match(line.strip())
        if match:
            data = match.groupdict()
            parsed_logs.append({
                'timestamp': data['timestamp'], 'level': data['level'].upper(),
                'source': data['source'].strip(), 'message': data['message'].strip(),
                'ip': 'N/A', 'user': 'N/A'
            })
        elif line.strip():
            if parsed_logs:
                parsed_logs[-1]['message'] += '\n' + line.strip()
            else:
                parsed_logs.append({
                    'timestamp': 'N/A', 'level': 'RAW', 'source': 'file',
                    'message': line.strip(), 'ip': 'N/A', 'user': 'N/A'
                })
    return parsed_logs