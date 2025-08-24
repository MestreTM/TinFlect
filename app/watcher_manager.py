# watcher_manager.py

import os
import json
import sqlite3
import re
import time
import threading
from datetime import datetime as dt
from watchdog.observers.polling import PollingObserver as Observer
from watchdog.events import FileSystemEventHandler
from pathlib import Path

try:
    from nstools.nut import Keys
    from nstools.Fs import Pfs0, Nca, Type, factory
    from nstools.lib import FsTools
    from binascii import hexlify as hx
except ImportError:
    print("CRITICAL ERROR: The 'nstools' library was not found. Install it with the command: pip install nstools")
    exit(1)

Pfs0.Print.silent = True

class WatcherManager:
    def __init__(self, config_path, logger_callback=None, event_manager=None):
        """
        Initializes the WatcherManager for monitoring directories and managing game database.
        """
        self.observer = None
        self.event_handler = self.EventHandler(self)
        self.is_running = False
        self.config_path = config_path
        self._lock = threading.RLock()
        
        self.log = logger_callback if callable(logger_callback) else lambda **kwargs: None
        self.event_manager = event_manager
        
        self.scan_status = {
            "is_scanning": False,
            "total_files": 0,
            "processed_files": 0,
            "last_scan_log": None
        }
        
        self._load_config()
        self._create_db_if_not_exists()
        self._load_keys()
        self._load_titledb()
        self.load_watched_paths_from_db()
        
        if self.config.get('WATCHER_ENABLED', False):
            if self.watched_paths:
                print(" -> WatcherManager: Starting automatically as per configuration.")
                self.start()
            else:
                print(" -> WatcherManager WARNING: Watcher is enabled but has no directories to monitor.")
                self.stop()

    def _publish_event(self, event_type, data):
        """
        Publishes events to the event manager if available.
        """
        if self.event_manager:
            self.log(type=event_type, message=f"Event: {event_type}", data=data)

    def _create_db_if_not_exists(self):
        """
        Creates the SQLite database and tables if they do not exist.
        """
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS paths (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                path TEXT UNIQUE NOT NULL,
                last_scan DATETIME
            );
            """)
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS games (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT,
                cover TEXT,
                icon TEXT,
                version TEXT,
                size INTEGER,
                url TEXT,
                search TEXT,
                type TEXT,
                tid TEXT,
                base_game_tid TEXT,
                filepath TEXT UNIQUE NOT NULL,
                filename TEXT NOT NULL,
                compressed BOOLEAN DEFAULT FALSE,
                download_count INTEGER DEFAULT 0
            );
            """)
            conn.commit()
    
    def _update_path_scan_time(self, path):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE paths SET last_scan = ? WHERE path = ?", (dt.now(), path))
            conn.commit()

    def run_full_scan(self):
        """
        Performs a full scan of watched directories and updates the database.
        """
        with self._lock:
            if self.scan_status["is_scanning"]:
                print("SCAN: Full scan is already in progress.")
                return
            if not self.watched_paths:
                print("FULL SCAN: No directories to scan.")
                return
            self.scan_status.update({"is_scanning": True, "processed_files": 0, "total_files": 0, "last_scan_log": None})
        
        print("\n--- STARTING FULL FILE SCAN ---")
        
        all_files_to_scan = []
        for scan_path in self.watched_paths:
            print(f"Scanning directory: {scan_path}")
            for root, _, files in os.walk(scan_path):
                for filename in files:
                    if filename.lower().endswith(('.nsp', '.nsz', '.xci', '.xcz')):
                        all_files_to_scan.append(os.path.join(root, filename))
            self._update_path_scan_time(scan_path)
        
        self.scan_status["total_files"] = len(all_files_to_scan)
        print(f"SCAN: Found {self.scan_status['total_files']} files to analyze.")
        self._publish_event('scan_progress', {'processed': 0, 'total': self.scan_status['total_files']})

        unrecognized_files = []
        newly_added_count = 0
        
        with sqlite3.connect(self.db_path) as conn:
            for i, filepath in enumerate(all_files_to_scan):
                print(f"Processing file {i+1}/{self.scan_status['total_files']}: {os.path.basename(filepath)}")
                parsed_info_list = self._parse_metadata_from_file(filepath)
                
                if not parsed_info_list:
                    unrecognized_files.append(filepath)
                else:
                    for parsed_info in parsed_info_list:
                        if self._add_game_to_db(parsed_info, conn):
                            newly_added_count += 1
                
                self.scan_status["processed_files"] = i + 1
                self._publish_event('scan_progress', {'processed': self.scan_status['processed_files'], 'total': self.scan_status['total_files']})
            
            conn.commit()

        log_filename = f"scan_summary_{dt.now().strftime('%Y%m%d_%H%M%S')}.log"
        log_filepath = os.path.join("logs", log_filename)
        print(f"--- SCAN FINISHED ---")
        print(f"Added: {newly_added_count} new content entries.")
        print(f"Unrecognized: {len(unrecognized_files)} file(s).")

        with open(log_filepath, 'w', encoding='utf-8') as f:
            f.write(f"Scan Summary - {dt.now().strftime('%d/%m/%Y %H:%M:%S')}\n" + "="*40 + "\n\n")
            f.write(f"Total files analyzed: {self.scan_status['total_files']}\n")
            f.write(f"New content entries added to DB: {newly_added_count}\n")
            f.write(f"Unrecognized or corrupt files: {len(unrecognized_files)}\n\n")
            if unrecognized_files:
                f.write("List of unrecognized files:\n" + "-"*40 + "\n")
                for path in unrecognized_files:
                    f.write(f"{path}\n")
        
        with self._lock:
            self.scan_status["is_scanning"] = False
            self.scan_status["last_scan_log"] = log_filename

        self._publish_event('scan_complete', {'added': newly_added_count, 'unrecognized': len(unrecognized_files), 'log_file': log_filename})

    def _load_config(self):
        """
        Loads configuration from the specified JSON file.
        """
        with self._lock:
            try:
                with open(self.config_path, 'r', encoding='utf-8') as f: self.config = json.load(f)
            except (FileNotFoundError, json.JSONDecodeError): self.config = {}
            
            self.project_root = os.path.dirname(self.config_path)
            db_filename = self.config.get('DB_FILE', 'games.db')
            self.db_path = os.path.join(self.project_root, db_filename)
            self.keys_path = os.path.join(self.project_root, self.config.get('KEYS_FILE', 'prod.keys'))
            print(" -> WatcherManager: Configuration loaded.")

    def load_watched_paths_from_db(self):
        with self._lock, sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT path FROM paths")
            self.watched_paths = {row[0] for row in cursor.fetchall()}
            print(f" -> WatcherManager: {len(self.watched_paths)} directory/ies loaded from database.")

    def _load_keys(self):
        """
        Loads keys from the configured keys file.
        """
        self.keys_loaded = False
        try:
            if os.path.isfile(self.keys_path):
                if Keys.load(self.keys_path):
                    self.keys_loaded = True
            else:
                print(f"\033[91m -> ! WatcherManager WARNING: Keys file '{os.path.basename(self.keys_path)}' not found. The watcher validation functions will not work!\033[0m")
        except Exception as e:
            print(f"WatcherManager ERROR: Failed to load keys: {e}")

    def _load_titledb(self):
        """
        Loads title and CNMT databases from JSON files.
        """
        self.titles_db, self.cnmts_db = {}, {}
        project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
        titles_path = os.path.join(project_root, 'titledb', 'titles.US.en.json')
        cnmts_path = os.path.join(project_root, 'titledb', 'cnmts.json')
        try:
            with open(titles_path, 'r', encoding='utf-8') as f: self.titles_db = json.load(f)
            with open(cnmts_path, 'r', encoding='utf-8') as f: self.cnmts_db = json.load(f)
        except Exception: pass

    def get_main_title_id(self, app_id):
        """
        Determines the main title ID for a given application ID.
        """
        app_id_lower = app_id.lower()
        if app_id_lower.endswith('000'): return app_id.upper()
        if self.cnmts_db and app_id_lower in self.cnmts_db:
            latest_key = list(self.cnmts_db[app_id_lower].keys())[-1]
            info = self.cnmts_db[app_id_lower][latest_key]
            if 'otherApplicationId' in info: return info['otherApplicationId'].upper()
        return app_id[:-3].upper() + '000'
    
    def start(self):
        """
        Starts the file system observer for monitored directories.
        """
        with self._lock:
            if self.is_running: return
            self.load_watched_paths_from_db()
            if not self.watched_paths:
                print("WatcherManager ERROR: No directories to monitor.")
                return
            self.observer = Observer()
            for path in self.watched_paths:
                if os.path.isdir(path):
                    self.observer.schedule(self.event_handler, path, recursive=True)
                else:
                    print(f"WatcherManager WARNING: The path '{path}' is not a valid directory and will be ignored.")
            if not self.observer.emitters:
                print("WatcherManager ERROR: No valid directories found to monitor.")
                self.is_running = False
                return
            self.observer.start()
            self.is_running = True
            print("Watcher started in the background.")

    def stop(self):
        """
        Stops the file system observer.
        """
        with self._lock:
            if self.observer and self.observer.is_alive():
                self.observer.stop()
                self.observer.join()
            self.is_running = False
            print("Watcher stopped.")

    def add_directory(self, path):
        """
        Adds a directory to the watched paths and updates the database.
        """
        with self._lock, sqlite3.connect(self.db_path) as conn:
            abs_path = os.path.abspath(path)
            if not os.path.isdir(abs_path): return False
            cursor = conn.cursor()
            try:
                cursor.execute("INSERT INTO paths (path, last_scan) VALUES (?, NULL)", (abs_path,))
                conn.commit()
                self.watched_paths.add(abs_path)
                if self.is_running:
                    self.stop()
                    self.start()
                return True
            except sqlite3.IntegrityError:
                return False

    def remove_directory(self, path):
        """
        Removes a directory from the watched paths and updates the database.
        """
        with self._lock, sqlite3.connect(self.db_path) as conn:
            abs_path = os.path.abspath(path)
            if abs_path not in self.watched_paths: return False
            was_running = self.is_running
            if was_running: self.stop()
            cursor = conn.cursor()
            cursor.execute("DELETE FROM paths WHERE path = ?", (abs_path,))
            conn.commit()
            self.watched_paths.remove(abs_path)
            if was_running and self.watched_paths: self.start()
            return True

    def get_status(self):
        """
        Retrieves the current status of the watcher and scan progress.
        """
        with self._lock, sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("SELECT path, last_scan FROM paths")
            paths_data = [dict(row) for row in cursor.fetchall()]
            
            status = {
                "is_running": self.is_running,
                "watched_paths": paths_data,
                "scan_status": self.scan_status
            }
            return status

    def _add_game_to_db(self, parsed_info, conn):
        """
        Adds a game to the database if it doesn't already exist.
        """
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM games WHERE filepath = ?", (parsed_info['filepath'],))
        if cursor.fetchone(): return False
        
        base_tid = self.get_main_title_id(parsed_info['tid'])
        game_name_info = self.titles_db.get(base_tid, {})
        base_game_name = game_name_info.get('name', 'Unknown Game')
        
        content_type_raw = parsed_info['type']
        if content_type_raw == 'BASE': content_type_final = 'game'
        elif content_type_raw == 'UPDATE': content_type_final = 'update'
        elif content_type_raw == 'DLC': content_type_final = 'dlc'
        else: content_type_final = content_type_raw.lower()
        
        if content_type_final == 'update':
            version_int = parsed_info['version_int']
            version_str = f"v{(version_int >> 16) & 0xFFFF}"
            final_display_name = f"{base_game_name} ({version_str})"
        elif content_type_final == 'dlc':
            dlc_name = self.titles_db.get(parsed_info['tid'], {}).get('name', 'Unknown DLC')
            final_display_name = f"{base_game_name} - {dlc_name}"
        else:
            final_display_name = base_game_name
        
        extension = os.path.splitext(parsed_info['filename'])[1]
        
        game_data = {
            "name": final_display_name, "cover": game_name_info.get('iconUrl', ''), "icon": game_name_info.get('iconUrl', ''),
            "version": str(parsed_info['version_int']), 
            "size": os.path.getsize(parsed_info['filepath']),
            "url": '',
            "search": base_game_name, 
            "type": content_type_final,
            "tid": parsed_info['tid'],
            "base_game_tid": base_tid, 
            "filepath": parsed_info['filepath'],
            "filename": parsed_info['filename'],
            "compressed": extension.lower() in ['.nsz', '.xcz'],
            "download_count": 0
        }
        
        cursor.execute("""
            INSERT INTO games (name, cover, icon, version, size, url, search, type, tid, base_game_tid, filepath, filename, compressed, download_count) 
            VALUES (:name, :cover, :icon, :version, :size, :url, :search, :type, :tid, :base_game_tid, :filepath, :filename, :compressed, :download_count)
        """, game_data)
        
        return True

    def _parse_metadata_from_file(self, filepath):
        """
        Parses metadata from NSP, NSZ, XCI, or XCZ files.
        """
        if not self.keys_loaded: return []
        contents = []
        try:
            container = factory(Path(filepath).resolve())
            container.open(filepath, 'rb')
            if filepath.lower().endswith(('.xci', '.xcz')):
                container = container.hfs0['secure']
            for nca_file in container:
                if isinstance(nca_file, Nca.Nca) and nca_file.header.contentType == Type.Content.META:
                    for section in nca_file:
                        if isinstance(section, Pfs0.Pfs0):
                            cnmt = section.getCnmt()
                            tid = cnmt.titleId.upper()
                            version_int = cnmt.version
                            type_bytes = hx(cnmt.titleType.to_bytes(length=(min(cnmt.titleType.bit_length(), 1) + 7) // 8, byteorder='big'))
                            type_text = FsTools.parse_cnmt_type_n(type_bytes)
                            
                            if type_text == 'GAME': file_type = 'BASE'
                            elif type_text == 'UPDATE': file_type = 'UPDATE'
                            elif type_text == 'DLC': file_type = 'DLC'
                            else: file_type = type_text.upper()
                            
                            contents.append({
                                "tid": tid, "version_int": version_int, "type": file_type, 
                                "filepath": filepath, "filename": os.path.basename(filepath)
                            })
            container.close()
        except Exception as e:
            filename = os.path.basename(filepath)
            error_message = f"Failed to read metadata from '{filename}'."
            print(f"  -> ERROR: {error_message} Details: {e}")
            self.log(type='file_error', message=error_message, data={'filepath': filepath, 'error': str(e)})
            return []
        return contents

    def process_new_file(self, filepath):
        """
        Processes a new file and adds it to the database.
        """
        all_parsed_info = self._parse_metadata_from_file(filepath)
        if all_parsed_info:
            with sqlite3.connect(self.db_path) as conn:
                for parsed_info in all_parsed_info:
                    self._add_game_to_db(parsed_info, conn)
                conn.commit()
            self._update_path_scan_time(os.path.dirname(filepath))

    def process_deleted_file(self, filepath):
        """
        Removes a file entry from the database.
        """
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM games WHERE filepath = ?", (filepath,))
            if cursor.rowcount > 0:
                print(f"  -> SUCCESS: Entry for '{os.path.basename(filepath)}' removed from the DB.")
            conn.commit()
    
    class EventHandler(FileSystemEventHandler):
        def __init__(self, manager, stability_seconds=5):
            """
            Initializes the event handler for file system events.
            """
            self.manager = manager
            self.stability_seconds = stability_seconds
            self.tracked_files = {}
        def on_created(self, event):
            if not event.is_directory and event.src_path.lower().endswith(('.nsp', '.nsz', '.xci', '.xcz')): self._handle_event(event.src_path)
        def on_modified(self, event):
            if not event.is_directory and event.src_path.lower().endswith(('.nsp', '.nsz', '.xci', '.xcz')): self._handle_event(event.src_path)
        def on_deleted(self, event):
            if not event.is_directory and event.src_path.lower().endswith(('.nsp', '.nsz', '.xci', '.xcz')): self.manager.process_deleted_file(event.src_path)
        def on_moved(self, event):
            if not event.is_directory:
                if event.src_path.lower().endswith(('.nsp', '.nsz', '.xci', '.xcz')): self.manager.process_deleted_file(event.src_path)
                if event.dest_path.lower().endswith(('.nsp', '.nsz', '.xci', '.xcz')): self._handle_event(event.dest_path)
        def _handle_event(self, filepath):
            try:
                self.tracked_files[filepath] = (time.time(), os.path.getsize(filepath))
                threading.Timer(self.stability_seconds + 1, self._check_stability, args=[filepath]).start()
            except FileNotFoundError: pass
        def _check_stability(self, filepath):
            if filepath not in self.tracked_files: return
            last_event_time, last_size = self.tracked_files[filepath]
            if time.time() - last_event_time < self.stability_seconds: return
            try:
                if os.path.getsize(filepath) == last_size and last_size > 0:
                    self.manager.process_new_file(filepath)
                    del self.tracked_files[filepath]
            except FileNotFoundError:
                if filepath in self.tracked_files: del self.tracked_files[filepath]
            except Exception as e:
                print(f"Error checking stability of '{filepath}': {e}")