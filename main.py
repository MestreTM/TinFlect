# main.py - The main script to start the Admin Panel

import os
import sys
import signal  # Module to handle signals like Ctrl+C
from waitress import serve

# Import the 'app' created inside the 'app' package
from app import app

# Import initialization functions from other modules
from app.models import load_all_databases, preprocess_game_links
from app.core_manager import start_core, stop_core
from app.routes import setup_database, setup_logs_db, setup_logging

# --- NEW FUNCTION FOR GRACEFUL SHUTDOWN ---
def signal_handler(sig, frame):
    """Handles the interruption signal (Ctrl+C) for a clean shutdown."""
    print("\nPlease wait, shutting down...")
    stop_core()  # First, command the core process to shut down
    sys.exit(0)  # Exit the main process cleanly

if __name__ == '__main__':
    # Register our handler for the interrupt signal (Ctrl+C)
    # From now on, pressing Ctrl+C will call the 'signal_handler' function
    signal.signal(signal.SIGINT, signal_handler)

    # --- PHASE 1: Environment and Services Setup ---
    # This section runs all necessary initialization tasks
    # before the admin panel web server is started.

    setup_logging()
    os.makedirs('shop', exist_ok=True)
    os.makedirs('cache', exist_ok=True)
    os.makedirs('logs', exist_ok=True)

    # Setup SQLite databases
    setup_database()
    setup_logs_db()

    # Load title databases (JSONs) into memory
    if not load_all_databases():
        app.logger.error("APPLICATION CANNOT START. PLEASE CHECK THE TITLEDB JSON FILES.")
        sys.exit(1)

    # Performance optimization
    preprocess_game_links()
    
    # Start the Tinfoil server process (core) in the background
    start_core()
    
    # The 'atexit.register(cleanup)' line was removed to prevent the race condition.

    # --- PHASE 2: Web Server (Admin Panel) Configuration and Startup ---
    
    # Get web server settings from config.json
    host = app.config.get('HOST', '0.0.0.0')
    admin_port = app.config.get('ADMIN_PORT')
    threads = app.config.get('WEB_THREADS', 8)

    # Security check: ensure the admin port is configured
    if not admin_port:
        app.logger.critical("ERROR: 'ADMIN_PORT' is not defined in config.json. The panel cannot start.")
        sys.exit(1)

    # Display information in the console about the server about to start
    app.logger.info("======================================================")
    app.logger.info("-> TinFlect - Starting Admin Panel with Waitress <-")
    app.logger.info(f"-> Listening on: http://{host}:{admin_port}")
    app.logger.info(f"-> Using {threads} worker threads.")
    app.logger.info("-> Press CTRL+C to shut down the server and the core.")
    app.logger.info("======================================================")

    # Start the Waitress server to serve the admin panel.
    # This function is blocking and will keep the script running.
    serve(app, host=host, port=admin_port, threads=threads)