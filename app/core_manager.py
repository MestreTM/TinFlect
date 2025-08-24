import subprocess
import sys
import socket
import time
import os

from app import app, add_log_entry

def start_core():
    """Starts core.py as a robust background process."""
    python_executable = sys.executable
    # Ensures the previous process is cleaned up before starting a new one
    if app.config.get('CORE_PROCESS') and app.config['CORE_PROCESS'].poll() is None:
        add_log_entry('warning', 'Attempting to start the core, but a process already existed. Stopping the old one...', source='system')
        stop_core()
        time.sleep(1)

    add_log_entry('system', 'Starting the shop core process...', source='system')
    # Starts the core from the project root for consistency
    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
    core_script_path = os.path.join(project_root, 'app', 'core.py')
    
    process = subprocess.Popen([python_executable, core_script_path], cwd=project_root)
    app.config['CORE_PROCESS'] = process

def stop_core():
    """Stops the core process safely."""
    process = app.config.get('CORE_PROCESS')
    if process and process.poll() is None:
        add_log_entry('system', 'Stopping the shop core process...', source='system')
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            add_log_entry('warning', 'Core process did not terminate in time, forcing shutdown.', source='system')
            process.kill()
    
    app.config['CORE_PROCESS'] = None
    app.config['CORE_STATUS'] = "Offline"

def check_core_status_real():
    """
    Checks if the core port is responding. This is the actual test function.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(1)
    try:
        # To test a service on the same machine, ALWAYS use '127.0.0.1'.
        host_to_check = '127.0.0.1'
        port_to_check = app.config['CORE_PORT']
        
        # connect_ex returns 0 if the connection is successful.
        if s.connect_ex((host_to_check, port_to_check)) == 0:
            return True
        return False
    except (socket.error, TypeError):
        return False
    finally:
        s.close()

def check_core_status():
    """
    Updates the status in app.config based on the port check.
    """
    if check_core_status_real():
        if app.config.get('CORE_STATUS') != "Online":
            app.config['CORE_STATUS'] = "Online"
    else:
        if app.config.get('CORE_STATUS') != "Offline":
            app.config['CORE_STATUS'] = "Offline"
            
def toggle_core():
    """Toggles the core's state (on/off)."""
    check_core_status()
    if app.config['CORE_STATUS'] == "Online":
        stop_core()
        return "Tinfoil server stopped", "stopped"
    else:
        start_core()
        return "Tinfoil server started", "started"

def restart_core():
    """Restarts the core process safely."""
    add_log_entry('system', 'Restarting the shop core...', source='system')
    stop_core()
    time.sleep(1)
    start_core()