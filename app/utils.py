import string
import random
from datetime import datetime as dt
import json
from flask_babel import _

def format_bytes(size):
    """Formats a size in bytes to a human-readable string."""
    if size is None or size == 0:
        return _("N/A")
    try:
        size = int(size)
        power = 1024
        n = 0
        power_labels = {0: 'B', 1: 'KB', 2: 'MB', 3: 'GB', 4: 'TB'}
        while size > power and n < len(power_labels) - 1:
            size /= power
            n += 1
        return f"{size:.2f} {power_labels[n]}"
    except (ValueError, TypeError):
        return _("Invalid")

def format_date(date_value):
    """Formats a date string into DD/MM/YYYY format."""
    if not date_value:
        return _("N/A")
    date_str = str(date_value)
    try:
        date_obj = dt.strptime(date_str, '%Y%m%d')
        return date_obj.strftime('%d/%m/%Y')
    except ValueError:
        return date_str

def get_update_number(version_int):
    """Converts a version integer to a human-readable string like vX.Y.Z."""
    if not isinstance(version_int, int):
        try:
            version_int = int(version_int)
        except (ValueError, TypeError):
            return "v?.?.?"
    major = version_int >> 26
    minor = (version_int >> 20) & 0x3F
    patch = (version_int >> 16) & 0xF
    return f"v{major}.{minor}.{patch}"

def generate_password():
    """Generates a random 8-character password."""
    letters = string.ascii_lowercase
    first_part = ''.join(random.choice(letters) for i in range(4))
    second_part = ''.join(random.choice(string.ascii_uppercase + string.digits) for i in range(4))
    return first_part + second_part

def get_pagination_range(current_page, total_pages, window=2):
    """Calculates the range of pages to display in pagination."""
    if total_pages <= (window * 2) + 1:
        return list(range(1, total_pages + 1))
    
    pages = []
    
    # Logic for leading pages and ellipsis
    if current_page - window > 2:
        pages.extend([1, '...'])
    else:
        for i in range(1, current_page - window):
            pages.append(i)
            
    # Logic for the central window of pages
    start = max(1, current_page - window)
    end = min(total_pages, current_page + window)
    for i in range(start, end + 1):
        pages.append(i)
        
    # Logic for trailing pages and ellipsis
    if current_page + window < total_pages - 1:
        pages.extend(['...', total_pages])
    else:
        for i in range(current_page + window + 1, total_pages + 1):
            pages.append(i)
            
    return pages

def save_config(new_settings):
    """Reads config.json, updates it with new values, and saves it back."""
    try:
        # Reads the current content to preserve other settings
        with open('config.json', 'r', encoding='utf-8') as f:
            config = json.load(f)
        
        # Updates the dictionary with the new settings
        config.update(new_settings)
        
        # Writes the complete file back
        with open('config.json', 'w', encoding='utf-8') as f:
            json.dump(config, f, indent=2, ensure_ascii=False)
        return True, None
    except Exception as e:
        return False, str(e)