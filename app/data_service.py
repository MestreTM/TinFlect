import os
import json
import re
import requests
import zipfile
import io
import logging
from functools import lru_cache
from tqdm import tqdm

TITLES_DB = {}
BASE_GAMES = {}

def initialize_titledb():
    """
    Loads TitleDB from JSON files and bootstraps data if missing.
    This function should be called once at application startup.
    """
    global TITLES_DB, BASE_GAMES
    
    titledb_path = 'titledb'
    if not os.path.exists(titledb_path) or not any(f.endswith('.json') for f in os.listdir(titledb_path)):
        logging.warning("TitleDB data not found. Attempting to download...")
        try:
            _download_and_extract_titledb(titledb_path)
        except requests.exceptions.RequestException as e:
            logging.error(f"Failed to download TitleDB: {e}")
            return

    logging.info("Processing database files, please wait...")
    
    all_titles = {}
    for filename in sorted(os.listdir(titledb_path)):
        if filename.endswith('.json'):
            file_path = os.path.join(titledb_path, filename)
            with open(file_path, 'r', encoding='utf-8') as f:
                all_titles.update(json.load(f))
    
    TITLES_DB = all_titles
    BASE_GAMES = {k: v for k, v in TITLES_DB.items() if k.endswith('000')}
    logging.info(f"Loaded {len(TITLES_DB)} total entries and {len(BASE_GAMES)} base games from TitleDB.")

def _download_and_extract_titledb(path):
    """Helper to download and extract the TitleDB zip file with a progress bar."""
    """Thanks a1ex4/ownfoil !"""
    url = "https://nightly.link/a1ex4/ownfoil/workflows/region_titles/master/titledb.zip"
    
    response = requests.get(url, stream=True)
    response.raise_for_status()
    
    total_size = int(response.headers.get('content-length', 0))
    block_size = 1024
    
    progress_bar = tqdm(total=total_size, unit='iB', unit_scale=True, desc="Downloading TitleDB")
    
    downloaded_data = io.BytesIO()
    for data in response.iter_content(block_size):
        progress_bar.update(len(data))
        downloaded_data.write(data)
        
    progress_bar.close()

    if total_size != 0 and progress_bar.n != total_size:
        logging.error("Download failed: Incomplete file received.")
        return

    logging.info("Download complete.")
    with zipfile.ZipFile(downloaded_data) as z:
        os.makedirs(path, exist_ok=True)
        for member in tqdm(z.infolist(), desc='Decompressing files'):
            z.extract(member, path)
            
    logging.info(f"Successfully extracted TitleDB to '{path}'.")

@lru_cache(maxsize=1)
def get_available_filters():
    """
    Calculates and returns sorted lists of all unique categories and publishers.
    Uses caching to avoid recalculating on every request.
    """
    categories = set()
    publishers = set()
    for game in BASE_GAMES.values():
        if game.get('category'):
            categories.update(game['category'])
        if game.get('publisher'):
            publishers.add(game['publisher'])
    return sorted(list(categories)), sorted(list(publishers))

def _sort_key_games(item):
    """Sort key for games: sort alphabetically, pushing games without a name to the end."""
    game_data = item[1]
    has_name = bool(game_data.get('name'))
    name = game_data.get('name', '').lower()
    return (not has_name, name)

def find_games(search=None, category=None, publisher=None):
    """Filters and sorts games based on the provided criteria."""
    filtered_games = BASE_GAMES.copy()

    if search:
        if re.match(r'^[0-9a-fA-F]{16}$', search):
            search_id = search.upper()
            filtered_games = {k: v for k, v in filtered_games.items() if k == search_id}
        else:
            search_lower = search.lower()
            filtered_games = {k: v for k, v in filtered_games.items() if v.get('name') and search_lower in v.get('name').lower()}
    
    if category:
        filtered_games = {k: v for k, v in filtered_games.items() if v.get('category') and category in v.get('category')}

    if publisher:
        publisher_lower = publisher.lower()
        filtered_games = {k: v for k, v in filtered_games.items() if v.get('publisher') and publisher_lower in v.get('publisher').lower()}
    
    return sorted(filtered_games.items(), key=_sort_key_games)

def get_related_content(game_id):
    """Finds a main game and its associated updates and DLCs."""
    base_id = game_id[:-3]
    main_game = TITLES_DB.get(f"{base_id}000")

    if not main_game:
        return {'main_game': None, 'updates': [], 'dlcs': []}

    updates, dlcs = [], []
    for key, value in TITLES_DB.items():
        if key.startswith(base_id):
            if key.endswith('800'):
                updates.append(value)
            elif not key.endswith('000'):
                dlcs.append(value)
    
    return {
        'main_game': main_game,
        'updates': sorted(updates, key=lambda x: x.get('version', 0), reverse=True),
        'dlcs': sorted(dlcs, key=lambda x: x.get('name', ''))
    }
