# library.py

import math
import re
from flask import render_template, request, flash, redirect, url_for
from flask_babel import _

from app import app
from .models import get_related_content, check_content_in_db
from .utils import get_pagination_range

def show_library_page():
    """
    Handles search, filtering, and pagination logic for the game library.
    """
    search = request.args.get('search', '').strip()
    category = request.args.get('category', '')
    publisher = request.args.get('publisher', '')
    page = int(request.args.get('page', 1))

    base_games = {k: v for k, v in app.config.get('_titles_db', {}).items() if k.endswith('000')}
    filtered_games = base_games.copy()

    if search:
        search_lower = search.lower()
        if re.match(r'^[0-9a-fA-F]{16}$', search):
            filtered_games = {k: v for k, v in filtered_games.items() if k == search.upper()}
        else:
            filtered_games = {k: v for k, v in filtered_games.items() if v.get('name') and search_lower in v.get('name').lower()}
    
    if category:
        filtered_games = {k: v for k, v in filtered_games.items() if v.get('category') and category in v.get('category')}
    
    if publisher:
        publisher_lower = publisher.lower()
        filtered_games = {k: v for k, v in filtered_games.items() if v.get('publisher') and publisher_lower in v.get('publisher').lower()}

    total_games = len(filtered_games)
    items_per_page = app.config.get('ITEMS_PER_PAGE', 24)
    total_pages = math.ceil(total_games / items_per_page)
    start = (page - 1) * items_per_page
    end = start + items_per_page
    
    sorted_games = sorted(filtered_games.items(), key=lambda item: (not bool(item[1].get('name')), item[1].get('name') or ''))
    paginated_games_dict = dict(sorted_games[start:end])

    for game_id, game_data in paginated_games_dict.items():
        game_data['exists_in_db'] = check_content_in_db(game_id)

    categories = set()
    publishers = set()
    for game in base_games.values():
        if game.get('category'):
            categories.update(game['category'])
        if game.get('publisher'):
            publishers.add(game['publisher'])

    pagination_range = get_pagination_range(page, total_pages)

    return render_template('admin/library.html',
                           games=paginated_games_dict,
                           categories=sorted(list(categories)),
                           publishers=sorted(list(publishers)),
                           current_page=page,
                           total_pages=total_pages,
                           pagination_range=pagination_range,
                           search=search,
                           category=category,
                           publisher=publisher)

def show_game_details_page(game_id):
    """
    Retrieves and displays details for a specific game, including its updates and DLCs.
    """
    related_content = get_related_content(game_id)
    
    if not related_content.get('main_game'):
        flash(_('Game not found in the TitleDB database.'), 'danger')
        return redirect(url_for('library'))
        
    return render_template('admin/game_details.html', 
                           game=related_content['main_game'], 
                           updates=related_content['updates'], 
                           dlcs=related_content['dlcs'])