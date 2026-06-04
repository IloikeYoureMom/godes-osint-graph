import sqlite3
import os
import json
import re
from flask import Flask, jsonify, request, render_template
from enrichment import enrich_entity

app = Flask(__name__)
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'osint_graph.db')
UPLOAD_FOLDER = os.path.join(app.static_folder or os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static'), 'uploads')


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

ENTITY_TYPES = [
    'person', 'email', 'username', 'url', 'ip_address', 'company',
    'phone_number', 'address', 'alias', 'social_media', 'domain',
    'cryptocurrency', 'organization', 'device', 'location', 'other'
]

SOCIAL_PLATFORMS = [
    'tiktok', 'instagram', 'twitter', 'facebook', 'linkedin', 'youtube',
    'snapchat', 'reddit', 'discord', 'telegram', 'whatsapp', 'signal',
    'pinterest', 'tumblr', 'twitch', 'threads', 'bluesky', 'mastodon',
    'wechat', 'qq', 'vkontakte', 'github', 'onlyfans', 'patreon',
    'flickr', 'imdb', 'fiverr', 'upwork', 'medium', 'substack',
    'behance', 'dribbble', 'strava', 'tinder', 'bumble', 'clubhouse',
    'parler', 'gab', 'truth_social', 'kick', 'rumble', 'other'
]

RELATIONSHIP_TYPES = [
    'known', 'member_of', 'owns', 'uses', 'works_at',
    'registered_at', 'associated_with', 'alias_of', 'located_at',
    'communicates_with', 'follows', 'administers', 'created',
    'related_to', 'other'
]


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db():
    conn = get_db()
    conn.executescript('''
        CREATE TABLE IF NOT EXISTS entities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            entity_type TEXT NOT NULL DEFAULT 'other',
            notes TEXT DEFAULT '',
            tags TEXT DEFAULT '',
            links TEXT DEFAULT '[]',
            images TEXT DEFAULT '[]',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS relationships (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source_id INTEGER NOT NULL,
            target_id INTEGER NOT NULL,
            relationship_type TEXT NOT NULL DEFAULT 'associated_with',
            notes TEXT DEFAULT '',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (source_id) REFERENCES entities(id) ON DELETE CASCADE,
            FOREIGN KEY (target_id) REFERENCES entities(id) ON DELETE CASCADE
        );

        CREATE INDEX IF NOT EXISTS idx_rel_source ON relationships(source_id);
        CREATE INDEX IF NOT EXISTS idx_rel_target ON relationships(target_id);
    ''')
    conn.commit()
    # Migrate existing tables — add columns if they don't exist
    try:
        conn.execute('ALTER TABLE entities ADD COLUMN links TEXT DEFAULT "[]"')
    except sqlite3.OperationalError:
        pass  # column already exists
    try:
        conn.execute('ALTER TABLE entities ADD COLUMN images TEXT DEFAULT "[]"')
    except sqlite3.OperationalError:
        pass  # column already exists
    try:
        conn.execute('ALTER TABLE entities ADD COLUMN platform TEXT DEFAULT ""')
    except sqlite3.OperationalError:
        pass  # column already exists
    try:
        conn.execute('ALTER TABLE entities ADD COLUMN profile_url TEXT DEFAULT ""')
    except sqlite3.OperationalError:
        pass  # column already exists
    conn.commit()
    conn.close()


@app.route('/')
def index():
    return render_template('index.html')




@app.route('/api/entities', methods=['GET'])
def list_entities():
    conn = get_db()
    search = request.args.get('search', '').strip()
    type_filter = request.args.get('type', '').strip()

    query = 'SELECT e.*, (SELECT COUNT(*) FROM relationships WHERE source_id = e.id OR target_id = e.id) as connection_count FROM entities e WHERE 1=1'
    params = []

    if search:
        query += ' AND (e.name LIKE ? OR e.notes LIKE ? OR e.tags LIKE ?)'
        like = f'%{search}%'
        params.extend([like, like, like])

    if type_filter and type_filter != 'all':
        query += ' AND e.entity_type = ?'
        params.append(type_filter)

    platform_filter = request.args.get('platform', '').strip()
    if platform_filter:
        query += ' AND e.platform = ?'
        params.append(platform_filter)

    query += ' ORDER BY e.updated_at DESC'

    entities = conn.execute(query, params).fetchall()
    conn.close()
    return jsonify([dict(e) for e in entities])


@app.route('/api/entities', methods=['POST'])
def create_entity():
    data = request.get_json()
    name = data.get('name', '').strip()
    if not name:
        return jsonify({'error': 'Name is required'}), 400

    entity_type = data.get('entity_type', 'other')
    if entity_type not in ENTITY_TYPES:
        entity_type = 'other'

    conn = get_db()
    cursor = conn.execute(
        'INSERT INTO entities (name, entity_type, notes, tags, links, images, platform, profile_url) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
        (name, entity_type, data.get('notes', ''), data.get('tags', ''),
         json.dumps(data.get('links', [])), json.dumps(data.get('images', [])),
         data.get('platform', ''), data.get('profile_url', ''))
    )
    conn.commit()
    entity_id = cursor.lastrowid
    entity = conn.execute('SELECT * FROM entities WHERE id = ?', (entity_id,)).fetchone()
    conn.close()

    # Auto-enrich if requested
    if data.get('auto_enrich') and entity['entity_type'] in ('phone_number', 'email', 'domain', 'url', 'username', 'ip_address', 'social_media'):
        try:
            enr = enrich_entity(entity['entity_type'], entity['name'], profile_url=entity.get('profile_url', ''))
            if enr.get('intel'):
                intel_lines = [f"[{i['label']}] {i['value']}" for i in enr['intel']]
                enrich_text = '\n'.join(intel_lines)
                new_notes = '─── OSINT Enrichment ───\n' + enrich_text
                if entity['notes']:
                    new_notes += '\n\n' + entity['notes']
                conn = get_db()
                conn.execute('UPDATE entities SET notes=?, updated_at=CURRENT_TIMESTAMP WHERE id=?', (new_notes, entity_id))
                conn.commit()
                conn.close()
        except Exception:
            pass

    return jsonify(dict(entity)), 201


@app.route('/api/entities/<int:entity_id>', methods=['PUT'])
def update_entity(entity_id):
    data = request.get_json()
    conn = get_db()

    entity = conn.execute('SELECT * FROM entities WHERE id = ?', (entity_id,)).fetchone()
    if not entity:
        conn.close()
        return jsonify({'error': 'Entity not found'}), 404

    name = data.get('name', entity['name']).strip()
    entity_type = data.get('entity_type', entity['entity_type'])
    if entity_type not in ENTITY_TYPES:
        entity_type = entity['entity_type']

    conn.execute(
        'UPDATE entities SET name=?, entity_type=?, notes=?, tags=?, links=?, images=?, platform=?, profile_url=?, updated_at=CURRENT_TIMESTAMP WHERE id=?',
        (name, entity_type,
         data.get('notes', entity['notes']), data.get('tags', entity['tags']),
         json.dumps(data.get('links', json.loads(entity['links']) if entity['links'] else [])),
         json.dumps(data.get('images', json.loads(entity['images']) if entity['images'] else [])),
         data.get('platform', entity['platform'] if entity['platform'] else ''),
         data.get('profile_url', entity['profile_url'] if entity['profile_url'] else ''),
         entity_id)
    )
    conn.commit()
    updated = conn.execute('SELECT * FROM entities WHERE id = ?', (entity_id,)).fetchone()
    conn.close()
    return jsonify(dict(updated))


@app.route('/api/entities/<int:entity_id>', methods=['DELETE'])
def delete_entity(entity_id):
    conn = get_db()
    conn.execute('DELETE FROM entities WHERE id = ?', (entity_id,))
    conn.commit()
    conn.close()
    return jsonify({'success': True})




@app.route('/api/relationships', methods=['GET'])
def list_relationships():
    conn = get_db()
    rels = conn.execute('''
        SELECT r.*, s.name as source_name, s.entity_type as source_type,
               t.name as target_name, t.entity_type as target_type
        FROM relationships r
        JOIN entities s ON r.source_id = s.id
        JOIN entities t ON r.target_id = t.id
        ORDER BY r.created_at DESC
    ''').fetchall()
    conn.close()
    return jsonify([dict(r) for r in rels])


@app.route('/api/relationships', methods=['POST'])
def create_relationship():
    data = request.get_json()
    source_id = data.get('source_id')
    target_id = data.get('target_id')
    rel_type = data.get('relationship_type', 'associated_with')

    if not source_id or not target_id:
        return jsonify({'error': 'source_id and target_id are required'}), 400

    if int(source_id) == int(target_id):
        return jsonify({'error': 'Cannot connect an entity to itself'}), 400

    if rel_type not in RELATIONSHIP_TYPES:
        rel_type = 'associated_with'

    conn = get_db()

    # Check for duplicate relationship
    existing = conn.execute(
        'SELECT id FROM relationships WHERE source_id = ? AND target_id = ? AND relationship_type = ?',
        (source_id, target_id, rel_type)
    ).fetchone()
    if existing:
        conn.close()
        return jsonify({'error': 'This connection already exists'}), 409

    # Check both entities exist
    source = conn.execute('SELECT id FROM entities WHERE id = ?', (source_id,)).fetchone()
    target = conn.execute('SELECT id FROM entities WHERE id = ?', (target_id,)).fetchone()
    if not source or not target:
        conn.close()
        return jsonify({'error': 'One or both entities not found'}), 404

    cursor = conn.execute(
        'INSERT INTO relationships (source_id, target_id, relationship_type, notes) VALUES (?, ?, ?, ?)',
        (source_id, target_id, rel_type, data.get('notes', ''))
    )
    conn.commit()
    rel = conn.execute('''
        SELECT r.*, s.name as source_name, s.entity_type as source_type,
               t.name as target_name, t.entity_type as target_type
        FROM relationships r
        JOIN entities s ON r.source_id = s.id
        JOIN entities t ON r.target_id = t.id
        WHERE r.id = ?
    ''', (cursor.lastrowid,)).fetchone()
    conn.close()
    return jsonify(dict(rel)), 201


@app.route('/api/relationships/<int:rel_id>', methods=['DELETE'])
def delete_relationship(rel_id):
    conn = get_db()
    conn.execute('DELETE FROM relationships WHERE id = ?', (rel_id,))
    conn.commit()
    conn.close()
    return jsonify({'success': True})




@app.route('/api/graph')
def get_graph():
    conn = get_db()
    entities = conn.execute('SELECT * FROM entities').fetchall()
    relationships = conn.execute('''
        SELECT r.*, s.name as source_name, t.name as target_name
        FROM relationships r
        JOIN entities s ON r.source_id = s.id
        JOIN entities t ON r.target_id = t.id
    ''').fetchall()
    conn.close()

    nodes = []
    for e in entities:
        links = json.loads(e['links']) if e['links'] else []
        images = json.loads(e['images']) if e['images'] else []
        title_html = f"<b>{e['name']}</b><br>Type: {e['entity_type']}"
        if e['notes']:
            title_html += f"<br><br>{e['notes'][:120] if len(e['notes']) > 120 else e['notes']}"
        if links:
            title_html += f"<br><br><b>Links ({len(links)}):</b>"
            for link in links[:3]:
                title_html += f"<br>• {link.get('title', link['url'][:40])}"
            if len(links) > 3:
                title_html += f"<br>  ... and {len(links) - 3} more"
        if images:
            title_html += f"<br><br><b>Images ({len(images)})</b>"
        nodes.append({
            'id': e['id'],
            'label': e['name'],
            'title': title_html,
            'group': e['entity_type'],
            'notes': e['notes'],
            'tags': e['tags'],
            'links': links,
            'images': images,
            'entity_type': e['entity_type'],
            'platform': e['platform'] if e['platform'] else '',
            'profile_url': e['profile_url'] if e['profile_url'] else '',
            'created_at': e['created_at'] if e['created_at'] else ''
        })

    edges = []
    for r in relationships:
        edges.append({
            'id': r['id'],
            'from': r['source_id'],
            'to': r['target_id'],
            'label': r['relationship_type'],
            'title': f"{r['source_name']} → {r['target_name']}<br>Type: {r['relationship_type']}<br>{r['notes'][:100] if r['notes'] else ''}",
            'relationship_type': r['relationship_type'],
            'notes': r['notes']
        })

    return jsonify({'nodes': nodes, 'edges': edges})


@app.route('/api/types')
def get_types():
    return jsonify({
        'entity_types': ENTITY_TYPES,
        'relationship_types': RELATIONSHIP_TYPES,
        'social_platforms': SOCIAL_PLATFORMS
    })




@app.route('/api/enrich/<int:entity_id>', methods=['POST'])
def enrich_entity_endpoint(entity_id):
    conn = get_db()
    entity = conn.execute('SELECT * FROM entities WHERE id = ?', (entity_id,)).fetchone()
    conn.close()

    if not entity:
        return jsonify({'error': 'Entity not found'}), 404

    try:
        result = enrich_entity(
            entity['entity_type'],
            entity['name'],
            profile_url=entity['profile_url'] if entity['profile_url'] else ''
        )

        # Save enrichment results into the entity's notes and links
        intel_lines = []
        for item in result.get('intel', []):
            intel_lines.append(f"[{item['label']}] {item['value']}")

        enrich_text = '\n'.join(intel_lines)
        existing_notes = entity['notes'] if entity['notes'] else ''

        # Build new notes: put enrichment at the top
        prefix = '─── OSINT Enrichment ───\n' if enrich_text else ''
        enrichment_block = f"{prefix}{enrich_text}"

        # Only add enrichment block if there's new intel
        if enrich_text:
            marker = '─── OSINT Enrichment'
            marker_idx = existing_notes.find(marker)
            if marker_idx != -1:
                # Replace existing enrichment block
                new_notes = existing_notes[:marker_idx].strip()
                if new_notes:
                    new_notes += '\n\n' + enrichment_block
                else:
                    new_notes = enrichment_block
            else:
                new_notes = enrichment_block + ('\n\n' + existing_notes if existing_notes else '')

            # Merge new OSINT links into existing links
            existing_links = json.loads(entity['links']) if entity['links'] else []
            existing_urls = {l['url'] for l in existing_links}
            new_links = [l for l in result.get('links', []) if l['url'] not in existing_urls]
            merged_links = existing_links + new_links

            # Merge tags
            existing_tags = [t.strip() for t in (entity['tags'] or '').split(',') if t.strip()]
            new_tags = [t for t in result.get('tags', []) if t not in existing_tags]
            merged_tags = existing_tags + new_tags

            # Update entity
            conn = get_db()
            conn.execute(
                'UPDATE entities SET notes=?, links=?, tags=?, updated_at=CURRENT_TIMESTAMP WHERE id=?',
                (new_notes, json.dumps(merged_links), ','.join(merged_tags), entity_id)
            )
            conn.commit()
            conn.close()

            result['saved'] = True
        else:
            result['saved'] = False

        return jsonify(result)

    except Exception as e:
        return jsonify({'error': str(e)}), 500




@app.route('/api/upload', methods=['POST'])
def upload_image():
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    file = request.files['file']
    if file.filename == '' or not allowed_file(file.filename):
        return jsonify({'error': 'Invalid file type. Allowed: png, jpg, jpeg, gif, webp'}), 400

    import uuid
    ext = file.filename.rsplit('.', 1)[1].lower()
    filename = f"{uuid.uuid4().hex}.{ext}"
    filepath = os.path.join(UPLOAD_FOLDER, filename)
    file.save(filepath)

    url = f"/static/uploads/{filename}"
    return jsonify({'url': url, 'filename': filename})




@app.route('/api/export')
def export_graph():
    conn = get_db()
    entities = conn.execute('SELECT * FROM entities').fetchall()
    relationships = conn.execute('SELECT * FROM relationships').fetchall()
    conn.close()
    return jsonify({
        'exported_at': __import__('datetime').datetime.now().isoformat(),
        'entities': [dict(e) for e in entities],
        'relationships': [dict(r) for r in relationships],
    })




@app.route('/api/bulk-import', methods=['POST'])
def bulk_import():
    data = request.get_json()
    lines = data.get('lines', '').strip().split('\n')
    default_type = data.get('default_type', 'url')
    default_platform = data.get('default_platform', '')
    created = []
    errors = []

    conn = get_db()
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            name = line
            entity_type = default_type
            platform = default_platform
            profile_url = ''

            # Auto-detect: if starts with http, it's url type
            if line.startswith('http'):
                entity_type = 'url'
            elif '@' in line and '.' in line.split('@')[-1]:
                entity_type = 'email'
            elif re.match(r'^[\d\+\-\(\)\s]+$', line):
                entity_type = 'phone_number'

            if entity_type == 'social_media' and platform:
                profile_url = line

            cursor = conn.execute(
                'INSERT INTO entities (name, entity_type, notes, tags, links, images, platform, profile_url) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
                (name, entity_type, '', '', '[]', '[]', platform, profile_url)
            )
            conn.commit()
            entity = conn.execute('SELECT * FROM entities WHERE id = ?', (cursor.lastrowid,)).fetchone()
            created.append(dict(entity))
        except Exception as e:
            errors.append({'line': line, 'error': str(e)})

    conn.close()
    return jsonify({'created': len(created), 'errors': len(errors), 'entities': created, 'error_details': errors})




@app.route('/api/bulk-enrich', methods=['POST'])
def bulk_enrich():
    conn = get_db()
    entities = conn.execute('SELECT * FROM entities ORDER BY created_at DESC').fetchall()
    conn.close()

    enriched = 0
    skipped = 0
    errors = 0

    for entity in entities:
        # Skip entities that already have enrichment
        if entity['notes'] and '─── OSINT Enrichment' in entity['notes']:
            skipped += 1
            continue
        try:
            result = enrich_entity(
                entity['entity_type'],
                entity['name'],
                profile_url=entity['profile_url'] if entity['profile_url'] else ''
            )
            if result.get('intel') and len(result['intel']) > 0:
                # Save similarly to single enrich
                intel_lines = []
                for item in result['intel']:
                    intel_lines.append(f"[{item['label']}] {item['value']}")
                enrich_text = '\n'.join(intel_lines)
                prefix = '─── OSINT Enrichment ───\n'
                enrichment_block = f"{prefix}{enrich_text}"
                new_notes = enrichment_block + ('\n\n' + entity['notes'] if entity['notes'] else '')

                existing_links = json.loads(entity['links']) if entity['links'] else []
                existing_urls = {l['url'] for l in existing_links}
                new_links = [l for l in result.get('links', []) if l['url'] not in existing_urls]
                merged_links = existing_links + new_links

                existing_tags = [t.strip() for t in (entity['tags'] or '').split(',') if t.strip()]
                new_tags = [t for t in result.get('tags', []) if t not in existing_tags]
                merged_tags = existing_tags + new_tags

                conn = get_db()
                conn.execute(
                    'UPDATE entities SET notes=?, links=?, tags=?, updated_at=CURRENT_TIMESTAMP WHERE id=?',
                    (new_notes, json.dumps(merged_links), ','.join(merged_tags), entity['id'])
                )
                conn.commit()
                conn.close()
                enriched += 1
            else:
                skipped += 1
        except Exception:
            errors += 1

    return jsonify({'enriched': enriched, 'skipped': skipped, 'errors': errors})


if __name__ == '__main__':
    init_db()
    print("╔══════════════════════════════════════════════╗")
    print("║       Godes OSINT Graph is running           ║")
    print("║    Open http://127.0.0.1:5000 in browser     ║")
    print("╚══════════════════════════════════════════════╝")
    app.run(debug=True, host='127.0.0.1', port=5000)
