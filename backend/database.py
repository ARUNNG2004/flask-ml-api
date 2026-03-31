import sqlite3
import json
import os
from datetime import datetime, timezone

DB_PATH = os.path.join(os.path.dirname(__file__), 'history.db')


def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db_connection()
    conn.execute('''
        CREATE TABLE IF NOT EXISTS scan_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT,
            timestamp TEXT,
            ensemble_label TEXT,
            risk_score INTEGER,
            dt_label TEXT,
            dt_confidence REAL,
            dt_malicious_proba REAL,
            rf_label TEXT,
            rf_confidence REAL,
            rf_malicious_proba REAL,
            scan_mode TEXT,
            features_json TEXT
        )
    ''')
    conn.commit()

    # Auto-migrate: add any missing columns to existing tables
    cursor = conn.execute("PRAGMA table_info(scan_history)")
    existing_cols = {row['name'] for row in cursor.fetchall()}

    migrations = {
        'dt_malicious_proba': 'REAL',
        'rf_malicious_proba': 'REAL',
    }
    for col_name, col_type in migrations.items():
        if col_name not in existing_cols:
            conn.execute(f'ALTER TABLE scan_history ADD COLUMN {col_name} {col_type}')
            conn.commit()

    conn.close()


def save_scan(result_dict):
    conn = get_db_connection()
    now = datetime.now(timezone.utc).isoformat()

    conn.execute('''
        INSERT INTO scan_history (
            url, timestamp, ensemble_label, risk_score,
            dt_label, dt_confidence, dt_malicious_proba,
            rf_label, rf_confidence, rf_malicious_proba,
            scan_mode, features_json
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        result_dict.get('url'),
        result_dict.get('timestamp', now),
        result_dict.get('ensemble', {}).get('label'),
        result_dict.get('risk_score'),
        result_dict.get('decision_tree', {}).get('label'),
        result_dict.get('decision_tree', {}).get('confidence'),
        result_dict.get('decision_tree', {}).get('malicious_proba'),
        result_dict.get('random_forest', {}).get('label'),
        result_dict.get('random_forest', {}).get('confidence'),
        result_dict.get('random_forest', {}).get('malicious_proba'),
        result_dict.get('scan_mode'),
        json.dumps(result_dict.get('features', {}))
    ))
    conn.commit()
    conn.close()


def get_history(page=1, per_page=20, filter_val='all'):
    conn = get_db_connection()
    offset = (page - 1) * per_page

    query = "SELECT * FROM scan_history"
    params = []

    if filter_val in ('safe', 'malicious'):
        query += " WHERE ensemble_label = ?"
        params.append(filter_val)

    query += " ORDER BY id DESC LIMIT ? OFFSET ?"
    params.extend([per_page, offset])

    rows = conn.execute(query, params).fetchall()

    count_query = "SELECT COUNT(*) FROM scan_history"
    count_params = []
    if filter_val in ('safe', 'malicious'):
        count_query += " WHERE ensemble_label = ?"
        count_params.append(filter_val)

    total = conn.execute(count_query, count_params).fetchone()[0]
    conn.close()

    records = []
    for row in rows:
        r = dict(row)
        if 'features_json' in r and r['features_json']:
            try:
                r['features_json'] = json.loads(r['features_json'])
            except Exception:
                pass
        records.append(r)

    return {
        "records": records,
        "total": total,
        "page": page,
        "per_page": per_page,
        "total_pages": max(1, (total + per_page - 1) // per_page)
    }


def delete_scan(scan_id):
    conn = get_db_connection()
    conn.execute("DELETE FROM scan_history WHERE id = ?", (scan_id,))
    conn.commit()
    conn.close()


def clear_history():
    conn = get_db_connection()
    conn.execute("DELETE FROM scan_history")
    conn.commit()
    conn.close()