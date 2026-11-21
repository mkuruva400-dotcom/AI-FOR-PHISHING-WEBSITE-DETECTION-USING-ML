import os
import sqlite3
import json
from datetime import datetime

DEFAULT_DB_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'instance', 'phishing_history.db'))

def get_db_connection(db_path: str = DEFAULT_DB_PATH):
    """Establishes an SQLite database connection with row factory."""
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn

def init_db(db_path: str = DEFAULT_DB_PATH):
    """Initializes the database schema if tables do not exist."""
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS scan_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target_url TEXT NOT NULL,
            source_type TEXT NOT NULL DEFAULT 'URL',
            model_name TEXT NOT NULL,
            verdict TEXT NOT NULL,
            risk_score REAL NOT NULL,
            ml_probability REAL NOT NULL,
            response_time_ms REAL NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            breakdown_json TEXT,
            warnings_json TEXT,
            features_json TEXT
        )
    ''')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_timestamp ON scan_history(timestamp DESC)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_verdict ON scan_history(verdict)')
    conn.commit()
    conn.close()

def add_scan_record(
    target_url: str,
    source_type: str,
    model_name: str,
    verdict: str,
    risk_score: float,
    ml_probability: float,
    response_time_ms: float,
    breakdown: dict = None,
    warnings: list = None,
    features: dict = None,
    db_path: str = DEFAULT_DB_PATH
) -> int:
    """Inserts a new scan event into the history database."""
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO scan_history (
            target_url, source_type, model_name, verdict, risk_score,
            ml_probability, response_time_ms, timestamp,
            breakdown_json, warnings_json, features_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        target_url,
        source_type,
        model_name,
        verdict,
        risk_score,
        ml_probability,
        response_time_ms,
        datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S'),
        json.dumps(breakdown or {}),
        json.dumps(warnings or []),
        json.dumps(features or {})
    ))
    scan_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return scan_id

def get_recent_scans(limit: int = 50, search: str = None, verdict_filter: str = None, db_path: str = DEFAULT_DB_PATH):
    """Retrieves filtered list of recent scans."""
    conn = get_db_connection(db_path)
    cursor = conn.cursor()

    query = 'SELECT * FROM scan_history WHERE 1=1'
    params = []

    if search:
        query += ' AND target_url LIKE ?'
        params.append(f'%{search}%')
    if verdict_filter and verdict_filter.upper() != 'ALL':
        if verdict_filter.upper() in ['SAFE', 'LEGITIMATE']:
            query += " AND verdict IN ('SAFE', 'LEGITIMATE')"
        else:
            query += ' AND verdict = ?'
            params.append(verdict_filter.upper())

    query += ' ORDER BY id DESC LIMIT ?'
    params.append(limit)

    cursor.execute(query, params)
    rows = cursor.fetchall()
    conn.close()

    results = []
    for r in rows:
        results.append({
            'id': r['id'],
            'target_url': r['target_url'],
            'source_type': r['source_type'],
            'model_name': r['model_name'],
            'verdict': r['verdict'],
            'risk_score': r['risk_score'],
            'ml_probability': r['ml_probability'],
            'response_time_ms': r['response_time_ms'],
            'timestamp': r['timestamp'],
            'breakdown': json.loads(r['breakdown_json']) if r['breakdown_json'] else {},
            'warnings': json.loads(r['warnings_json']) if r['warnings_json'] else [],
            'features': json.loads(r['features_json']) if r['features_json'] else {}
        })
    return results

def get_scan_by_id(scan_id: int, db_path: str = DEFAULT_DB_PATH):
    """Retrieves full details of a specific scan record."""
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM scan_history WHERE id = ?', (scan_id,))
    row = cursor.fetchone()
    conn.close()

    if not row:
        return None

    return {
        'id': row['id'],
        'target_url': row['target_url'],
        'source_type': row['source_type'],
        'model_name': row['model_name'],
        'verdict': row['verdict'],
        'risk_score': row['risk_score'],
        'ml_probability': row['ml_probability'],
        'response_time_ms': row['response_time_ms'],
        'timestamp': row['timestamp'],
        'breakdown': json.loads(row['breakdown_json']) if row['breakdown_json'] else {},
        'warnings': json.loads(row['warnings_json']) if row['warnings_json'] else [],
        'features': json.loads(row['features_json']) if row['features_json'] else {}
    }

def delete_scan(scan_id: int, db_path: str = DEFAULT_DB_PATH) -> bool:
    """Deletes a single scan record."""
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    cursor.execute('DELETE FROM scan_history WHERE id = ?', (scan_id,))
    deleted = cursor.rowcount > 0
    conn.commit()
    conn.close()
    return deleted

def clear_all_scans(db_path: str = DEFAULT_DB_PATH):
    """Clears all scan history."""
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    cursor.execute('DELETE FROM scan_history')
    conn.commit()
    conn.close()

def get_dashboard_analytics(db_path: str = DEFAULT_DB_PATH) -> dict:
    """
    Computes comprehensive KPI metrics and visualization arrays for the interactive dashboard.
    """
    conn = get_db_connection(db_path)
    cursor = conn.cursor()

    # Total and verdicts
    cursor.execute('''
        SELECT 
            COUNT(*) as total,
            SUM(CASE WHEN verdict = 'PHISHING' THEN 1 ELSE 0 END) as phishing,
            SUM(CASE WHEN verdict IN ('SAFE', 'LEGITIMATE') THEN 1 ELSE 0 END) as safe,
            AVG(risk_score) as avg_score,
            AVG(response_time_ms) as avg_latency
        FROM scan_history
    ''')
    stats = cursor.fetchone()

    total = stats['total'] or 0
    phishing = stats['phishing'] or 0
    safe = stats['safe'] or 0
    avg_score = round(float(stats['avg_score'] or 0), 1)
    avg_latency = round(float(stats['avg_latency'] or 0), 1)

    # Risk score buckets (0-20, 21-40, 41-60, 61-80, 81-100)
    cursor.execute('''
        SELECT 
            SUM(CASE WHEN risk_score BETWEEN 0 AND 20 THEN 1 ELSE 0 END) as b1,
            SUM(CASE WHEN risk_score BETWEEN 21 AND 40 THEN 1 ELSE 0 END) as b2,
            SUM(CASE WHEN risk_score BETWEEN 41 AND 60 THEN 1 ELSE 0 END) as b3,
            SUM(CASE WHEN risk_score BETWEEN 61 AND 80 THEN 1 ELSE 0 END) as b4,
            SUM(CASE WHEN risk_score BETWEEN 81 AND 100 THEN 1 ELSE 0 END) as b5
        FROM scan_history
    ''')
    buckets = cursor.fetchone()
    risk_distribution = [
        buckets['b1'] or 0,
        buckets['b2'] or 0,
        buckets['b3'] or 0,
        buckets['b4'] or 0,
        buckets['b5'] or 0
    ]

    # Model usage distribution
    cursor.execute('''
        SELECT model_name, COUNT(*) as cnt 
        FROM scan_history 
        GROUP BY model_name 
        ORDER BY cnt DESC
    ''')
    model_rows = cursor.fetchall()
    model_usage = {r['model_name']: r['cnt'] for r in model_rows}

    # Recent scans timeline (Last 7 days or entries)
    cursor.execute('''
        SELECT DATE(timestamp) as scan_date, COUNT(*) as cnt,
               SUM(CASE WHEN verdict = 'PHISHING' THEN 1 ELSE 0 END) as phish_cnt
        FROM scan_history
        GROUP BY DATE(timestamp)
        ORDER BY scan_date ASC
        LIMIT 10
    ''')
    timeline_rows = cursor.fetchall()
    timeline = {
        'dates': [r['scan_date'] for r in timeline_rows],
        'total': [r['cnt'] for r in timeline_rows],
        'phishing': [r['phish_cnt'] for r in timeline_rows]
    }

    conn.close()

    return {
        'total_scans': total,
        'phishing_count': phishing,
        'suspicious_count': 0,
        'safe_count': safe,
        'avg_risk_score': avg_score,
        'avg_latency_ms': avg_latency,
        'verdict_distribution': {
            'Phishing': phishing,
            'Legitimate': safe
        },
        'risk_distribution': risk_distribution,
        'model_usage': model_usage,
        'timeline': timeline
    }

if __name__ == '__main__':
    init_db()
    print("Database initialized successfully at:", DEFAULT_DB_PATH)
