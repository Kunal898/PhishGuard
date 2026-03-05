import os
import json
import sqlite3
from typing import List, Dict, Any

# Path to SQLite database file (placed in backend directory)
DB_PATH = os.path.join(os.path.dirname(__file__), 'phishguard.db')

def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Create tables if they do not exist."""
    conn = get_connection()
    cur = conn.cursor()
    # Scans table stores each scan result
    cur.execute('''
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL,
            prediction TEXT,
            confidence REAL,
            risk_score REAL,
            features TEXT,
            probabilities TEXT,
            timestamp TEXT,
            scan_source TEXT
        )
    ''')
    # Reports table stores user‑submitted phishing reports
    cur.execute('''
        CREATE TABLE IF NOT EXISTS reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL,
            reason TEXT,
            reported_at TEXT,
            status TEXT,
            report_to_cybercrime INTEGER
        )
    ''')
    conn.commit()
    conn.close()

def save_scan(scan_data: Dict[str, Any]) -> int:
    """Insert a scan record and return its row id."""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        '''
        INSERT INTO scans (url, prediction, confidence, risk_score, features, probabilities, timestamp, scan_source)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''',
        (
            scan_data.get('url'),
            scan_data.get('prediction'),
            scan_data.get('confidence'),
            scan_data.get('risk_score'),
            json.dumps(scan_data.get('features', {})),
            json.dumps(scan_data.get('probabilities', {})),
            scan_data.get('timestamp'),
            scan_data.get('scan_source')
        )
    )
    row_id = cur.lastrowid
    conn.commit()
    conn.close()
    return row_id

def save_report(report_data: Dict[str, Any]) -> int:
    """Insert a report record and return its row id."""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        '''
        INSERT INTO reports (url, reason, reported_at, status, report_to_cybercrime)
        VALUES (?, ?, ?, ?, ?)
        ''',
        (
            report_data.get('url'),
            report_data.get('reason'),
            report_data.get('reported_at'),
            report_data.get('status'),
            int(bool(report_data.get('report_to_cybercrime')))
        )
    )
    row_id = cur.lastrowid
    conn.commit()
    conn.close()
    return row_id

def get_recent_scans(limit: int = 20) -> List[Dict[str, Any]]:
    conn = get_connection()
    cur = conn.cursor()
    cur.execute('SELECT * FROM scans ORDER BY timestamp DESC LIMIT ?', (limit,))
    rows = cur.fetchall()
    conn.close()
    results = []
    for r in rows:
        results.append({
            'id': r['id'],
            'url': r['url'],
            'prediction': r['prediction'],
            'confidence': r['confidence'],
            'risk_score': r['risk_score'],
            'features': json.loads(r['features'] or '{}'),
            'probabilities': json.loads(r['probabilities'] or '{}'),
            'timestamp': r['timestamp'],
            'scan_source': r['scan_source']
        })
    return results

def get_scan_stats() -> Dict[str, int]:
    conn = get_connection()
    cur = conn.cursor()
    cur.execute('SELECT COUNT(*) FROM scans')
    total = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM scans WHERE prediction='Phishing'")
    phishing = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM scans WHERE prediction='Suspicious'")
    suspicious = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM scans WHERE prediction='Safe'")
    safe = cur.fetchone()[0]
    cur.execute('SELECT COUNT(*) FROM reports')
    reports = cur.fetchone()[0]
    conn.close()
    return {
        'total_scans': total,
        'phishing_detected': phishing,
        'phishing_count': phishing,
        'suspicious_detected': suspicious,
        'suspicious_count': suspicious,
        'safe_detected': safe,
        'safe_count': safe,
        'total_reports': reports
    }

def get_all_scans() -> List[Dict[str, Any]]:
    conn = get_connection()
    cur = conn.cursor()
    cur.execute('SELECT * FROM scans ORDER BY timestamp DESC')
    rows = cur.fetchall()
    conn.close()
    results = []
    for r in rows:
        results.append({
            'url': r['url'],
            'prediction': r['prediction'],
            'confidence': r['confidence'],
            'risk_score': r['risk_score'],
            'timestamp': r['timestamp'],
            'scan_source': r['scan_source']
        })
    return results

def get_reports(limit: int = 20) -> List[Dict[str, Any]]:
    conn = get_connection()
    cur = conn.cursor()
    cur.execute('SELECT * FROM reports ORDER BY reported_at DESC LIMIT ?', (limit,))
    rows = cur.fetchall()
    conn.close()
    reports = []
    for r in rows:
        reports.append({
            'id': r['id'],
            'url': r['url'],
            'reason': r['reason'],
            'reported_at': r['reported_at'],
            'status': r['status'],
            'report_to_cybercrime': bool(r['report_to_cybercrime'])
        })
    return reports
