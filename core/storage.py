"""Small SQLite storage primitives for normalized assets and resumable runs."""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from datetime import datetime, timezone

ASSET_STATES = ('discovered', 'probed', 'enumerated', 'triaged')
SCHEMA = '''
CREATE TABLE IF NOT EXISTS core_assets (
  id INTEGER PRIMARY KEY, scan_id TEXT NOT NULL, kind TEXT NOT NULL, value TEXT NOT NULL,
  state TEXT NOT NULL DEFAULT 'discovered', data_json TEXT NOT NULL DEFAULT '{}',
  created_at TEXT NOT NULL, updated_at TEXT NOT NULL, UNIQUE(scan_id,kind,value));
CREATE TABLE IF NOT EXISTS core_tool_history (
  id INTEGER PRIMARY KEY, scan_id TEXT NOT NULL, stage_id TEXT NOT NULL, tool TEXT NOT NULL,
  target TEXT NOT NULL, status TEXT NOT NULL, profile TEXT NOT NULL DEFAULT 'standard',
  started_at TEXT NOT NULL, finished_at TEXT, output_ref TEXT, detail TEXT);
CREATE INDEX IF NOT EXISTS idx_core_assets_scan_state ON core_assets(scan_id,state);
CREATE INDEX IF NOT EXISTS idx_core_tool_scan ON core_tool_history(scan_id,stage_id,tool,target);
'''

def _now():
    return datetime.now(timezone.utc).isoformat()

class Store:
    def __init__(self, path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as db:
            db.executescript(SCHEMA)

    def connect(self):
        db = sqlite3.connect(self.path, timeout=15)
        db.row_factory = sqlite3.Row
        return db

    def upsert_asset(self, scan_id, kind, value, data=None, state='discovered'):
        if state not in ASSET_STATES:
            raise ValueError(f'Estado de ativo inválido: {state}')
        now = _now()
        with self.connect() as db:
            previous = db.execute('SELECT state FROM core_assets WHERE scan_id=? AND kind=? AND value=?',
                                  (scan_id, kind, value)).fetchone()
            effective_state = state
            if previous and ASSET_STATES.index(previous['state']) > ASSET_STATES.index(state):
                effective_state = previous['state']
            db.execute('''INSERT INTO core_assets(scan_id,kind,value,state,data_json,created_at,updated_at)
                VALUES(?,?,?,?,?,?,?) ON CONFLICT(scan_id,kind,value) DO UPDATE SET
                state=excluded.state,data_json=excluded.data_json,updated_at=excluded.updated_at''',
                (scan_id, kind, value, effective_state, json.dumps(data or {}, ensure_ascii=False), now, now))

    def assets(self, scan_id):
        with self.connect() as db:
            return [dict(row) for row in db.execute(
                'SELECT * FROM core_assets WHERE scan_id=? ORDER BY id', (scan_id,))]

    def set_state(self, scan_id, kind, value, state):
        if state not in ASSET_STATES:
            raise ValueError(f'Estado de ativo inválido: {state}')
        with self.connect() as db:
            db.execute('UPDATE core_assets SET state=?,updated_at=? WHERE scan_id=? AND kind=? AND value=?',
                       (state, _now(), scan_id, kind, value))

    def export_jsonl(self, scan_id, path):
        rows = self.assets(scan_id)
        Path(path).write_text(''.join(json.dumps(row, ensure_ascii=False)+'\n' for row in rows), encoding='utf-8')
        return len(rows)

    def export_txt(self, scan_id, path):
        rows = self.assets(scan_id)
        Path(path).write_text(''.join(f"{r['kind']}\t{r['state']}\t{r['value']}\n" for r in rows), encoding='utf-8')
        return len(rows)

    def completed_targets(self, scan_id):
        with self.connect() as db:
            return {(r['stage_id'], r['tool'], r['target']) for r in db.execute(
                "SELECT stage_id,tool,target FROM core_tool_history WHERE scan_id=? AND status='completed'",
                (scan_id,))}

    def record_tool(self, scan_id, stage_id, tool, target, status, profile='standard', output_ref=None, detail=''):
        now = _now()
        with self.connect() as db:
            db.execute('''INSERT INTO core_tool_history
              (scan_id,stage_id,tool,target,status,profile,started_at,finished_at,output_ref,detail)
              VALUES(?,?,?,?,?,?,?,?,?,?)''',
              (scan_id, stage_id, tool, target, status, profile, now, now, output_ref, detail))
