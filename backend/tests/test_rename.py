import sqlite3
from pathlib import Path
from backend.store import Store

def test_new_install_uses_new_database(tmp_path):
    store = Store(tmp_path)
    assert store.db.name == 'offsecs-u-ai.sqlite3'

def test_legacy_history_is_preserved(tmp_path):
    legacy = tmp_path / 'reconforge.sqlite3'
    with sqlite3.connect(legacy) as c:
        c.execute('CREATE TABLE targets(id TEXT PRIMARY KEY,url TEXT UNIQUE NOT NULL,created TEXT NOT NULL)')
        c.execute("INSERT INTO targets VALUES('existing','example.com','2026-01-01')")
    store = Store(tmp_path)
    assert store.db == legacy
    assert store.targets()[0]['id'] == 'existing'
    assert not (tmp_path / 'offsecs-u-ai.sqlite3').exists()
