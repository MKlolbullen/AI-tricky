"""Smoke-test a Linux executable against fresh and historical disposable workspaces."""
import json
import os
from contextlib import contextmanager
from pathlib import Path
import signal
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
from urllib.error import URLError
from urllib.request import urlopen

FIXTURE = Path(__file__).resolve().parents[1] / 'backend/tests/fixtures/workspaces/v0.5-reviewed.sql'


@contextmanager
def running(command, root):
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        port = sock.getsockname()[1]
    env = dict(os.environ, HOME=str(root.parent), AI_TRICKY_DATA_DIR=str(root), AI_TRICKY_PORT=str(port))
    proc = subprocess.Popen(command, cwd=root.parent, env=env, start_new_session=True)
    base = f'http://127.0.0.1:{port}'

    def get(path):
        with urlopen(base + path, timeout=5) as response:
            return json.load(response)

    try:
        deadline = time.monotonic() + 45
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                raise RuntimeError(f'Application exited during startup with status {proc.returncode}')
            try:
                get('/api/runs')
                break
            except ConnectionRefusedError:
                pass
            except URLError as exc:
                if not isinstance(exc.reason, ConnectionRefusedError):
                    raise
            time.sleep(0.2)
        else:
            raise RuntimeError('Application never became ready on loopback')
        with urlopen(base + '/', timeout=5) as response:
            assert b'id="root"' in response.read(), 'Packaged UI is missing'
        yield get
    finally:
        if proc.poll() is None:
            os.killpg(proc.pid, signal.SIGTERM)
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                os.killpg(proc.pid, signal.SIGKILL)
                proc.wait()


def check_upgrade(command, root, filename):
    root.mkdir()
    db_path = root / filename
    with sqlite3.connect(db_path) as db:
        db.executescript(FIXTURE.read_text())
        rid, = db.execute('SELECT id FROM runs').fetchone()
        review_id, fid, note, aid, revision, decision = db.execute(
            'SELECT id,finding_id,note,evidence_id,revision,decision FROM finding_reviews').fetchone()
        captures = {key: json.loads(body) for key, body in db.execute('SELECT id,content FROM artifacts')}
        original_occurrences = list(db.execute('SELECT observation_id FROM finding_occurrences WHERE finding_id=?', (fid,)))
    for _ in range(2):
        with running(command, root) as get:
            assert [r['id'] for r in get('/api/runs')] == [rid]
            page = get('/api/findings?run_id=' + rid)
            assert page['total'] == 1 and page['items'][0]['id'] == fid
            finding = get('/api/findings/' + fid)
            review, = finding['reviews']
            assert (review['id'], review['note'], review['evidence_id']) == (review_id, note, aid)
            assert review['revision'] == finding['revision'] == revision
            for field, value in json.loads(decision).items():
                assert finding[field] == review['decision'][field] == value
            assert {o['observation_id'] for o in finding['occurrences'] if o['active']} == {o[0] for o in original_occurrences}
            for key, original in captures.items():
                assert get('/api/artifacts/' + key) == original
            exported, = get(f'/api/runs/{rid}/assessment-report')['findings']
            assert exported['review']['id'] == review_id and aid in exported['artifact_ids']
        assert set(root.glob('*.sqlite3')) == {db_path}, 'Startup selected a different workspace file'
        with sqlite3.connect(db_path) as db:
            assert db.execute('PRAGMA integrity_check').fetchall() == [('ok',)]
    print(f'PASS: preserved {filename}, its evidence and review through upgrade and restart.', flush=True)


def main(command):
    with tempfile.TemporaryDirectory(prefix='ai-tricky-release-') as temporary:
        work = Path(temporary)
        with running(command, work / 'new') as get:
            assert get('/api/runs') == [] and get('/api/findings')['total'] == 0
        assert (work / 'new/offsecs-u-ai.sqlite3').is_file()
        print('PASS: new workspace, API and bundled UI.', flush=True)
        for filename in ('offsecs-u-ai.sqlite3', 'reconforge.sqlite3'):
            check_upgrade(command, work / filename.removesuffix('.sqlite3'), filename)
        broken = work / 'invalid'
        broken.mkdir()
        database = broken / 'offsecs-u-ai.sqlite3'
        original = b'synthetic invalid database'
        database.write_bytes(original)
        failed = subprocess.run(command, cwd=work, env=dict(os.environ, HOME=str(work), AI_TRICKY_DATA_DIR=str(broken)),
                                capture_output=True, text=True, timeout=45)
        assert failed.returncode and str(broken) in failed.stderr and 'SQLite' in failed.stderr
        assert database.read_bytes() == original
        print('PASS: invalid database diagnosed and retained.')


if __name__ == '__main__':
    if len(sys.argv) < 2:
        sys.exit('Usage: python scripts/check-workspace-upgrade.py /absolute/path/to/ai-tricky')
    main(sys.argv[1:])
