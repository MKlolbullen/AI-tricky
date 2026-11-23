import os
import sqlite3
import uvicorn
from .app import create_app, workspace_path


def main():
    os.umask(0o077)
    # Intentional fixed loopback bind. No remote-host override; only the port
    # is configurable (AI_TRICKY_PORT), so the platform is never exposed off-host.
    try:
        port = int(os.environ.get('AI_TRICKY_PORT') or 8787)
    except ValueError:
        port = 8787
    port = port if 1 <= port <= 65535 else 8787
    root = workspace_path().absolute()
    try:
        app = create_app(root)
    except sqlite3.DatabaseError as exc:
        raise SystemExit(f'Could not open or upgrade SQLite in {root}. Check that the workspace is writable '
                         f'and no other instance is using it. Preserve a copy before attempting repair. SQLite: {exc}') from None
    except OSError as exc:
        raise SystemExit(f'Could not initialize the workspace at {root}. Check AI_TRICKY_DATA_DIR and '
                         f'the filesystem permissions. Details: {exc}') from None
    print(f'AI-tricky → http://127.0.0.1:{port}   (Ctrl-C to stop)', flush=True)
    uvicorn.run(app, host='127.0.0.1', port=port, access_log=False)


if __name__ == '__main__':
    main()
