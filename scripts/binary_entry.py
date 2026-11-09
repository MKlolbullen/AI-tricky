"""PyInstaller entry point for the standalone AI-tricky binary.

Serves the API and the bundled UI on loopback only. Runtime data files
(catalog, native registry, payloads, UI) are bundled alongside the backend
package, so the backend's ROOT-relative paths resolve inside the extracted
bundle with no code change. The optional CAI SDK stays external (CAI_PYTHON);
native assessment and the whole platform run without it.
"""
import os

import uvicorn

from backend.app import create_app


def main():
    os.umask(0o077)
    # Intentional fixed loopback bind. No remote-host override; only the port
    # is configurable, so the platform is never exposed off-host.
    try:
        port = int(os.environ.get('AI_TRICKY_PORT') or 8787)
    except ValueError:
        port = 8787
    port = port if 1 <= port <= 65535 else 8787
    print(f'AI-tricky → http://127.0.0.1:{port}   (Ctrl-C to stop)', flush=True)
    uvicorn.run(create_app(), host='127.0.0.1', port=port, access_log=False)


if __name__ == '__main__':
    main()
