import os
import uvicorn
from .app import create_app

if __name__ == '__main__':
    os.umask(0o077)
    # Intentional fixed loopback bind. No remote-host override; only the port
    # is configurable (AI_TRICKY_PORT), so the platform is never exposed off-host.
    try:
        port = int(os.environ.get('AI_TRICKY_PORT') or 8787)
    except ValueError:
        port = 8787
    port = port if 1 <= port <= 65535 else 8787
    uvicorn.run(create_app(), host='127.0.0.1', port=port, access_log=False)
