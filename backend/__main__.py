import os
import uvicorn
from .app import create_app

if __name__ == '__main__':
    os.umask(0o077)
    # Intentional fixed loopback bind. No remote-host override.
    uvicorn.run(create_app(), host='127.0.0.1', port=8787, access_log=False)
