"""PyInstaller entry point for the standalone AI-tricky binary.

Serves the API and the bundled UI on loopback only. Runtime data files
(catalog, native registry, payloads, UI) are bundled alongside the backend
package, so the backend's ROOT-relative paths resolve inside the extracted
bundle with no code change. The optional CAI SDK stays external (CAI_PYTHON);
native assessment and the whole platform run without it.
"""
from backend.__main__ import main


if __name__ == '__main__':
    main()
