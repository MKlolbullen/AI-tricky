#!/usr/bin/env python3
"""Report the web recon tool versions using local executable metadata."""

import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from backend.recon_tools import PROFILES, tool_check


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--tool', choices=PROFILES)
    parser.add_argument('--binary', type=Path)
    args = parser.parse_args()
    if args.binary and not args.tool:
        parser.error('--binary requires --tool')
    results = [tool_check(tool, args.binary) for tool in ([args.tool] if args.tool else PROFILES)]
    print(json.dumps(results, indent=2))
    return int(any(result['status'] != 'tested_version' for result in results))


if __name__ == '__main__':
    sys.exit(main())
