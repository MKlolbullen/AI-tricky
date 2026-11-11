#!/usr/bin/env python3
"""Report pinned tool versions using local executable metadata."""

import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from backend.recon_tools import PROFILES_BY_GROUP, tool_check


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--profile', choices=PROFILES_BY_GROUP, default='web-recon')
    parser.add_argument('--tool')
    parser.add_argument('--binary', type=Path)
    args = parser.parse_args()
    if args.binary and not args.tool:
        parser.error('--binary requires --tool')
    profiles = PROFILES_BY_GROUP[args.profile]
    if args.tool and args.tool not in profiles:
        parser.error('Select a tool from the chosen profile.')
    results = [tool_check(tool, args.binary) for tool in ([args.tool] if args.tool else profiles)]
    print(json.dumps(results, indent=2))
    return int(any(result['status'] != 'tested_version' for result in results))


if __name__ == '__main__':
    sys.exit(main())
