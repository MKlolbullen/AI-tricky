#!/usr/bin/env python3
"""Install pinned assessment data and register typed inputs. No target traffic."""
import argparse
import json
import os
from pathlib import Path
import sys

sys.path.insert(0,str(Path(__file__).resolve().parent.parent))
from backend.store import Store
from backend.support_data import SupportData


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--data-dir',default=os.environ.get('AI_TRICKY_DATA_DIR') or os.environ.get('OFFSECS_U_AI_DATA_DIR') or os.environ.get('RECONFORGE_DATA_DIR','./local-data'))
    parser.add_argument('--install',choices=['bundled','nuclei-templates','jaeles-signatures'],action='append',help='Repeat to install multiple packages; default: bundled')
    parser.add_argument('--status',action='store_true',help='Inspect without downloading or registering inputs')
    parser.add_argument('--json',action='store_true')
    args=parser.parse_args()
    manager=SupportData(Store(Path(args.data_dir).resolve()))
    if not args.status:
        for identifier in args.install or ['bundled']:
            manager.install(identifier)
    status=manager.status()
    if args.json:print(json.dumps(status,indent=2))
    else:
        for entry in status['bundled']+status['remote']:
            print(f'{entry["name"]}: {"installed" if entry["installed"] else "not installed"} · {entry["revision"][:12]} · {len(entry["inputs"])} inputs')
        print('Bind installed inputs in the canvas or Run setup. No assessment tools or targets were invoked.')


if __name__=='__main__':main()
