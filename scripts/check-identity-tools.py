#!/usr/bin/env python3
"""Check the owned identity CLI argv via --help, without engagement credentials."""
import argparse
import asyncio
import json
from pathlib import Path
import sys

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from backend.identity_cli_check import check_cli_contract
from backend.identity_tools import PROFILES, pin_profile
from backend.scope import ScopeError


async def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--profile',action='append',choices=sorted(PROFILES),help='Repeat to select profiles; default is all four.')
    options=parser.parse_args();results=[]
    for key in options.profile or PROFILES:
        profile=PROFILES[key]
        try:pin=pin_profile(profile)
        except ScopeError:
            results.append({'profile_id':key,'status':'missing_binary'});continue
        results.append(await check_cli_contract(profile,pin['path']))
    print(json.dumps({'schema':'ai-tricky.identity-cli-checks/v1','checks':results},indent=2))
    return 0 if all(row['status']=='passed' for row in results) else 1


if __name__=='__main__':sys.exit(asyncio.run(main()))
