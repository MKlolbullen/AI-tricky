#!/usr/bin/env python3
"""Download one checksummed Linux x86_64 AzureHound test binary from its official release."""
import argparse
import hashlib
import io
from pathlib import Path
import platform
import sys
import urllib.request
import zipfile

URL='https://github.com/SpecterOps/AzureHound/releases/download/v3.1.3/AzureHound_v3.1.3_linux_amd64.zip'
SHA256='b814116a9850658ef36be54c3f8e2d1560a0560ca377052206defac064e5a68d'


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('directory',type=Path);args=parser.parse_args()
    if sys.platform!='linux' or platform.machine() not in ('x86_64','AMD64'):parser.error('This CI fixture supports Linux x86_64 only.')
    with urllib.request.urlopen(URL,timeout=30) as response:raw=response.read(10000001)
    if len(raw)>10000000 or hashlib.sha256(raw).hexdigest()!=SHA256:raise RuntimeError('AzureHound release checksum did not match.')
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        entry=archive.getinfo('azurehound')
        if entry.file_size>30000000:raise RuntimeError('Unexpected AzureHound binary size.')
        binary=archive.read(entry)
    args.directory.mkdir(parents=True,exist_ok=True)
    path=args.directory/'azurehound';path.write_bytes(binary);path.chmod(0o755)
    print('Prepared AzureHound v3.1.3 with verified archive checksum.')


if __name__=='__main__':main()
