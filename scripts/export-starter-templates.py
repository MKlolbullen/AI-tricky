"""Export server-built curated starters to docs/templates (no network).

The curated catalog (src/templates.json) names each starter; the graph itself is
built and type-validated by the backend. This writes an importable copy of every
starter so the documented file can never drift from the tool and native socket
contracts. `--check` fails when a committed file differs from the builder.
"""
import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from backend.web_recon import web_app_assessment_workflow  # noqa: E402

BUILDERS = {'web-app-assessment': web_app_assessment_workflow}


def exports():
    curated = json.loads((ROOT / 'src/templates.json').read_text())['workflows']
    for entry in curated:
        starter = entry.get('starter')
        if not starter:
            continue
        if starter not in BUILDERS:
            raise SystemExit(f'No builder is registered for curated starter {starter!r}.')
        body = {**entry, **BUILDERS[starter]()}
        yield ROOT / 'docs/templates' / f'{starter}-workflow.json', json.dumps(body, indent=2) + '\n'


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    stale = []
    for path, body in exports():
        if args.check:
            if not path.exists() or path.read_text() != body:
                stale.append(str(path.relative_to(ROOT)))
        else:
            path.write_text(body)
            print('wrote', path.relative_to(ROOT))
    if stale:
        raise SystemExit('Stale starter exports (run scripts/export-starter-templates.py): ' + ', '.join(stale))
