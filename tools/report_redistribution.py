#!/usr/bin/env python3
"""Render the recorded source-specific licensing findings; not legal clearance.

Re-fetch evidence with audit_redistribution.py. Live requests do not automatically
validate or replace the historical human-reviewed findings in source-licenses.json.
"""
import json
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
def main():
    data = json.loads((ROOT / 'docs/source-licenses.json').read_text())
    lines = ['# Source-specific licensing findings', '',
             'Historical review, not legal advice. Public all-source publication was an owner decision, not resolution of these findings.', '',
             '| Source ID / URL | Included | License finding | Review status | Requirements |',
             '|---|---|---|---|---|']
    for s in data['sources']:
        clean = lambda value: str(value).replace('|', r'\|').replace('\n', ' ')
        lines.append('| ' + ' | '.join(map(clean, [s['id'] + ' / ' + s['url'], s['included'], s['license'], s['review_status'], s['requirements']])) + ' |')
    (ROOT / 'docs/source-licenses.md').write_text('\n'.join(lines) + '\n')
    print(f"Rendered {len(data['sources'])} catalog entries; no legal certification")
if __name__ == '__main__':
    main()
