#!/usr/bin/env python3
"""Synthetic baseline-drift demo; scans only a temporary fixture it creates."""
import argparse
import json
import shutil
import subprocess
import tempfile
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', default='mcp-drift', help='Your installed mcp-drift binary')
    args = parser.parse_args()
    binary = shutil.which(args.binary)
    if binary is None:
        parser.error('mcp-drift not found; install the pinned release or specify --binary')
    binary = str(Path(binary).resolve())
    with tempfile.TemporaryDirectory(prefix='orynval-synthetic-demo-') as directory:
        root = Path(directory)
        config = {'mcpServers': {'demo': {'url': 'https://approved.example/mcp'}}}
        path = root / '.mcp.json'
        path.write_text(json.dumps(config), encoding='utf-8')
        baseline = subprocess.run([binary, '--print-baseline', directory],
                                  capture_output=True, text=True, check=True)
        json.loads(baseline.stdout)  # Refuse to save malformed output.
        (root / '.orynval').mkdir()
        (root / '.orynval/mcp-baseline.json').write_text(baseline.stdout, encoding='utf-8')
        before = subprocess.run([binary, '-f', 'json', '--fail-on', 'high', directory],
                                capture_output=True, text=True, check=True)
        if any('baseline-drift' in f['title'] for f in json.loads(before.stdout)['findings']):
            raise RuntimeError('Unexpected drift before the synthetic change')
        config['mcpServers']['demo']['url'] = 'https://changed.example/mcp'
        path.write_text(json.dumps(config), encoding='utf-8')
        after = subprocess.run([binary, '-f', 'json', '--fail-on', 'high', directory],
                               capture_output=True, text=True)
        findings = json.loads(after.stdout)['findings']
        drift = [f for f in findings if 'baseline-drift' in f['title']]
        if after.returncode != 3 or not drift:
            raise RuntimeError('Expected baseline drift and a HIGH-policy exit code of 3')
        print('Synthetic demo: no real company configuration or incident.')
        print('Only the temporary fixture created by this script was scanned.')
        print('Before change: no baseline drift; HIGH policy passed.')
        print('After URL change: baseline drift detected; HIGH policy exit code = 3.')
        print('The configured server was not started or contacted.')
        print('This shows configuration change detection, not prevention or runtime compromise.')
        print(drift[0]['title'])


if __name__ == '__main__':
    main()
