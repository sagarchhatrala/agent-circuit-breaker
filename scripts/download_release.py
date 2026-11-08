"""Fetch both indexed distributions and require the authoritative bytes."""
import hashlib
import json
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path


def main():
    manifest = json.loads(Path(sys.argv[1]).read_text())
    index = sys.argv[2]
    assert index in ('pypi.org', 'test.pypi.org')
    destination = Path(sys.argv[3])
    destination.mkdir(exist_ok=True)
    url = f'https://{index}/pypi/agent-circuit-breaker/{manifest["version"]}/json'
    for attempt in range(12):
        try:
            with urllib.request.urlopen(url, timeout=20) as response:
                indexed = json.load(response)
            break
        except urllib.error.HTTPError as exc:
            if exc.code != 404 or attempt == 11:
                raise
            time.sleep(5)
    else:
        raise RuntimeError('package index has not exposed the release')
    urls = {item['filename']: item for item in indexed['urls']}
    assert set(urls) == set(manifest['sha256']), 'unexpected/missing indexed distributions'
    for name, expected in manifest['sha256'].items():
        item = urls[name]
        assert item['digests']['sha256'] == expected, 'index digest differs from build'
        assert Path(name).name == name
        with urllib.request.urlopen(item['url'], timeout=60) as response:
            data = response.read()
        assert hashlib.sha256(data).hexdigest() == expected, 'download differs from build'
        (destination / name).write_bytes(data)
    print('Indexed wheel and sdist exactly match the authoritative build')


if __name__ == '__main__':
    main()
