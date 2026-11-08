"""Inspect authoritative release distributions and record their exact hashes."""
import argparse
import hashlib
import json
import tarfile
import zipfile
from pathlib import Path


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--directory',type=Path,default=Path('dist'))
    parser.add_argument('--version',required=True)
    parser.add_argument('--revision',required=True)
    args=parser.parse_args()
    artifacts=sorted(args.directory.glob('*'))
    assert len(artifacts)==2, 'release must contain exactly one wheel and one sdist'
    hashes={}
    for artifact in artifacts:
        assert args.version in artifact.name
        hashes[artifact.name]=hashlib.sha256(artifact.read_bytes()).hexdigest()
        if artifact.suffix=='.whl':
            with zipfile.ZipFile(artifact) as archive:
                names=archive.namelist()
                assert all('agent_circuit_breaker/demo_assets/'+name in names for name in ('index.html','app.js','style.css'))
                metadata=archive.read(next(n for n in names if n.endswith('.dist-info/METADATA'))).decode()
                assert 'Version: '+args.version+'\n' in metadata
        else:
            assert artifact.name.endswith('.tar.gz')
            with tarfile.open(artifact) as archive:
                names=archive.getnames()
                assert any(n.endswith('/setup.py') for n in names)
        for name in names:
            assert not any(part in name for part in ('/.git/','/.env','/raw/','.mp4','.webm','.sqlite3','provenance.key','.acb-integrations')),(artifact.name,name)
    manifest={'source_revision':args.revision,'version':args.version,'sha256':hashes}
    Path('release-manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
    Path('SHA256SUMS').write_text(''.join(value+'  '+name+'\n' for name,value in hashes.items()))
    print(json.dumps(manifest,indent=2))

if __name__=='__main__':
    main()
