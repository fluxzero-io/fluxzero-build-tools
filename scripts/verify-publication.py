#!/usr/bin/env python3
"""Compare anonymous published bytes with the locally tested publication."""
from pathlib import Path
import hashlib,subprocess
root=Path(__file__).resolve().parents[1]/'build/repository'
count=0
for file in sorted(root.rglob('*')):
 if not file.is_file() or file.name.startswith('maven-metadata'):continue
 relative=file.relative_to(root).as_posix()
 data=subprocess.check_output(['curl','--fail','--silent','--show-error','--retry','5','--retry-all-errors','https://packages.fluxzero.io/maven/'+relative])
 assert hashlib.sha256(data).digest()==hashlib.sha256(file.read_bytes()).digest(),relative
 count+=1
assert count>0
print(f'Verified {count} anonymous publication files against local SHA-256 digests')
