#!/usr/bin/env bash
# publish-repo.sh — regenerate the apt index for the soardev repo and stage it
# into a checkout of erv5/repo. Run after lane debs have been downloaded into
# ./release-debs/. Idempotent: only rewrites Packages*/Release when content
# actually changed.
#
# Usage: publish-repo.sh <repo-checkout-dir> <debs-dir>
set -euo pipefail

REPO_DIR="${1:?usage: publish-repo.sh <repo-checkout-dir> <debs-dir>}"
DEBS_DIR="${2:?usage: publish-repo.sh <repo-checkout-dir> <debs-dir>}"

command -v dpkg-scanpackages >/dev/null 2>&1 || { echo "error: dpkg-scanpackages not found" >&2; exit 1; }

mkdir -p "$REPO_DIR/debs"

# Copy any debs in, newest-wins per package id (dpkg-scanpackages takes the
# first occurrence; keep only the latest version of each package id).
cp -f "$DEBS_DIR"/*.deb "$REPO_DIR/debs/" 2>/dev/null || true

# Prune to latest version per (package id, architecture). The same package at
# the same version ships as separate debs per lane (rootless=iphoneos-arm64,
# roothide=iphoneos-arm64e); those are distinct and must coexist, so the key
# includes Architecture, not just Package.
python3 - "$REPO_DIR/debs" <<'PY'
import os, re, subprocess, sys
debs = sys.argv[1]
def ver_key(v):
    return [int(t) if t.isdigit() else t for t in re.split(r'([0-9]+)', v)]
latest = {}
for f in os.listdir(debs):
    if not f.endswith('.deb'): continue
    p = os.path.join(debs, f)
    try:
        raw = subprocess.check_output(
            ['dpkg-deb','-f',p,'Package','Version','Architecture']).decode().splitlines()
    except Exception:
        continue
    # dpkg-deb -f prints bare values on some builds, "Field: value" on others;
    # strip any "Field: " label so the key is just (pkgid, arch) either way.
    vals = [l.split(': ',1)[1] if ': ' in l else l for l in raw]
    if len(vals) < 3: continue
    pkgid, ver, arch = vals[0].strip(), vals[1].strip(), vals[2].strip()
    key = (pkgid, arch)
    cur = latest.get(key)
    if cur is None or ver_key(ver) > ver_key(cur[0]):
        latest[key] = (ver, p)
keep = {v[1] for v in latest.values()}
for f in os.listdir(debs):
    p = os.path.join(debs, f)
    if f.endswith('.deb') and p not in keep:
        os.remove(p)
PY

# Regenerate the package index. Paths in Packages must be relative to the repo
# root, so scan from inside the repo dir.
( cd "$REPO_DIR" && dpkg-scanpackages -m debs /dev/null > Packages )

gzip -9 -c "$REPO_DIR/Packages" > "$REPO_DIR/Packages.gz"
if command -v bzip2 >/dev/null 2>&1; then
  bzip2 -9 -c "$REPO_DIR/Packages" > "$REPO_DIR/Packages.bz2"
fi

# Release file: fixed metadata + fresh checksums for the index files.
DATE="$(LC_ALL=C date -u '+%a, %d %b %Y %H:%M:%S UTC')"
cat > "$REPO_DIR/Release" <<EOF
Origin: soardev repo
Label: soardev repo
Suite: stable
Version: 1.0
Codename: soardev
Date: $DATE
Architectures: iphoneos-arm64 iphoneos-arm64e
Components: main
Description: soardev repo — Shadow fork (beta) by erv5, based on jjolano/shadow
MD5Sum:
EOF
( cd "$REPO_DIR" && for f in Packages Packages.gz Packages.bz2; do
  [ -f "$f" ] || continue
  printf ' %s %16d %s\n' "$(md5 -q "$f" 2>/dev/null || md5sum "$f" | awk '{print $1}')" "$(stat -f%z "$f" 2>/dev/null || stat -c%s "$f")" "$f" >> Release
done )

echo "published index for $(ls "$REPO_DIR/debs"/*.deb 2>/dev/null | wc -l | tr -d ' ') deb(s) in $REPO_DIR"
