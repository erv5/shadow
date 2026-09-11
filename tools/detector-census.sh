#!/bin/sh
# detector-census.sh — inventory jailbreak/tamper detector SDKs embedded in installed apps.
# Run ON-DEVICE (as root) or over SSH with sudo. Handles app names with spaces.
#
# A detector SDK almost always ships as an embedded .framework (or a SPM static
# lib that still leaves a recognizable image name). The image path suffix is the
# signature Shadow's DetectorAutoDetect keys on — this script collects those names
# so we know which adapters an app needs.
#
# Usage:  sh tools/detector-census.sh            # human-readable
#         sh tools/detector-census.sh --signatures   # just image-suffix signatures

SIG_ONLY=0
[ "$1" = "--signatures" ] && SIG_ONLY=1

# Known detector substring patterns (extend as new SDKs appear). Matched
# case-insensitively against embedded framework names AND the app executable's
# linked-library list (otool) to catch static/SPM embeds with no .framework dir.
PATTERNS='shield|security|guard|detect|rasp|talsec|promon|solid|appsealing|sealing|liapp|nprotect|xigncode|senta|vkey|v-key|build38|tak|iproov|jailmonkey|freerasp|iossecuritysuite|devicesecuritykit|batjailbreak|dttjailbreak|trusteer|cyberark|intercept|arpx|dxshield|keychain|obfusc'

found_any=0
for app in /var/containers/Bundle/Application/*/*.app; do
    [ -d "$app" ] || continue
    name=$(basename "$app" .app)

    # 1) embedded framework dirs
    fw_hits=""
    if [ -d "$app/Frameworks" ]; then
        fw_hits=$(ls "$app/Frameworks/" 2>/dev/null \
            | grep -iE "$PATTERNS" | sed 's/\.framework$//')
    fi

    # 2) linked images on the executable (catches static/SPM embeds)
    bin="$app/$name"
    [ -f "$bin" ] || bin=$(find "$app" -maxdepth 1 -type f -perm +111 2>/dev/null | head -1)
    img_hits=""
    if [ -n "$bin" ] && command -v otool >/dev/null 2>&1; then
        img_hits=$(otool -L "$bin" 2>/dev/null \
            | grep -iE "$PATTERNS" | sed -E 's#.*[/@]([A-Za-z0-9_.-]+)\.(framework|dylib).*#\1#' | sort -u)
    fi

    hits=$(printf '%s\n%s\n' "$fw_hits" "$img_hits" | sed '/^$/d' | sort -u)
    [ -z "$hits" ] && continue
    found_any=1

    if [ "$SIG_ONLY" = 1 ]; then
        printf '%s\n' "$hits"
    else
        printf '### %s\n' "$name"
        printf '%s\n' "$hits" | sed 's/^/    /'
    fi
done

[ "$found_any" = 0 ] && echo "no detector SDKs found"
exit 0
