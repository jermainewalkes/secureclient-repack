#!/bin/bash
#
# Asserts the macOS end-to-end run produced a correctly stripped package.
# Run against the --output directory of a `--keep umbrella` build of the
# synthetic fixture DMG.
#
set -euo pipefail

OUT="${1:?usage: assert-output.sh <output-dir>}"
PKG="$OUT/Cisco Secure Client-9.9.9.9-vpn-ui-umbrella.pkg"

fail(){ echo "ASSERTION FAILED: $*" >&2; exit 1; }

if [[ ! -f "$PKG" ]]; then
  ls -la "$OUT" >&2
  fail "expected package not found: $PKG"
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
pkgutil --expand "$PKG" "$WORK/x"
DIST="$WORK/x/Distribution"

for keep in module_vpn module_ui module_umbrella; do
  if ! grep -qF "choice=\"$keep\"" "$DIST"; then fail "kept choice missing: $keep"; fi
done
for drop in module_dart module_nvm; do
  if grep -qF "choice=\"$drop\"" "$DIST"; then fail "dropped choice still present: $drop"; fi
done

# the outline must list exactly the three kept modules
lines="$(awk '/<choices-outline>/,/<\/choices-outline>/' "$DIST" | grep -c '<line ')"
if [[ "$lines" -ne 3 ]]; then fail "expected 3 outline entries, found $lines"; fi

# orphaned payloads are gone, including the one shared by the two dropped modules
for gone in dart_module.pkg nvm_module.pkg common_module.pkg; do
  if [[ -d "$WORK/x/$gone" ]]; then fail "orphaned payload survived: $gone"; fi
done
for kept in vpn_module.pkg ui_module.pkg umbrella_module.pkg; do
  if [[ ! -d "$WORK/x/$kept" ]]; then fail "kept payload missing: $kept"; fi
done

# no dangling reference to a payload that is no longer on disk
while IFS= read -r ref; do
  f="${ref#\#}"
  [[ -n "$f" ]] || continue
  if [[ ! -d "$WORK/x/$f" ]]; then fail "Distribution references missing payload: $f"; fi
done < <(grep 'pkg-ref' "$DIST" | grep -oE '#[^"<[:space:]]+' | sort -u)

# the OrgInfo deploy script is produced even though this run did not sign
ORG="$OUT/deploy-orginfo.sh"
if [[ ! -x "$ORG" ]]; then fail "OrgInfo deploy script missing or not executable: $ORG"; fi
bash -n "$ORG"
if ! grep -q 'ORGINFO_B64=' "$ORG"; then fail "OrgInfo script does not embed the profile"; fi
if grep -qx 'ORGINFO_EOF' "$ORG"; then fail "OrgInfo script still uses a heredoc terminator"; fi

echo "end-to-end assertions passed"
