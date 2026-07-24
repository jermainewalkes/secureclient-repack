#!/bin/bash
#
# Builds a synthetic predeploy DMG for the macOS end-to-end test.
#
# Nothing here comes from Cisco. The package mirrors only the *structure* of an
# expanded multi-module installer: a Distribution listing leaf choices, and one
# payload folder per component, with a payload shared by two optional modules so
# the shared-payload protection is exercised for real.
#
set -euo pipefail

DEST="${1:?usage: build-fixture-dmg.sh <destination-dir>}"
HERE="$(cd "$(dirname "$0")" && pwd)"

rm -rf "$DEST"
mkdir -p "$DEST"

SRC="$DEST/expanded"
mkdir -p "$SRC"
for m in vpn ui umbrella dart nvm common; do
  mkdir -p "$SRC/${m}_module.pkg"
  printf 'synthetic payload for %s\n' "$m" > "$SRC/${m}_module.pkg/Payload"
  printf '%s\n' "<pkg-info identifier=\"com.example.$m\" version=\"1.0\" install-location=\"/\"/>" \
    > "$SRC/${m}_module.pkg/PackageInfo"
done
cp "$HERE/../fixtures/Distribution.xml" "$SRC/Distribution"

STAGE="$DEST/stage"
mkdir -p "$STAGE"
pkgutil --flatten "$SRC" "$STAGE/Example Secure Client.pkg"

hdiutil create -quiet -srcfolder "$STAGE" -volname "Example Secure Client" \
  -format UDZO "$DEST/Example Secure Client-9.9.9.9.dmg"

printf '%s\n' '{"organizationId":"1234567","fingerprint":"abcdef","userId":"7654321"}' \
  > "$DEST/OrgInfo.json"

echo "fixture DMG built: $DEST/Example Secure Client-9.9.9.9.dmg"
