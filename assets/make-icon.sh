#!/bin/bash
# Renders assets/icon.svg to assets/icon.png (512x512) reproducibly.
# Uses rsvg-convert when available, otherwise ImageMagick.
set -euo pipefail
cd "$(dirname "$0")"

if command -v rsvg-convert >/dev/null 2>&1; then
  rsvg-convert -w 512 -h 512 icon.svg -o icon.png
elif command -v magick >/dev/null 2>&1; then
  magick -background none icon.svg -resize 512x512 icon.png
elif command -v convert >/dev/null 2>&1; then
  convert -background none icon.svg -resize 512x512 icon.png
else
  echo "ERROR: need rsvg-convert or ImageMagick to render the icon." >&2
  exit 1
fi
echo "Wrote $(pwd)/icon.png"
