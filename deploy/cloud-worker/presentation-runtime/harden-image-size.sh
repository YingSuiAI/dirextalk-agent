#!/bin/sh
set -eu

types=node_modules/image-size/dist/types/index.js
detector=node_modules/image-size/dist/detector.js
[ -f "$types" ] && [ -f "$detector" ] || {
    echo "pinned image-size layout changed" >&2
    exit 66
}
[ "$(node -p "require('./node_modules/image-size/package.json').version")" = 1.2.1 ] || {
    echo "pinned image-size version changed" >&2
    exit 66
}

# image-size 1.2.1 has published denial-of-service advisories in the ICNS,
# HEIF, and JXL parsers. PptxGenJS only needs the qualified PNG/JPEG/GIF/SVG
# surface here, so remove the vulnerable parsers from both dispatch tables.
sed -i \
    -e '/require("\.\/heif")/d' \
    -e '/require("\.\/icns")/d' \
    -e '/require("\.\/jxl")/d' \
    -e '/require("\.\/jxl-stream")/d' \
    -e '/^[[:space:]]*heif:/d' \
    -e '/^[[:space:]]*icns:/d' \
    -e '/^[[:space:]]*jxl:/d' \
    -e "/^[[:space:]]*'jxl-stream':/d" \
    "$types"
sed -i -e "/0x69: 'icns'/d" "$detector"

if grep -Eq 'heif|icns|jxl' "$types" || grep -Eq "0x69: 'icns'" "$detector"; then
    echo "vulnerable image-size parsers remain enabled" >&2
    exit 66
fi

node - <<'NODE'
const { imageSize } = require('image-size');
const png = Buffer.from('89504e470d0a1a0a0000000d49484452000000010000000108060000001f15c4890000000d49444154789c6360000000020001e221bc330000000049454e44ae426082', 'hex');
const size = imageSize(png);
if (size.width !== 1 || size.height !== 1 || size.type !== 'png') process.exit(1);
for (const magic of ['69636e7300000008', '000000186674797061766966', '0000000c4a584c20']) {
  try {
    imageSize(Buffer.from(magic, 'hex'));
    process.exit(1);
  } catch (_) {
    // Disabled formats must fail closed without entering their parsers.
  }
}
NODE
