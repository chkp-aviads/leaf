#!/usr/bin/env sh
#
# Build the Apple xcframework, zip it for SwiftPM, and pin it in Package.swift.
#
#   ./scripts/package_spm.sh 0.2.0
#
# Produces target/apple/release/leaf.xcframework.zip and rewrites the version
# and checksum in Package.swift. Then attach the zip to a release with that tag:
#
#   gh release create 0.2.0 target/apple/release/leaf.xcframework.zip
#
# The zip is deliberately not committed -- it is a build artifact, pinned by
# checksum, exactly as GuardianWireGuard distributes GRDWireGuardKit.

set -e

version="$1"
if [ -z "$version" ]; then
    echo "usage: $0 <version>    e.g. $0 0.2.0" >&2
    exit 2
fi

root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"

# All three Apple slices: Picard's package declares macOS as well as iOS, so a
# missing macOS slice would break a macOS build of anything that links this.
./scripts/build_apple_xcframework.sh

xcframework="target/apple/release/leaf.xcframework"
zip="$xcframework.zip"

rm -f "$zip"
# ditto with these flags is what SwiftPM expects; a plain `zip` produces an
# archive whose checksum SwiftPM will reject.
ditto -c -k --sequesterRsrc --keepParent "$xcframework" "$zip"

checksum=$(swift package compute-checksum "$zip")

python3 - "$version" "$checksum" <<'PY'
import re, sys
version, checksum = sys.argv[1], sys.argv[2]
p = 'Package.swift'
s = open(p).read()
s = re.sub(r'let version = "[^"]*"', f'let version = "{version}"', s, count=1)
s = re.sub(r'let checksum = "[^"]*"', f'let checksum = "{checksum}"', s, count=1)
open(p, 'w').write(s)
PY

echo
echo "xcframework : $xcframework"
echo "zip         : $zip"
echo "version     : $version"
echo "checksum    : $checksum"
echo
echo "Package.swift updated. To publish:"
echo "  git commit -am \"Release $version\" && git tag $version && git push --tags"
echo "  gh release create $version \"$zip\" --title $version"
