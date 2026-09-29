#!/bin/bash
# ============================================================
# Vantic Breach - macOS build script (lives in app/, one level
# above the platform folders). Builds ONE edition from project
# source and ad-hoc signs it:
#   app/Mac app/Vantic Breach CLI.app   double-click -> Terminal menu
#
#   ./build_mac.sh          build + self-sign
#   ./build_mac.sh --sign   only re-sign an existing bundle
#
# Self-signing on macOS = ad-hoc codesign ("codesign -s -"). No developer
# account needed. Apps built locally are not Gatekeeper-quarantined; a copy
# that was downloaded instead needs: xattr -dr com.apple.quarantine <app>
# ============================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
APP="$SCRIPT_DIR/Mac app/Vantic Breach CLI.app"

sign() {
    # Desktop folders under iCloud sync can re-attach xattrs between the
    # strip and the signing step - so verify and retry a few times.
    local i
    for i in 1 2 3; do
        echo "[*] Stripping Finder metadata / resource forks: $1"
        find "$1" -name '.DS_Store' -delete 2>/dev/null || true
        xattr -cr "$1" 2>/dev/null || true
        echo "[*] Ad-hoc signing: $1"
        if codesign --force --deep -s - "$1" 2>/dev/null && \
           codesign --verify "$1" 2>/dev/null; then
            echo "[+] Signature verified on attempt $i"
            return 0
        fi
        echo "[!] Sign/verify failed (attempt $i) - retrying after strip"
        sleep 1
    done
    echo "[!] WARNING: signature did not verify; run: xattr -cr '$1' && codesign --force --deep -s - '$1'"
    return 1
}

if [[ "$1" == "--sign" ]]; then
    sign "$APP"
    echo "[+] Re-signed."
    exit 0
fi

echo "[*] Source: $ROOT"
echo "[*] Output: $APP"

MACOS="$APP/Contents/MacOS"
rm -rf "$APP"
mkdir -p "$MACOS" "$APP/Contents/Resources"

cp "$ROOT/vantic.py" "$MACOS/"
rsync -a --exclude='__pycache__' "$ROOT/vantic/" "$MACOS/vantic/"
mkdir -p "$MACOS/wordlists"
cp "$ROOT"/wordlists/*.txt "$MACOS/wordlists/" 2>/dev/null || true

cat > "$APP/Contents/Info.plist" << 'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleExecutable</key>
    <string>launcher</string>
    <key>CFBundleIdentifier</key>
    <string>com.vantic.breach</string>
    <key>CFBundleName</key>
    <string>Vantic Breach</string>
    <key>CFBundleDisplayName</key>
    <string>Vantic Breach</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
    <key>CFBundleShortVersionString</key>
    <string>3.0.0</string>
    <key>CFBundleVersion</key>
    <string>5</string>
    <key>LSMinimumSystemVersion</key>
    <string>10.15</string>
    <key>NSHighResolutionCapable</key>
    <true/>
    <key>NSHumanReadableCopyright</key>
    <string>Every wall has a way in. © Vantic</string>
</dict>
</plist>
PLIST

cat > "$MACOS/launcher" << 'LAUNCH'
#!/bin/bash
# Opens the toolkit in Terminal at a size that fits the banner, tables
# and the two-level menu (>= 110 cols x 36 rows for 11pt monospace).
# Terminal.app ignores the in-app XTWINOPS resize, so bounds are set here;
# the app itself keeps growing the window if the user shrinks it later
# (auto_size_terminal in vantic/utils).
DIR="$(cd "$(dirname "$0")" && pwd)"
osascript > /dev/null 2>&1 << OSA
tell application "Terminal" to activate
tell application "Terminal"
    do script "PYTHONDONTWRITEBYTECODE=1 python3 '$DIR/vantic.py'"
    set bounds of front window to {30, 50, 860, 720}
end tell
OSA
exit 0
LAUNCH
chmod +x "$MACOS/launcher"

sign "$APP"

codesign -dv "$APP" 2>&1 | grep -E "Identifier|CodeDirectory" || true
echo "[+] Built: $APP"