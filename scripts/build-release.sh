#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

VERSION=$(awk -F'"' '/^version *=/ { print $2; exit }' Cargo.toml)
APP_NAME="BonLogin"
BIN_NAME="bon-login"
OUT_DIR="target/release"
APP_DIR="${OUT_DIR}/${APP_NAME}.app"
CONTENTS_DIR="${APP_DIR}/Contents"
MACOS_DIR="${CONTENTS_DIR}/MacOS"
RESOURCES_DIR="${CONTENTS_DIR}/Resources"

echo "==> Building ${BIN_NAME} v${VERSION} (release)..."
cargo build --release

echo "==> Packaging ${APP_DIR}..."
rm -rf "${APP_DIR}"
mkdir -p "${MACOS_DIR}" "${RESOURCES_DIR}"
cp "${OUT_DIR}/${BIN_NAME}" "${MACOS_DIR}/${BIN_NAME}"
chmod +x "${MACOS_DIR}/${BIN_NAME}"

if command -v rsvg-convert >/dev/null 2>&1 && command -v iconutil >/dev/null 2>&1; then
  ICONSET_DIR="${OUT_DIR}/AppIcon.iconset"
  rm -rf "${ICONSET_DIR}"
  mkdir -p "${ICONSET_DIR}"
  for size in 16 32 128 256 512; do
    rsvg-convert -w "${size}" -h "${size}" assets/bonlogin-logo.svg -o "${ICONSET_DIR}/icon_${size}x${size}.png"
    size2x=$((size * 2))
    rsvg-convert -w "${size2x}" -h "${size2x}" assets/bonlogin-logo.svg -o "${ICONSET_DIR}/icon_${size}x${size}@2x.png"
  done
  iconutil -c icns "${ICONSET_DIR}" -o "${RESOURCES_DIR}/AppIcon.icns"
  rm -rf "${ICONSET_DIR}"
fi

cat > "${CONTENTS_DIR}/Info.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleName</key>
  <string>${APP_NAME}</string>
  <key>CFBundleDisplayName</key>
  <string>${APP_NAME}</string>
  <key>CFBundleIdentifier</key>
  <string>com.bonlogin.app</string>
  <key>CFBundleVersion</key>
  <string>${VERSION}</string>
  <key>CFBundleShortVersionString</key>
  <string>${VERSION}</string>
  <key>CFBundlePackageType</key>
  <string>APPL</string>
  <key>CFBundleExecutable</key>
  <string>${BIN_NAME}</string>
  <key>CFBundleIconFile</key>
  <string>AppIcon</string>
  <key>LSMinimumSystemVersion</key>
  <string>13.0</string>
  <key>NSHighResolutionCapable</key>
  <true/>
  <key>NSSupportsAutomaticGraphicsSwitching</key>
  <true/>
  <key>LSApplicationCategoryType</key>
  <string>public.app-category.developer-tools</string>
  <key>NSPrincipalClass</key>
  <string>NSApplication</string>
</dict>
</plist>
EOF

xattr -cr "${APP_DIR}" 2>/dev/null || true
codesign --force --deep --sign - "${APP_DIR}" >/dev/null

if [ -L "${HOME}/.local/bin/${BIN_NAME}" ] || [ -f "${HOME}/.local/bin/${BIN_NAME}" ]; then
  ln -sf "$(pwd)/${OUT_DIR}/${BIN_NAME}" "${HOME}/.local/bin/${BIN_NAME}"
fi
BIN_SIZE=$(du -sh "${OUT_DIR}/${BIN_NAME}" | awk '{print $1}')
APP_SIZE=$(du -sh "${APP_DIR}" | awk '{print $1}')
echo "==> Done!"
echo "    CLI Binary : ${OUT_DIR}/${BIN_NAME} (${BIN_SIZE})"
echo "    macOS App  : ${APP_DIR} (${APP_SIZE})"
