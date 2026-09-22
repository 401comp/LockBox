#!/usr/bin/env bash
# LockBox build script.
#
# Creates a local venv (Homebrew python3.14), installs deps, runs the
# self-test, builds a py2app .app, verifies cross-Mac portability with
# otool -L, and packages a DMG.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
cd "$HERE"

VENV="$HERE/.venv"
PY="$VENV/bin/python"
APP_NAME="LockBox"
APP_BUNDLE="dist/$APP_NAME.app"
DMG_PATH="dist/${APP_NAME}.dmg"

# Find a usable non-conda Python 3.9+. Prefer python.org framework installer
# (always includes _tkinter), fall back to Homebrew if present, then PATH.
# Reject conda: its libffi/tcl/tk are @rpath-linked and py2app can't bundle
# them, so the built app crashes on launch (dlopen: Library not loaded:
# @rpath/libffi.8.dylib).
find_python() {
  local cand real
  for v in 3.14 3.13 3.12 3.11 3.10 3.9; do
    cand="/Library/Frameworks/Python.framework/Versions/$v/bin/python$v"
    [ -x "$cand" ] && echo "$cand" && return 0
  done
  for v in 3.14 3.13 3.12 3.11 3.10; do
    cand="/usr/local/opt/python@$v/bin/python$v"
    [ -x "$cand" ] && echo "$cand" && return 0
    cand="/opt/homebrew/opt/python@$v/bin/python$v"
    [ -x "$cand" ] && echo "$cand" && return 0
  done
  if command -v python3 >/dev/null 2>&1; then
    cand=$(command -v python3)
    real=$("$cand" -c 'import sys; print(sys.executable)' 2>/dev/null || echo "")
    if ! echo "$real" | grep -qiE 'conda|miniconda|anaconda'; then
      echo "$cand" && return 0
    fi
  fi
  return 1
}

BOOTSTRAP=$(find_python) || {
  echo "ERROR: no usable non-conda Python 3.9+ found." >&2
  echo "       Install python.org 3.12+ or Homebrew python@3.14." >&2
  exit 1
}
echo "==> Python: $BOOTSTRAP ($("$BOOTSTRAP" --version))"

# A venv built (or copied) from a different/stale interpreter is unusable —
# recreate it. Comparing versions alone doesn't catch a venv relocated from
# another directory (its activate script keeps the old absolute path and
# silently falls through PATH to whatever python3 is next, e.g. conda), so
# also check the venv's own recorded source directory.
if [[ -x "$PY" ]]; then
  VENV_VER=$("$PY" -c 'import sys; print("%d.%d" % sys.version_info[:2])' 2>/dev/null || echo none)
  SYS_VER=$("$BOOTSTRAP" -c 'import sys; print("%d.%d" % sys.version_info[:2])')
  VENV_HOME=$(grep '^command *=' "$VENV/pyvenv.cfg" 2>/dev/null || echo "")
  if [[ "$VENV_VER" != "$SYS_VER" ]] || ! echo "$VENV_HOME" | grep -qF "$VENV"; then
    echo "==> Recreating venv (stale or version mismatch: was $VENV_VER, need $SYS_VER)"
    rm -rf "$VENV"
  fi
fi

if [[ ! -x "$PY" ]]; then
  echo "==> Creating venv at $VENV"
  "$BOOTSTRAP" -m venv "$VENV"
fi

echo "==> Upgrading pip"
"$PY" -m pip install --quiet --upgrade pip

echo "==> Installing runtime deps"
# --only-binary forces a real prebuilt wheel. Without it, if pip's local
# cache or resolver ever falls back to building cryptography's Rust
# extension from source, it links against whatever OpenSSL happens to be
# on THIS machine (Homebrew's) instead of the vendored one official wheels
# ship — same @rpath leak class as the conda libffi problem above, just
# from a different toolchain. Seen 2026-08-31: a locally-built 2MB wheel
# in the pip cache (vs. ~8MB for the real universal2 wheel) silently linked
# to /usr/local/opt/openssl@3.
"$PY" -m pip install --quiet --only-binary=:all: 'cryptography>=42'

echo "==> Installing build deps"
"$PY" -m pip install --quiet 'py2app>=0.28' 'setuptools>=68'

echo "==> Checking for tkinter"
"$PY" -c 'import tkinter' || {
  echo "ERROR: this Python has no tkinter. On Homebrew: brew install python-tk@3.14" >&2
  exit 1
}

echo "==> Running self-test"
"$PY" lockbox.py --self-test

echo "==> Cleaning previous build/dist"
rm -rf build dist

echo "==> Building .app with py2app"
"$PY" setup.py py2app --quiet

if [[ ! -d "$APP_BUNDLE" ]]; then
  echo "!! py2app did not produce $APP_BUNDLE" >&2
  exit 1
fi

echo "==> Checking bundled Python for Homebrew leaks (otool -L)"
BUNDLED_PY="$APP_BUNDLE/Contents/MacOS/python"
if [[ -x "$BUNDLED_PY" ]]; then
  if otool -L "$BUNDLED_PY" | grep -E '/usr/local/|/opt/homebrew/' >/dev/null; then
    echo "!! Bundled python links to Homebrew paths — will not launch on clean Macs:" >&2
    otool -L "$BUNDLED_PY" | grep -E '/usr/local/|/opt/homebrew/' >&2
    exit 2
  fi
  echo "   bundled python: OK (no /usr/local or /opt/homebrew links)"
fi

# Scan .so files inside the bundle for the same leak.
LEAK=0
while IFS= read -r so; do
  if otool -L "$so" 2>/dev/null | grep -E '/usr/local/|/opt/homebrew/' >/dev/null; then
    echo "!! Homebrew link in $so:" >&2
    otool -L "$so" | grep -E '/usr/local/|/opt/homebrew/' >&2
    LEAK=1
  fi
done < <(find "$APP_BUNDLE" -type f \( -name '*.so' -o -name '*.dylib' \))

if [[ "$LEAK" -ne 0 ]]; then
  echo "!! Cross-Mac portability check failed." >&2
  exit 3
fi
echo "==> Portability check passed."

echo "==> Building DMG"
rm -f "$DMG_PATH"
STAGE=$(mktemp -d)
cp -R "$APP_BUNDLE" "$STAGE/"
ln -s /Applications "$STAGE/Applications"
hdiutil create -volname "$APP_NAME" -srcfolder "$STAGE" -ov -format UDZO "$DMG_PATH" >/dev/null
rm -rf "$STAGE"

echo "==> Building self-contained app ZIP"
APP_ZIP="dist/${APP_NAME}-1.0.0-macos.zip"
rm -f "$APP_ZIP"
ditto -c -k --sequesterRsrc --keepParent "$APP_BUNDLE" "$APP_ZIP"
unzip -t "$APP_ZIP" >/dev/null
echo "   $APP_ZIP"

echo "==> Building source zip"
SRC_ZIP="dist/${APP_NAME}-src.zip"
rm -f "$SRC_ZIP"
zip -q -r "$SRC_ZIP" \
  lockbox.py crypto_core.py setup.py build.sh README.md resources \
  -x "resources/*.png"
echo "   $SRC_ZIP"

echo ""
echo "Done."
echo "  App: $APP_BUNDLE"
echo "  DMG: $DMG_PATH"
echo "  ZIP: $APP_ZIP"
echo "  Src: $SRC_ZIP"
