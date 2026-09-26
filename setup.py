"""py2app build config for LockBox."""

from setuptools import setup

APP = ["lockbox.py"]
DATA_FILES = []
OPTIONS = {
    "argv_emulation": False,
    "iconfile": "resources/lockbox.icns",
    "packages": ["cryptography", "cffi"],
    "includes": ["crypto_core", "applog", "_cffi_backend"],
    "plist": {
        "CFBundleName": "LockBox",
        "CFBundleDisplayName": "LockBox",
        "CFBundleIdentifier": "com.saltz.lockbox",
        "CFBundleShortVersionString": "1.1.0",
        "CFBundleVersion": "1.1.0",
        "CFBundleDocumentTypes": [{
            "CFBundleTypeName": "LockBox Vault",
            "CFBundleTypeExtensions": ["lockbox"],
            "CFBundleTypeRole": "Editor",
        "LSTypeIsPackage": True,
        }],
        "NSAppleEventsUsageDescription": "LockBox opens vault folders sent by Finder.",
        "NSHighResolutionCapable": True,
        "LSMinimumSystemVersion": "10.15",
        "NSHumanReadableCopyright": "© 2026",
    },
}

setup(
    app=APP,
    name="LockBox",
    data_files=DATA_FILES,
    options={"py2app": OPTIONS},
    setup_requires=["py2app"],
)
