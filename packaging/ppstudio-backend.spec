# -*- mode: python ; coding: utf-8 -*-
from pathlib import Path

ROOT = Path(SPECPATH).resolve().parent

a = Analysis(
    [str(ROOT / "app" / "rpc.py")],
    pathex=[str(ROOT)],
    binaries=[],
    datas=[(str(ROOT / "examples"), "examples")],
    hiddenimports=[
        "app.core.pipeline",
        "app.formats.converter",
        "app.pcap.reassembler",
        "app.protocols.inspector",
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        "tkinter", "_tkinter", "unittest", "test", "pydoc", "doctest",
        "pdb", "sqlite3", "ftplib", "imaplib", "poplib", "smtplib",
        "xmlrpc", "turtle", "turtledemo",
    ],
    noarchive=False,
    optimize=2,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="ppstudio-backend",
    debug=False,
    bootloader_ignore_signals=False,
    strip=True,
    upx=False,
    console=True,
)
