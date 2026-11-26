# Packet Payload Studio

A cross-platform network payload conversion, deep packet inspection, PCAP stream reassembly, and binary diffing workbench.

Packet Payload Studio ships as both:
1. **Standalone Desktop Application (Tauri 2 + React + TypeScript)** — Bundles a compiled Python engine sidecar (`ppstudio-backend`) so end users require **zero Python, Node, or pip installations**.
2. **Zero-Dependency Python CLI & Tk Workbench (`ppstudio`)** — Pure Python 3 standard-library engine preserved for headless automation and CI pipelines.

## Desktop Workspaces
- **Convert (`⌘/Ctrl + 1`)** — Bidirectional conversion across UTF-8, ASCII, Hex Dump, C Array (`peer0`/`peer1`), Base64, Raw, and EBCDIC with 38+ chained operations.
- **Analyze (`⌘/Ctrl + 2`)** — Payload size, Shannon entropy, printable ASCII ratio, protocol fingerprinting, MD5/SHA-1/SHA-256 digests, and Hex/ASCII preview.
- **Capture (`⌘/Ctrl + 3`)** — Native `.pcap` / `.pcapng` TCP & UDP flow reassembly with one-click handoff into Convert.
- **Recipes (`⌘/Ctrl + 4`)** — Load `version: 2` JSON transformation recipes directly into the active pipeline.
- **Compare (`⌘/Ctrl + 5`)** — Synchronized 16-byte Hex & ASCII diffing with one-click `peer0` vs `peer1` stream splitting.

## Building & Running Locally

### Desktop App (Development Mode)
    npm --prefix ui install
    npx --prefix ui tauri dev

### Standalone Desktop Bundle (Zero-Python End-User Installer)
    python3 -m venv .venv-build
    .venv-build/bin/pip install pyinstaller
    .venv-build/bin/pyinstaller --noconfirm --clean packaging/ppstudio-backend.spec
    TARGET_TRIPLE=$(rustc -vV | awk '/host:/ {print $2}')
    mkdir -p src-tauri/binaries
    cp dist/ppstudio-backend "src-tauri/binaries/ppstudio-backend-${TARGET_TRIPLE}"
    chmod +x "src-tauri/binaries/ppstudio-backend-${TARGET_TRIPLE}"
    npx --prefix ui tauri build

### Pure-Python Headless CLI & Tests
    python3 -m unittest discover -s tests -v
    python3 -m app --in-format "Hex Dump" --out-format "UTF-8" --input "48 65 6c 6c 6f"
