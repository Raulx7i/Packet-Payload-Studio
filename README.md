# Packet Payload Studio

A lightweight, CyberChef-inspired Python desktop GUI built with the Python standard library (`tkinter`) for converting and inspecting Wireshark packet streams across **C Array**, **Hex Dump**, **YAML**, **ASCII**, **UTF-8**, **EBCDIC**, and **Raw** binary formats.

![Packet Payload Studio Interface](assets/preview.png)

## Features

- **7-Format Hub-and-Spoke Engine:** Seamlessly decode and re-encode streams across **C Array**, **Hex Dump**, **YAML**, **ASCII**, **UTF-8**, **EBCDIC** (`cp037`, `cp500`, `cp1047`), and **Raw** bytes.
- **Nord Frost Frosted-Glass UI:** Equal-split two-pane layout styled with the low-glare **Nord Frost** dark slate palette and a real-time **Glass** opacity slider (`75%`–`100%`).
- **Dual Format Controls:** Switch formats instantly using either the dropdown menus or equal-width quick-select format tabs above both editors.
- **Auto-Detect Input:** Automatically identifies C Arrays, offset-prefixed Hex Dumps, YAML stream exports, or plain text upon pasting or loading a file.
- **Live Payload Inspector:** Real-time byte counter, SHA-256 digest preview, and **Shannon Entropy** score (`0.00`–`8.00`) to distinguish structured plaintext from encrypted or compressed traffic.
- **Built-in HTTP Gunzip & Zlib:** Detects Gzip (`1f 8b`) or Zlib headers in raw payloads or HTTP response bodies and decompresses them safely (with a 10 MB memory cap, HTTP chunked decoding, and partial recovery on truncated streams).
- **CyberChef-Style Data Transforms:** Apply Base64 encode/decode, URL encode/decode, and custom hex or ASCII key XOR operations directly on decoded payloads.
- **Client/Server Stream Splitter (`peer0` / `peer1`):** Isolate client requests (`peer0`) or server responses (`peer1`) from multi-packet Wireshark C Array exports.
- **Pure-Python `.pcap` Payload Extractor:** Load standard `.pcap` packet captures directly to extract IPv4/IPv6 (and VLAN-tagged) TCP/UDP application payloads in capture order with Ethernet padding stripped without third-party dependencies.
- **Live Output Search (`Cmd+F` / `Ctrl+F`):** Search converted output case-insensitively and highlight all matching strings or hex sequences in real time.

## Project Structure

```text
Packet-Payload-Studio/
├── main.py                  # Root entrypoint (run: python3 main.py)
├── code/
│   ├── __init__.py
│   ├── theme.py             # Nord Frost palette & typography constants
│   ├── engine.py            # 7-format hub-and-spoke engine, peer0/peer1 splitter, PCAP parser, XOR/Base64/URL/Gunzip transforms
│   └── app.py               # Modular Tkinter frosted-glass GUI with search, stream filter, and transform bar
├── assets/
│   └── preview.png
├── README.md
└── LICENSE
```

## Requirements & Dependencies

- **Python 3.8+** (zero third-party `pip` packages required)
- **Tcl/Tk 8.6+** (`tkinter`)

### macOS Setup (Important)

Apple's pre-installed system Python uses an outdated Tcl/Tk 8.5 framework that causes rendering and text-visibility bugs. Install Homebrew's modern `python-tk` package and ensure Homebrew is prioritized in your `PATH`:

```bash
brew install python-tk
echo 'export PATH="/opt/homebrew/bin:$PATH"' >> ~/.zshrc
source ~/.zshrc
```

Verify your active Python uses Tcl/Tk 8.6 or newer:

```bash
python3 -c "import tkinter; print(tkinter.TkVersion)"
```

### Linux (Debian / Ubuntu)

If `tkinter` is not bundled with your Python installation:

```bash
sudo apt update && sudo apt install python3-tk
```

### Windows

`tkinter` is included automatically with the official Python installer from [python.org](https://www.python.org/downloads/).

## Installation & Usage

1. **Clone the repository:**
   ```bash
   git clone [https://github.com/Raulx7i/Packet-Payload-Studio.git](https://github.com/Raulx7i/Packet-Payload-Studio.git)
   cd Packet-Payload-Studio
   ```

2. **Launch the application:**
   ```bash
   python3 main.py
   ```

## License

Licensed under the MIT License — see [LICENSE](LICENSE).
