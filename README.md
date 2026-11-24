# Stream Converter

A lightweight Python desktop GUI (built with standard library `tkinter`) for converting and inspecting Wireshark packet streams across **C Array**, **Hex Dump**, **YAML**, **ASCII**, **UTF-8**, **EBCDIC**, and **Raw** binary formats.

## Features

- **7-Format Hub-and-Spoke Engine:** Convert seamlessly between **C Array**, **Hex Dump**, **YAML**, **ASCII**, **UTF-8**, **EBCDIC** (`cp037`, `cp500`, `cp1047`), and **Raw** bytes.
- **Clickable Format Tabs:** Dedicated input and output format tab bars for instant one-click switching.
- **Auto-Detect Input:** Automatically detects C Arrays, offset-prefixed Hex Dumps, YAML stream exports, or plain text upon pasting.
- **Live Payload Inspector:** Real-time byte length, SHA-256 digest, and **Shannon Entropy** calculation (0.00–8.00) to distinguish plaintext from encrypted or compressed payloads.
- **Built-in HTTP Gunzip:** Detects Gzip magic bytes (`1f 8b`) and decompresses HTTP payloads in one click.

## Requirements

- **Python 3.8+** (uses Python standard library modules only; no third-party `pip` packages required)

## Usage

```bash
python3 packet_converter.py
```

*(On macOS, run `TK_SILENCE_DEPRECATION=1 python3 packet_converter.py` to suppress the system Tcl/Tk notice.)*

## License

Licensed under the MIT License — see [LICENSE](LICENSE).
