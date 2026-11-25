<div align="center">

# Packet Payload Studio

**Zero-dependency Python network payload analysis, packet stream reconstruction, and CyberChef-style transformation workbench.**

[![Python](https://img.shields.io/badge/Python-3.9%2B%20(3.11--3.13%20CI)-88C0D0?style=flat-square&logo=python&logoColor=2E3440&labelColor=2E3440)](https://www.python.org/)
[![Dependencies](https://img.shields.io/badge/Dependencies-Zero%20(Stdlib%20Only)-A3BE8C?style=flat-square&labelColor=2E3440)](#requirements)
[![Theme](https://img.shields.io/badge/Palette-Nord%20Frost%20%26%20Snow%20Storm-81A1C1?style=flat-square&labelColor=2E3440)](#features)
[![License](https://img.shields.io/badge/License-MIT-EBCB8B?style=flat-square&labelColor=2E3440)](#license)

![Packet Payload Studio Preview](assets/preview.png)

</div>

---

## Features

| Capability | Details |
| :--- | :--- |
| **Nord 3-Pane Workbench** | Resizable **Input**, collapsible **Transformation Pipeline**, and **Output** panes with **Nord Frost (Dark)** and **Nord Snow Storm (Light)** themes, a live **60–100% Window Transparency** slider (`90%` default), and persistent preferences (`~/.packet_payload_studio.json`). |
| **Hub-and-Spoke Formats** | Bidirectional conversion across **C Array** (Wireshark `peer0` / `peer1` filtering, comment stripping, hex/decimal/char literals), **Hex Dump** (`hexdump -C`, `xxd`, continuous hex), **YAML** (multi-line `!!binary \|`), **ASCII**, **UTF-8**, **EBCDIC (`cp037`)**, and **Raw** bytes. |
| **Transformation Pipeline** | CyberChef-style operation chaining with `On/Off` toggles, step reordering, click-to-inspect intermediate snapshots, browser-style `<` / `>` undo/redo history, and versioned `.json` recipes (`version: 2`). |
| **Encodings & Web** | Base16, Base32, Base58, Base62, Base64 (Standard & URL-safe), ASCII85 (Base85), byte-exact URL & Double-URL decoding (`0x80–0xFF`), HTML entities, Quoted-Printable, Unicode escape decoding, and JSON beautification. |
| **Compression & HTTP** | Auto-detection, **HTTP Extract Body** (headers + `Transfer-Encoding: chunked` + gzip/deflate), GZIP (multi-member & truncated recovery), ZLIB, Raw DEFLATE, BZIP2, and LZMA/XZ with a **10 MB decompression-bomb ceiling**. |
| **Cryptography & Digests** | CRC32, Adler-32, MD5, SHA-1, SHA-256, SHA-384, SHA-512, SHA3-256, BLAKE2b, BLAKE2s, HMAC-SHA256/512, ROT13, and single/multi-byte XOR. |
| **PCAP / PCAPNG Streams** | Extracts directional IPv4/IPv6 (including 802.1Q/QinQ VLAN-tagged) TCP & UDP flows from Ethernet, Linux Cooked (`SLL`), and Loopback captures with sequence-number ordering, wraparound handling, and retransmission deduplication. |
| **Protocol Inspector** | Magic-byte detection for HTTP/1.x, TLS records, compressed streams, JSON, and binary headers paired with length-normalized Shannon entropy diagnostics. |
| **100% Local & Private** | All packet parsing, decompression, and transformations execute offline on your machine with zero external network calls. |

---

## Requirements

- **Python 3.9+** (tested in CI on Python 3.11, 3.12, and 3.13) with standard library `tkinter` enabled.

---

## Quick Start

~~~bash
git clone https://github.com/Raulx7i/Packet-Payload-Studio.git
cd Packet-Payload-Studio
python3 main.py
~~~

### Headless CLI Mode

Run recipes and extract PCAP streams directly from the terminal without opening the GUI:

~~~bash
# List all reconstructed TCP/UDP streams in a capture
pip install .  # installs the `ppstudio` CLI command
ppstudio --pcap capture.pcap --list-streams

# Extract a specific stream, run a JSON recipe, and save the decoded output
ppstudio --pcap capture.pcap --stream "TCP 10.0.0.1:52314 -> 93.184.216.34:80" --recipe recipes/http_gzip_json.json --out body.json

# Convert and transform a Hex Dump or C Array file from disk or stdin
ppstudio --input dump.txt --in-format "Hex Dump" --recipe recipe.json --out-format "UTF-8"
~~~

### Running Tests

~~~bash
python3 -m unittest discover -s tests -v
~~~

---

> See [`examples/README.md`](examples/README.md) for ready-to-run `.pcap` captures, Wireshark C Arrays, and transformation recipes.

## Example Recipe (`recipes/http_gzip_json.json`)

~~~json
{
  "version": 2,
  "steps": [
    { "op_id": "http_extract_body", "param": "", "enabled": true },
    { "op_id": "json_beautify", "param": "", "enabled": true }
  ]
}
~~~

---

## Project Structure

~~~text
Packet-Payload-Studio/
├── main.py                       # Application entry point
├── assets/
│   └── preview.png               # Workbench UI screenshot
├── app/
│   ├── compression/engines.py    # Bounded GZIP/ZLIB/DEFLATE/BZ2/XZ & HTTP body extraction
│   ├── core/pipeline.py          # Versioned CyberChef-style transformation pipeline
│   ├── crypto/digests.py         # Cryptographic hashes, checksums & HMAC reports
│   ├── encoders/codecs.py        # Base16/32/58/62/64/85, URL, HTML, Unicode, XOR & JSON
│   ├── formats/converter.py      # 7-format hub-and-spoke parser & serializer
│   ├── pcap/reassembler.py       # PCAP/PCAPNG parser & sequence-ordered TCP stream reassembler
│   ├── protocols/inspector.py    # Magic-byte protocol identification & entropy analysis
│   └── ui/
│       ├── theme.py              # Nord Frost (Dark) & Nord Snow Storm (Light) palettes
│       └── workbench.py          # Resizable 3-pane Tkinter workbench & Settings dialog
├── tests/
│   └── test_workbench.py         # Unit & regression test suite
├── .github/workflows/tests.yml   # Automated CI test workflow
└── LICENSE                       # MIT License
~~~

---

## Known Limitations

- **IP Fragmentation:** Fragmented IPv4 datagrams (`frag_offset != 0`) are skipped rather than reassembled at the IP layer.
- **TLS Decryption:** TLS record headers are identified, but encrypted application payloads are not decrypted.
- **Large File Display Cap:** Files larger than 1 MB are truncated in the text editor preview for UI responsiveness while preserving the full byte buffer when saving to disk.

---

## License

MIT License — see [LICENSE](LICENSE) for full details.