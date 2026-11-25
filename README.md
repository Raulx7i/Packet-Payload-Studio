# Packet Payload Studio

A zero-dependency Python network payload analysis, packet stream reconstruction, and CyberChef-style transformation workbench built with Tkinter and the Nord palette.

![Packet Payload Studio Preview](preview.png)

## Features

- **Resizable 3-Pane Workbench:** Adjustable **Input**, collapsible **Transformation Pipeline**, and **Output** panes with **Nord Frost (Dark)** and **Nord Snow Storm (Light)** themes, a live **60-100% Window Transparency** slider (`Settings`), and persistent workspace preferences (`~/.packet_payload_studio.json`).
- **Hub-and-Spoke Format Converter:** Convert between **C Array** (with Wireshark `peer0` / `peer1` stream filtering, comment stripping, decimal/char/hex literals), **Hex Dump** (`hexdump -C`, `xxd`, and continuous hex), **YAML** (including Wireshark multi-line `!!binary |` blocks), **ASCII**, **UTF-8**, **EBCDIC (`cp037`)**, and **Raw** bytes.
- **CyberChef-Style Transformation Pipeline:** Chain, reorder, toggle (`On/Off`), inspect intermediate steps, step backward/forward (`<` / `>`) through recipe history, and save/load versioned `.json` recipes.
  - **Encodings & Web:** Base16, Base32, Base58, Base62, Base64 (Standard & URL-safe), ASCII85 (Base85), URL & Double-URL encoding/decoding (byte-exact for `0x80-0xFF`), HTML entities, Quoted-Printable, Unicode escape decoding, and JSON beautification.
  - **Compression & HTTP:** Auto-detection, **HTTP Extract Body** (headers + `Transfer-Encoding: chunked` + gzip/deflate), GZIP (including multi-member & truncated streams), ZLIB, Raw DEFLATE, BZIP2, and LZMA/XZ — all enforced with a **10 MB decompression-bomb ceiling**.
  - **Cryptography & Digests:** CRC32, Adler-32, MD5, SHA-1, SHA-256, SHA-384, SHA-512, SHA3-256, BLAKE2b, BLAKE2s, HMAC-SHA256/512, ROT13, and single/multi-byte XOR.
- **PCAP & PCAPNG Stream Reassembly:** Extracts directional IPv4/IPv6 (and 802.1Q/QinQ VLAN-tagged) TCP and UDP flows from Ethernet, Linux Cooked (`SLL`), and Loopback captures using magic-byte detection, ordering TCP segments by sequence number with wraparound handling and retransmission deduplication.
- **Protocol & Entropy Inspector:** Automatically detects HTTP/1.x, TLS records, GZIP/BZIP2/XZ/ZLIB streams, JSON, and common binary headers with length-normalized Shannon entropy diagnostics.
- **100% Local & Private:** All packet parsing, decompression, and transformations run locally offline with zero external network calls or third-party dependencies.

## Project Structure

```text
Packet-Payload-Studio/
├── main.py                       # Application entry point
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
```

## Known Limitations

- **IP Fragmentation:** Fragmented IPv4 datagrams (`frag_offset != 0`) are skipped rather than reassembled at the IP layer.
- **TLS Decryption:** TLS record headers are identified, but encrypted application payloads are not decrypted.
- **Large File Display Cap:** Files larger than 1 MB are truncated in the text editor preview for UI responsiveness while preserving the full byte buffer when saving to disk.

## License

MIT License — see [LICENSE](LICENSE).

## Requirements

- **Python 3.9+** with standard library `tkinter` enabled.

## Quick Start

```bash
git clone [https://github.com/Raulx7i/Packet-Payload-Studio.git](https://github.com/Raulx7i/Packet-Payload-Studio.git)
cd Packet-Payload-Studio
python3 main.py
```

## Running Tests

```bash
python3 -m unittest discover -s tests -v
```

## Example Recipe (`recipes/http_gzip_json.json`)

```json
{
  "version": 2,
  "steps": [
    { "op_id": "http_extract_body", "param": "", "enabled": true },
    { "op_id": "json_beautify", "param": "", "enabled": true }
  ]
}
```

## Project Structure

```text
Packet-Payload-Studio/
├── main.py                       # Application entry point
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
```

## Known Limitations

- **IP Fragmentation:** Fragmented IPv4 datagrams (`frag_offset != 0`) are skipped rather than reassembled at the IP layer.
- **TLS Decryption:** TLS record headers are identified, but encrypted application payloads are not decrypted.
- **Large File Display Cap:** Files larger than 1 MB are truncated in the text editor preview for UI responsiveness while preserving the full byte buffer when saving to disk.

## License

MIT License — see [LICENSE](LICENSE).
