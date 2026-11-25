# Examples & Walkthroughs

Ready-to-run sample captures, Wireshark C arrays, encoded web payloads, and transformation recipes.

---

## 1. Extract & Decompress HTTP GZIP JSON from PCAP

List reconstructed TCP/UDP flows inside `sample.pcap`:
```bash
ppstudio --pcap examples/sample.pcap --list-streams
```

Extract the HTTP body, decompress GZIP, and pretty-print JSON:
```bash
ppstudio --pcap examples/sample.pcap --recipe examples/http_gzip_json.json --out-format UTF-8
```

---

## 2. Filter Wireshark C Array Streams (`peer0` vs `peer1`) & XOR Decode

`examples/wireshark_c_array.txt` contains both client (`peer0_0`) and server (`peer1_0`, XOR-encoded with `0x55`) arrays.

Decode only the server stream (`peer1`):
```bash
ppstudio --input examples/wireshark_c_array.txt --in-format "C Array" --peer peer1 --recipe examples/xor_decode.json --out-format UTF-8
```

Inspect the client stream (`peer0`) without running a recipe:
```bash
ppstudio --input examples/wireshark_c_array.txt --in-format "C Array" --peer peer0 --out-format ASCII
```

---

## 3. Multi-Layer Web Unescaping (Double URL + HTML Entities)

Decode `examples/double_url_html.txt` in one command:
```bash
ppstudio --input examples/double_url_html.txt --in-format UTF-8 --recipe examples/web_unescape.json --out-format UTF-8
```

---

## 4. Running in the Desktop GUI

1. Launch the workbench: `ppstudio` (or `python3 -m app`).
2. Click **Open...** in the **INPUT** pane and select any file in `examples/`.
3. Click **Load** in the **PIPELINE** pane and select the matching `.json` recipe.
4. Click any step in **ACTIVE STEPS** to inspect intermediate bytes before and after each transformation.
