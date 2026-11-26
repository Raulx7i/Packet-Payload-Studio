# NDJSON Sidecar IPC Protocol (`app/rpc.py`)

Packet Payload Studio communicates between the Rust/Tauri desktop shell and the bundled Python engine over `stdin`/`stdout` using newline-delimited JSON (`NDJSON`).

## Request Envelope
```json
{ "id": "req-1", "method": "convert_and_transform", "params": { "input_text": "...", "in_format": "UTF-8", "out_format": "Hex Dump", "steps": [] } }
```

## Response Envelope
```json
{ "id": "req-1", "result": { "output_text": "..." }, "error": null }
```

## Supported Methods
- `ping` — Health check and Python engine module status.
- `list_capabilities` — Returns supported input/output formats and categorized pipeline operations.
- `convert_and_transform` — Decodes input format (with optional `peer` filter or `file_path`), runs chained operations, and encodes output format.
- `analyze_payload` — Computes byte length, Shannon entropy, printable ratio, protocol detection, MD5/SHA-1/SHA-256 digests, and Hex/ASCII previews.
- `list_pcap_streams` — Lists reconstructed TCP/UDP streams from a local `.pcap`/`.pcapng` path.
- `extract_pcap_stream` — Extracts a specific stream payload from a `.pcap`/`.pcapng` path.
- `list_example_recipes` — Loads bundled JSON recipes from `examples/`.
