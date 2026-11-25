import ipaddress
import struct
from dataclasses import dataclass, field


@dataclass
class FlowStream:
    flow_id: str
    protocol: str
    src: str
    dst: str
    packet_count: int = 0
    retransmissions: int = 0
    segments: list = field(default_factory=list)  # list of (seq, timestamp, payload_bytes)
    udp_chunks: list = field(default_factory=list)

    def reconstructed_bytes(self) -> bytes:
        if self.protocol == "UDP":
            return b"".join(self.udp_chunks)
        if not self.segments:
            return b""
        from functools import cmp_to_key
        def _seq_diff(a: int, b: int) -> int:
            return ((a - b + 0x80000000) & 0xFFFFFFFF) - 0x80000000

        ordered = sorted(self.segments, key=cmp_to_key(lambda x, y: _seq_diff(x[0], y[0])))
        base_seq = ordered[0][0]
        out = bytearray()
        cursor = None
        for seq, _ts, payload in ordered:
            if not payload:
                continue
            rel_seq = _seq_diff(seq, base_seq)
            if cursor is None:
                out.extend(payload)
                cursor = rel_seq + len(payload)
            elif rel_seq >= cursor:
                out.extend(payload)
                cursor = rel_seq + len(payload)
            elif rel_seq + len(payload) > cursor:
                # Partial overlap (retransmission with new tail bytes)
                overlap = cursor - rel_seq
                out.extend(payload[overlap:])
                cursor += len(payload) - overlap
            else:
                self.retransmissions += 1
        return bytes(out)


def _iter_frames(raw: bytes):
    """Yield (timestamp_float, ethernet_frame_bytes) from classic .pcap or .pcapng."""
    if len(raw) < 24:
        raise ValueError("File too small to be a valid PCAP/PCAPNG capture.")
    magic = struct.unpack("<I", raw[:4])[0]

    # PCAPNG Section Header Block (0x0A0D0D0A)
    if magic == 0x0A0D0D0A:
        pos = 0
        n = len(raw)
        while pos + 12 <= n:
            btype, blen = struct.unpack("<II", raw[pos:pos + 8])
            if blen < 12 or pos + blen > n:
                break
            if btype == 0x00000006 and blen >= 32:  # Enhanced Packet Block (EPB)
                _iface, ts_hi, ts_lo, cap_len, _orig_len = struct.unpack("<IIIII", raw[pos + 8:pos + 28])
                ts = ((ts_hi << 32) | ts_lo) / 1_000_000.0
                yield ts, raw[pos + 28:pos + 28 + cap_len]
            pos += blen
        return

    # Classic PCAP
    if magic in (0xA1B2C3D4, 0xA1B23C4D):
        endian = "<"
        ts_div = 1_000_000_000.0 if magic == 0xA1B23C4D else 1_000_000.0
    elif magic in (0xD4C3B2A1, 0x4D3CB2A1):
        endian = ">"
        ts_div = 1_000_000_000.0 if magic == 0x4D3CB2A1 else 1_000_000.0
    else:
        raise ValueError("Unrecognized capture magic bytes (expected .pcap or .pcapng).")

    _vmaj, _vmin, _tz, _sig, _snap, network = struct.unpack(f"{endian}HHIIII", raw[4:24])
    if network != 1:
        raise ValueError(f"Unsupported link-layer type {network} (Ethernet DLT_EN10MB=1 required).")

    offset = 24
    while offset + 16 <= len(raw):
        ts_sec, ts_sub, incl_len, _orig_len = struct.unpack(f"{endian}IIII", raw[offset:offset + 16])
        offset += 16
        pkt = raw[offset:offset + incl_len]
        offset += incl_len
        yield ts_sec + (ts_sub / ts_div), pkt


def parse_capture_flows(raw: bytes) -> dict[str, FlowStream]:
    """Parse .pcap/.pcapng into sequence-reconstructed directional TCP & UDP flows."""
    flows: dict[str, FlowStream] = {}
    for ts, pkt in _iter_frames(raw):
        if len(pkt) < 14:
            continue
        eth_type = struct.unpack("!H", pkt[12:14])[0]
        ip_start = 14
        while eth_type in (0x8100, 0x88A8) and len(pkt) >= ip_start + 4:
            eth_type = struct.unpack("!H", pkt[ip_start + 2:ip_start + 4])[0]
            ip_start += 4

        if eth_type == 0x0800 and len(pkt) >= ip_start + 20:
            ihl = (pkt[ip_start] & 0x0F) * 4
            total_len = struct.unpack("!H", pkt[ip_start + 2:ip_start + 4])[0]
            frag_off = struct.unpack("!H", pkt[ip_start + 6:ip_start + 8])[0] & 0x1FFF
            if frag_off != 0:
                continue
            ip_end = min(len(pkt), ip_start + total_len) if total_len >= ihl else len(pkt)
            proto = pkt[ip_start + 9]
            src_ip = ".".join(str(b) for b in pkt[ip_start + 12:ip_start + 16])
            dst_ip = ".".join(str(b) for b in pkt[ip_start + 16:ip_start + 20])
            l4_start = ip_start + ihl
        elif eth_type == 0x86DD and len(pkt) >= ip_start + 40:
            payload_len = struct.unpack("!H", pkt[ip_start + 4:ip_start + 6])[0]
            ip_end = min(len(pkt), ip_start + 40 + payload_len)
            proto = pkt[ip_start + 6]
            src_ip = f"[{ipaddress.IPv6Address(pkt[ip_start + 8:ip_start + 24])}]"
            dst_ip = f"[{ipaddress.IPv6Address(pkt[ip_start + 24:ip_start + 40])}]"
            l4_start = ip_start + 40
        else:
            continue

        if proto == 6 and ip_end >= l4_start + 20:
            sport, dport, seq = struct.unpack("!HHI", pkt[l4_start:l4_start + 8])
            tcp_hdr_len = ((pkt[l4_start + 12] >> 4) & 0x0F) * 4
            payload = pkt[l4_start + tcp_hdr_len:ip_end] if ip_end > l4_start + tcp_hdr_len else b""
            key = f"TCP {src_ip}:{sport} -> {dst_ip}:{dport}"
            flow = flows.setdefault(key, FlowStream(key, "TCP", f"{src_ip}:{sport}", f"{dst_ip}:{dport}"))
            flow.packet_count += 1
            if payload:
                flow.segments.append((seq, ts, payload))
        elif proto == 17 and ip_end >= l4_start + 8:
            sport, dport = struct.unpack("!HH", pkt[l4_start:l4_start + 4])
            payload = pkt[l4_start + 8:ip_end]
            key = f"UDP {src_ip}:{sport} -> {dst_ip}:{dport}"
            flow = flows.setdefault(key, FlowStream(key, "UDP", f"{src_ip}:{sport}", f"{dst_ip}:{dport}"))
            flow.packet_count += 1
            if payload:
                flow.udp_chunks.append(payload)

    # Keep flows that carry application payload
    active = {k: v for k, v in flows.items() if (v.segments or v.udp_chunks)}
    if not active:
        raise ValueError("No IPv4/IPv6 TCP or UDP application payloads found in capture.")
    return active
