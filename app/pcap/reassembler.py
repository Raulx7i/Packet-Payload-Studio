from __future__ import annotations

from dataclasses import dataclass, field
from functools import cmp_to_key
import ipaddress
import struct

IPV6_EXT_HEADERS = {0, 43, 44, 50, 51, 60, 135, 139, 140}


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
            self.retransmissions = 0
            return b""

        def _seq_diff(a: int, b: int) -> int:
            return ((a - b + 0x80000000) & 0xFFFFFFFF) - 0x80000000

        ordered = sorted(self.segments, key=cmp_to_key(lambda x, y: _seq_diff(x[0], y[0])))
        base_seq = ordered[0][0]
        out = bytearray()
        cursor = None
        retrans = 0
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
                overlap = cursor - rel_seq
                out.extend(payload[overlap:])
                cursor += len(payload) - overlap
            else:
                retrans += 1
        self.retransmissions = retrans
        return bytes(out)


def _iter_frames(raw: bytes):
    """Yield (timestamp_float, link_type, frame_bytes) from classic .pcap or .pcapng."""
    if len(raw) < 24:
        raise ValueError("File too small to be a valid PCAP/PCAPNG capture.")
    magic = struct.unpack("<I", raw[:4])[0]

    # PCAPNG Section Header Block (0x0A0D0D0A)
    if magic == 0x0A0D0D0A:
        bom = struct.unpack("<I", raw[8:12])[0]
        endian = "<" if bom == 0x1A2B3C4D else ">"
        pos = 0
        n = len(raw)
        iface_links: list[int] = []
        while pos + 12 <= n:
            btype, blen = struct.unpack(f"{endian}II", raw[pos:pos + 8])
            if blen < 12 or pos + blen > n:
                break
            if btype == 0x00000001 and blen >= 16:  # Interface Description Block
                link_type = struct.unpack(f"{endian}H", raw[pos + 8:pos + 10])[0]
                iface_links.append(link_type)
            elif btype == 0x00000006 and blen >= 32:  # Enhanced Packet Block
                iface_id, ts_hi, ts_lo, cap_len, _orig_len = struct.unpack(f"{endian}IIIII", raw[pos + 8:pos + 28])
                ts = ((ts_hi << 32) | ts_lo) / 1_000_000.0
                lt = iface_links[iface_id] if iface_id < len(iface_links) else 1
                yield ts, lt, raw[pos + 28:pos + 28 + cap_len]
            elif btype == 0x00000003 and blen >= 16:  # Simple Packet Block
                lt = iface_links[0] if iface_links else 1
                yield 0.0, lt, raw[pos + 12:pos + blen - 4]
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
    if network not in (0, 1, 113):
        raise ValueError(f"Unsupported link-layer type {network} (supported: Ethernet=1, Loopback=0, Linux SLL=113).")

    offset = 24
    while offset + 16 <= len(raw):
        ts_sec, ts_sub, incl_len, _orig_len = struct.unpack(f"{endian}IIII", raw[offset:offset + 16])
        offset += 16
        pkt = raw[offset:offset + incl_len]
        offset += incl_len
        yield ts_sec + (ts_sub / ts_div), network, pkt


def _strip_l2(pkt: bytes, link_type: int) -> tuple[int, int] | None:
    """Return (eth_type, ip_start_offset) for Ethernet (1), Loopback (0), or Linux SLL (113)."""
    if link_type == 1:  # Ethernet
        if len(pkt) < 14:
            return None
        eth_type = struct.unpack("!H", pkt[12:14])[0]
        ip_start = 14
        while eth_type in (0x8100, 0x88A8) and len(pkt) >= ip_start + 4:
            eth_type = struct.unpack("!H", pkt[ip_start + 2:ip_start + 4])[0]
            ip_start += 4
        return eth_type, ip_start
    if link_type == 113:  # Linux cooked capture v1 (SLL)
        if len(pkt) < 16:
            return None
        eth_type = struct.unpack("!H", pkt[14:16])[0]
        return eth_type, 16
    if link_type == 0:  # BSD/macOS Null Loopback
        if len(pkt) < 4:
            return None
        family = struct.unpack("<I", pkt[:4])[0]
        if family > 0xFFFF:
            family = struct.unpack("!I", pkt[:4])[0]
        return (0x0800 if family == 2 else 0x86DD), 4
    return None


def parse_capture_flows(raw: bytes) -> dict[str, FlowStream]:
    """Parse .pcap/.pcapng into sequence-reconstructed directional TCP & UDP flows."""
    flows: dict[str, FlowStream] = {}
    conn_epoch: dict[str, int] = {}

    for ts, link_type, pkt in _iter_frames(raw):
        l2 = _strip_l2(pkt, link_type)
        if not l2:
            continue
        eth_type, ip_start = l2

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
            # Walk IPv6 extension headers
            while proto in IPV6_EXT_HEADERS and l4_start + 2 <= ip_end:
                next_hdr = pkt[l4_start]
                ext_len = (pkt[l4_start + 1] + 1) * 8
                l4_start += ext_len
                proto = next_hdr
        else:
            continue

        if proto == 6 and ip_end >= l4_start + 20:
            sport, dport, seq = struct.unpack("!HHI", pkt[l4_start:l4_start + 8])
            flags = pkt[l4_start + 13]
            tcp_hdr_len = ((pkt[l4_start + 12] >> 4) & 0x0F) * 4
            payload = pkt[l4_start + tcp_hdr_len:ip_end] if ip_end > l4_start + tcp_hdr_len else b""
            base_tuple = f"TCP {src_ip}:{sport} -> {dst_ip}:{dport}"
            # Split reused 4-tuples when a fresh SYN arrives
            if (flags & 0x02) and base_tuple in conn_epoch and flows.get(f"{base_tuple}#{conn_epoch[base_tuple]}"):
                if flows[f"{base_tuple}#{conn_epoch[base_tuple]}"].segments:
                    conn_epoch[base_tuple] += 1
            ep = conn_epoch.setdefault(base_tuple, 1)
            key = base_tuple if ep == 1 else f"{base_tuple} (conn #{ep})"
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

    active = {k: v for k, v in flows.items() if (v.segments or v.udp_chunks)}
    if not active:
        raise ValueError("No IPv4/IPv6 TCP or UDP application payloads found in capture.")
    return active
