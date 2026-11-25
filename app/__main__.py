import argparse
import sys
from pathlib import Path

from app.core.pipeline import PipelineStepError, TransformationPipeline
from app.formats.converter import ConversionEngine
from app.pcap.reassembler import parse_capture_flows


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ppstudio",
        description="Packet Payload Studio — GUI workbench & headless network payload transformation CLI.",
    )
    source = parser.add_mutually_exclusive_group()
    source.add_argument("--pcap", type=Path, help="Path to a .pcap or .pcapng capture file.")
    source.add_argument(
        "--input", "-i", type=Path, help="Path to an input payload file (use '-' for stdin)."
    )
    parser.add_argument(
        "--list-streams",
        action="store_true",
        help="List all reconstructed TCP/UDP flow IDs in --pcap and exit.",
    )
    parser.add_argument(
        "--stream",
        "-s",
        type=str,
        default=None,
        help="Flow ID (or substring match) to extract from --pcap. Defaults to the first flow.",
    )
    parser.add_argument(
        "--in-format",
        type=str,
        default="Auto",
        help="Input format for --input: Auto, Raw, Hex Dump, C Array, YAML, ASCII, UTF-8, EBCDIC.",
    )
    parser.add_argument(
        "--peer",
        type=str,
        default="All Streams",
        help="C Array peer filter (All Streams, peer0, peer1).",
    )
    parser.add_argument(
        "--recipe",
        "-r",
        type=Path,
        default=None,
        help="Path to a Packet Payload Studio JSON recipe file.",
    )
    parser.add_argument(
        "--out-format",
        type=str,
        default="Raw",
        help="Output format: Raw, Hex Dump, C Array, YAML, ASCII, UTF-8, EBCDIC.",
    )
    parser.add_argument(
        "--out",
        "-o",
        type=Path,
        default=None,
        help="Output file path (writes raw bytes for Raw format, UTF-8 text otherwise). Defaults to stdout.",
    )
    return parser


def _select_flow(flows: dict, selector: str | None):
    if not flows:
        raise ValueError("No TCP or UDP flows found in capture file.")
    if not selector:
        first_key = next(iter(flows))
        return flows[first_key]
    if selector in flows:
        return flows[selector]
    matches = [flow for fid, flow in flows.items() if selector.lower() in fid.lower()]
    if len(matches) == 1:
        return matches[0]
    if len(matches) > 1:
        names = ", ".join(m.flow_id for m in matches)
        raise ValueError(f"Ambiguous --stream '{selector}'. Matches: {names}")
    raise ValueError(f"Stream '{selector}' not found. Use --list-streams to inspect available flows.")


def run_cli(argv: list[str]) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.list_streams and not args.pcap:
        parser.error("--list-streams requires --pcap")

    if args.pcap:
        raw_capture = args.pcap.read_bytes()
        flows = parse_capture_flows(raw_capture)
        if args.list_streams:
            for fid, flow in flows.items():
                payload_len = len(flow.reconstructed_bytes())
                print(
                    f"{fid} | packets={flow.packet_count} | retrans={flow.retransmissions} | bytes={payload_len}"
                )
            return 0
        flow = _select_flow(flows, args.stream)
        payload = flow.reconstructed_bytes()
    else:
        if str(args.input) == "-":
            raw_in = sys.stdin.buffer.read()
        else:
            raw_in = args.input.read_bytes()

        if args.in_format == "Raw":
            payload = raw_in
        else:
            text_in = raw_in.decode("utf-8", errors="replace")
            fmt = ConversionEngine.auto_detect(text_in) if args.in_format == "Auto" else args.in_format
            payload = ConversionEngine.to_bytes(text_in, fmt, peer_filter=args.peer)

    pipeline = TransformationPipeline()
    if args.recipe:
        pipeline.load_json(args.recipe.read_text(encoding="utf-8"))

    output_bytes, _logs, _snapshots = pipeline.execute(payload)

    if args.out_format == "Raw":
        if args.out:
            args.out.write_bytes(output_bytes)
        else:
            sys.stdout.buffer.write(output_bytes)
    else:
        formatted = ConversionEngine.from_bytes(output_bytes, args.out_format)
        if args.out:
            args.out.write_text(formatted, encoding="utf-8")
        else:
            sys.stdout.write(formatted)
            if not formatted.endswith("\n"):
                sys.stdout.write("\n")

    return 0


def main(argv: list[str] | None = None) -> int:
    args_list = sys.argv[1:] if argv is None else argv
    if not args_list:
        import tkinter as tk
        from app.ui.workbench import PacketWorkbenchApp

        root = tk.Tk()
        PacketWorkbenchApp(root)
        root.mainloop()
        return 0

    try:
        return run_cli(args_list)
    except (OSError, ValueError, PipelineStepError) as exc:
        print(f"ppstudio error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
