import React, { useState } from "react";
import { FolderOpen, ArrowUpRight, Network } from "lucide-react";
import { open } from "@tauri-apps/plugin-dialog";
import { PcapStreamItem, rpcCall } from "../lib/ipc";

interface Props { onSendToConvert: (payload: string, format: string) => void; }

export const CaptureWorkspace: React.FC<Props> = ({ onSendToConvert }) => {
  const [pcapPath, setPcapPath] = useState("");
  const [streams, setStreams] = useState<PcapStreamItem[]>([]);
  const [selectedIdx, setSelectedIdx] = useState<number | null>(null);
  const [previewText, setPreviewText] = useState("");
  const [error, setError] = useState<string | null>(null);

  const openPcap = async () => {
    setError(null);
    try {
      const selected = await open({ multiple: false, filters: [{ name: "Packet Captures", extensions: ["pcap", "pcapng", "cap"] }] });
      if (typeof selected === "string") {
        setPcapPath(selected);
        const res = await rpcCall<{ streams: PcapStreamItem[] }>("list_pcap_streams", { pcap_path: selected });
        setStreams(res.streams); setSelectedIdx(null); setPreviewText("");
      }
    } catch (err) { setError(err instanceof Error ? err.message : String(err)); }
  };

  const selectStream = async (s: PcapStreamItem) => {
    setSelectedIdx(s.index); setError(null);
    try {
      const res = await rpcCall<{ payload_text: string }>("extract_pcap_stream", {
        pcap_path: pcapPath, stream_key: s.key, stream_index: s.index, out_format: "UTF-8"
      });
      setPreviewText(res.payload_text);
    } catch (err) { setError(err instanceof Error ? err.message : String(err)); }
  };

  return (
    <div className="flex h-full flex-col gap-3 p-3">
      <div className="flex items-center justify-between rounded-lg border border-borderSubtle bg-surface px-3 py-2">
        <div className="flex items-center gap-2 truncate text-xs">
          <Network className="h-4 w-4 shrink-0 text-accent" />
          <span className="truncate font-mono text-textSecondary">{pcapPath || "No .pcap / .pcapng capture loaded"}</span>
        </div>
        <button onClick={openPcap} className="flex shrink-0 items-center gap-1.5 rounded bg-accent px-3 py-1 text-xs font-semibold text-slate-950 hover:opacity-90">
          <FolderOpen className="h-3.5 w-3.5" /><span>Open PCAP</span>
        </button>
      </div>
      {error && <div className="rounded border border-red-500/40 bg-red-500/10 p-2.5 text-xs text-red-300">{error}</div>}
      <div className="grid flex-1 grid-cols-1 gap-3 lg:grid-cols-12 overflow-hidden">
        <section className="flex flex-col rounded-lg border border-borderSubtle bg-surface lg:col-span-5 overflow-hidden">
          <div className="border-b border-borderSubtle bg-elevated/60 px-3 py-2 text-[11px] font-semibold uppercase tracking-wider text-textSecondary">Reconstructed Flows ({streams.length})</div>
          <div className="flex-1 divide-y divide-borderSubtle overflow-y-auto">
            {streams.length === 0 ? <div className="p-6 text-center text-xs text-textSecondary">Open a PCAP or PCAPNG file to list directional TCP/UDP streams.</div> : streams.map((s) => (
              <button key={s.index} onClick={() => selectStream(s)} className={`w-full px-3 py-2.5 text-left font-mono text-xs ${selectedIdx === s.index ? "bg-accentMuted text-accent" : "text-textPrimary hover:bg-elevated"}`}>{s.summary}</button>
            ))}
          </div>
        </section>
        <section className="flex flex-col rounded-lg border border-borderSubtle bg-surface lg:col-span-7 overflow-hidden">
          <div className="flex items-center justify-between border-b border-borderSubtle bg-elevated/60 px-3 py-2">
            <span className="text-[11px] font-semibold uppercase tracking-wider text-textSecondary">Stream Payload Preview</span>
            <button disabled={!previewText} onClick={() => onSendToConvert(previewText, "UTF-8")} className="flex items-center gap-1 rounded border border-accent/50 bg-accentMuted px-2.5 py-1 text-xs font-medium text-accent hover:bg-accent hover:text-slate-950 disabled:opacity-40">
              <span>Send to Convert</span><ArrowUpRight className="h-3.5 w-3.5" />
            </button>
          </div>
          <pre className="flex-1 overflow-auto p-3 font-mono text-xs leading-relaxed">{previewText || "Select a stream on the left to inspect its reassembled payload."}</pre>
        </section>
      </div>
    </div>
  );
};
