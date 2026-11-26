import React, { useState, useEffect } from "react";
import { RefreshCw } from "lucide-react";
import { AnalyzeResult, rpcCall } from "../lib/ipc";

interface Props { inputText: string; inFormat: string; peerFilter: string; }

export const AnalyzeWorkspace: React.FC<Props> = ({ inputText, inFormat, peerFilter }) => {
  const [analysis, setAnalysis] = useState<AnalyzeResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  const runAnalysis = async () => {
    setError(null);
    try {
      const res = await rpcCall<AnalyzeResult>("analyze_payload", {
        input_text: inputText, in_format: inFormat, peer: inFormat === "C Array" ? peerFilter : "All Streams"
      });
      setAnalysis(res);
    } catch (err) { setError(err instanceof Error ? err.message : String(err)); }
  };

  useEffect(() => { runAnalysis(); }, [inputText, inFormat, peerFilter]);

  return (
    <div className="flex h-full flex-col gap-3 overflow-y-auto p-3">
      <div className="flex items-center justify-between">
        <span className="text-xs text-textSecondary">Analyzing current input buffer ({inFormat})</span>
        <button onClick={runAnalysis} className="flex items-center gap-1.5 rounded border border-borderSubtle bg-surface px-2.5 py-1 text-xs text-textPrimary hover:border-accent">
          <RefreshCw className="h-3.5 w-3.5" /><span>Refresh</span>
        </button>
      </div>
      {error && <div className="rounded border border-red-500/40 bg-red-500/10 p-2.5 text-xs text-red-300">{error}</div>}
      {analysis && (
        <>
          <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
            <div className="rounded-lg border border-borderSubtle bg-surface p-3"><div className="text-[11px] text-textSecondary">Payload Size</div><div className="mt-1 font-mono text-lg font-semibold tabular-nums">{analysis.byte_length} B</div></div>
            <div className="rounded-lg border border-borderSubtle bg-surface p-3"><div className="text-[11px] text-textSecondary">Shannon Entropy</div><div className="mt-1 font-mono text-lg font-semibold text-accent tabular-nums">{analysis.entropy} / 8.0</div></div>
            <div className="rounded-lg border border-borderSubtle bg-surface p-3"><div className="text-[11px] text-textSecondary">Printable ASCII</div><div className="mt-1 font-mono text-lg font-semibold tabular-nums">{analysis.printable_ratio}%</div></div>
            <div className="rounded-lg border border-borderSubtle bg-surface p-3"><div className="text-[11px] text-textSecondary">Detected Protocol</div><div className="mt-1 truncate font-mono text-sm font-semibold">{analysis.detected_protocol}</div></div>
          </div>
          <div className="rounded-lg border border-borderSubtle bg-surface p-3 font-mono text-xs space-y-1">
            <div className="flex justify-between"><span className="text-textSecondary">MD5</span><span className="select-all">{analysis.hashes.md5}</span></div>
            <div className="flex justify-between"><span className="text-textSecondary">SHA-1</span><span className="select-all">{analysis.hashes.sha1}</span></div>
            <div className="flex justify-between"><span className="text-textSecondary">SHA-256</span><span className="select-all">{analysis.hashes.sha256}</span></div>
          </div>
          <div className="flex flex-1 flex-col rounded-lg border border-borderSubtle bg-surface overflow-hidden">
            <div className="border-b border-borderSubtle bg-elevated/60 px-3 py-2 text-[11px] font-semibold uppercase tracking-wider text-textSecondary">Hexadecimal & ASCII Preview</div>
            <pre className="flex-1 overflow-auto p-3 font-mono text-xs leading-relaxed">{analysis.hex_preview || "Buffer is empty."}</pre>
          </div>
        </>
      )}
    </div>
  );
};
