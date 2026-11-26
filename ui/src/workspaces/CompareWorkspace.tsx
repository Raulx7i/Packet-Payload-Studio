import React, { useState } from "react";
import { GitCompare, Play, Split, AlertCircle } from "lucide-react";
import { rpcCall } from "../lib/ipc";

interface DiffRow {
  offset: string;
  left_hex: string[];
  right_hex: string[];
  left_ascii: string;
  right_ascii: string;
  diff_cols: number[];
}

interface CompareResult {
  left_bytes: number;
  right_bytes: number;
  diff_count: number;
  similarity_pct: number;
  rows: DiffRow[];
  truncated: boolean;
}

const FORMATS = ["UTF-8", "ASCII", "Hex Dump", "C Array", "Base64", "Raw", "EBCDIC"];

export const CompareWorkspace: React.FC = () => {
  const [leftText, setLeftText] = useState("");
  const [rightText, setRightText] = useState("");
  const [leftFormat, setLeftFormat] = useState("UTF-8");
  const [rightFormat, setRightFormat] = useState("UTF-8");
  const [leftPeer, setLeftPeer] = useState("All Streams");
  const [rightPeer, setRightPeer] = useState("All Streams");
  const [onlyDiffs, setOnlyDiffs] = useState(false);
  const [result, setResult] = useState<CompareResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  const runCompare = async () => {
    setError(null);
    try {
      const res = await rpcCall<CompareResult>("compare_payloads", {
        left_text: leftText,
        right_text: rightText,
        left_format: leftFormat,
        right_format: rightFormat,
        left_peer: leftFormat === "C Array" ? leftPeer : "All Streams",
        right_peer: rightFormat === "C Array" ? rightPeer : "All Streams",
      });
      setResult(res);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  };

  const splitPeersFromLeft = () => {
    if (!leftText.trim()) return;
    setRightText(leftText);
    setLeftFormat("C Array");
    setRightFormat("C Array");
    setLeftPeer("peer0");
    setRightPeer("peer1");
  };

  const visibleRows = result ? (onlyDiffs ? result.rows.filter((r) => r.diff_cols.length > 0) : result.rows) : [];

  return (
    <div className="flex h-full flex-col gap-3 overflow-hidden p-3">
      <div className="flex flex-wrap items-center justify-between gap-2 rounded-lg border border-borderSubtle bg-surface px-3 py-2">
        <div className="flex items-center gap-2 text-xs">
          <GitCompare className="h-4 w-4 text-accent" />
          <span className="font-semibold text-textPrimary">Binary & Stream Diff</span>
          {result && (
            <span className="ml-2 font-mono text-[11px] text-textSecondary tabular-nums">
              Left: {result.left_bytes}B · Right: {result.right_bytes}B · Diffs:{" "}
              <strong className={result.diff_count > 0 ? "text-amber-400" : "text-emerald-400"}>
                {result.diff_count}B
              </strong>{" "}
              ({result.similarity_pct}% match)
            </span>
          )}
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={splitPeersFromLeft}
            title="Copy Left C-Array to Right and compare peer0 vs peer1"
            className="flex items-center gap-1.5 rounded border border-borderSubtle bg-canvas px-2.5 py-1 text-xs text-textSecondary hover:text-textPrimary"
          >
            <Split className="h-3.5 w-3.5" />
            <span>Split peer0 vs peer1</span>
          </button>
          <label className="flex cursor-pointer items-center gap-1.5 text-xs text-textSecondary select-none">
            <input
              type="checkbox"
              checked={onlyDiffs}
              onChange={(e) => setOnlyDiffs(e.target.checked)}
              className="accent-[var(--accent)]"
            />
            <span>Only diffs</span>
          </label>
          <button
            onClick={runCompare}
            className="flex items-center gap-1.5 rounded bg-accent px-3 py-1 text-xs font-semibold text-slate-950 hover:opacity-90"
          >
            <Play className="h-3 w-3 fill-current" />
            <span>Compare</span>
          </button>
        </div>
      </div>

      {error && (
        <div className="flex items-center gap-2 rounded border border-red-500/40 bg-red-500/10 px-3 py-2 text-xs text-red-300">
          <AlertCircle className="h-4 w-4 shrink-0 text-red-400" />
          <span className="font-mono">{error}</span>
        </div>
      )}

      <div className="grid h-44 shrink-0 grid-cols-1 gap-3 md:grid-cols-2">
        <div className="flex flex-col rounded-lg border border-borderSubtle bg-surface overflow-hidden">
          <div className="flex items-center justify-between border-b border-borderSubtle bg-elevated/60 px-3 py-1.5">
            <span className="text-[11px] font-semibold uppercase tracking-wider text-textSecondary">Payload A (Left)</span>
            <div className="flex items-center gap-1.5">
              <select
                value={leftFormat}
                onChange={(e) => setLeftFormat(e.target.value)}
                className="rounded border border-borderSubtle bg-canvas px-2 py-0.5 text-xs text-textPrimary outline-none"
              >
                {FORMATS.map((f) => <option key={f} value={f}>{f}</option>)}
              </select>
              {leftFormat === "C Array" && (
                <select
                  value={leftPeer}
                  onChange={(e) => setLeftPeer(e.target.value)}
                  className="rounded border border-borderSubtle bg-canvas px-2 py-0.5 text-xs text-textPrimary outline-none"
                >
                  <option value="All Streams">All Streams</option>
                  <option value="peer0">peer0</option>
                  <option value="peer1">peer1</option>
                </select>
              )}
            </div>
          </div>
          <textarea
            value={leftText}
            onChange={(e) => setLeftText(e.target.value)}
            spellCheck={false}
            placeholder="Paste first payload or Wireshark C Array..."
            className="flex-1 resize-none bg-surface p-2.5 font-mono text-xs text-textPrimary outline-none"
          />
        </div>

        <div className="flex flex-col rounded-lg border border-borderSubtle bg-surface overflow-hidden">
          <div className="flex items-center justify-between border-b border-borderSubtle bg-elevated/60 px-3 py-1.5">
            <span className="text-[11px] font-semibold uppercase tracking-wider text-textSecondary">Payload B (Right)</span>
            <div className="flex items-center gap-1.5">
              <select
                value={rightFormat}
                onChange={(e) => setRightFormat(e.target.value)}
                className="rounded border border-borderSubtle bg-canvas px-2 py-0.5 text-xs text-textPrimary outline-none"
              >
                {FORMATS.map((f) => <option key={f} value={f}>{f}</option>)}
              </select>
              {rightFormat === "C Array" && (
                <select
                  value={rightPeer}
                  onChange={(e) => setRightPeer(e.target.value)}
                  className="rounded border border-borderSubtle bg-canvas px-2 py-0.5 text-xs text-textPrimary outline-none"
                >
                  <option value="All Streams">All Streams</option>
                  <option value="peer0">peer0</option>
                  <option value="peer1">peer1</option>
                </select>
              )}
            </div>
          </div>
          <textarea
            value={rightText}
            onChange={(e) => setRightText(e.target.value)}
            spellCheck={false}
            placeholder="Paste second payload to diff..."
            className="flex-1 resize-none bg-surface p-2.5 font-mono text-xs text-textPrimary outline-none"
          />
        </div>
      </div>

      <div className="flex flex-1 flex-col rounded-lg border border-borderSubtle bg-surface overflow-hidden">
        <div className="border-b border-borderSubtle bg-elevated/60 px-3 py-1.5 text-[11px] font-semibold uppercase tracking-wider text-textSecondary">
          Synchronized 16-Byte Hex & ASCII Comparison
        </div>
        <div className="flex-1 overflow-auto p-3 font-mono text-xs">
          {!result ? (
            <div className="flex h-full items-center justify-center text-textSecondary">
              Enter two payloads above and click Compare to inspect byte-level differences.
            </div>
          ) : visibleRows.length === 0 ? (
            <div className="flex h-full items-center justify-center text-emerald-400">
              No differing bytes found between Payload A and Payload B.
            </div>
          ) : (
            <div className="space-y-1">
              {visibleRows.map((row) => (
                <div key={row.offset} className="grid grid-cols-12 items-center gap-2 rounded px-1.5 py-0.5 hover:bg-elevated/50">
                  <span className="col-span-1 text-textSecondary">{row.offset}</span>
                  <div className="col-span-4 flex flex-wrap gap-1">
                    {Array.from({ length: 16 }).map((_, col) => {
                      const hex = row.left_hex[col] ?? "..";
                      const isDiff = row.diff_cols.includes(col);
                      return (
                        <span
                          key={col}
                          className={isDiff ? "rounded bg-amber-500/25 px-0.5 font-semibold text-amber-300" : "text-textPrimary"}
                        >
                          {hex}
                        </span>
                      );
                    })}
                  </div>
                  <span className="col-span-1 truncate text-textSecondary">|{row.left_ascii}|</span>
                  <div className="col-span-4 flex flex-wrap gap-1 border-l border-borderSubtle pl-2">
                    {Array.from({ length: 16 }).map((_, col) => {
                      const hex = row.right_hex[col] ?? "..";
                      const isDiff = row.diff_cols.includes(col);
                      return (
                        <span
                          key={col}
                          className={isDiff ? "rounded bg-accentMuted px-0.5 font-semibold text-accent" : "text-textPrimary"}
                        >
                          {hex}
                        </span>
                      );
                    })}
                  </div>
                  <span className="col-span-2 truncate text-textSecondary">|{row.right_ascii}|</span>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
