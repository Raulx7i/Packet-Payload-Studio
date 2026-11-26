import React, { useState } from "react";
import { Play, Copy, Trash2, ArrowLeftRight, Plus, FolderOpen, Check, AlertCircle } from "lucide-react";
import { open } from "@tauri-apps/plugin-dialog";
import { CapabilitiesResult, ConvertResult, PipelineStep, rpcCall } from "../lib/ipc";

interface Props {
  inputText: string; setInputText: (v: string) => void;
  inFormat: string; setInFormat: (v: string) => void;
  outFormat: string; setOutFormat: (v: string) => void;
  peerFilter: string; setPeerFilter: (v: string) => void;
  steps: PipelineStep[]; setSteps: (s: PipelineStep[]) => void;
  capabilities: CapabilitiesResult | null;
}

export const ConvertWorkspace: React.FC<Props> = ({
  inputText, setInputText, inFormat, setInFormat, outFormat, setOutFormat, peerFilter, setPeerFilter, steps, setSteps, capabilities
}) => {
  const [result, setResult] = useState<ConvertResult | null>(null);
  const [selectedStepIdx, setSelectedStepIdx] = useState<number | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  const formats = capabilities?.formats ?? ["UTF-8", "ASCII", "Hex Dump", "C Array", "Base64", "Raw", "EBCDIC"];

  const execute = async () => {
    setLoading(true); setError(null); setSelectedStepIdx(null);
    try {
      const res = await rpcCall<ConvertResult>("convert_and_transform", {
        input_text: inputText, in_format: inFormat, out_format: outFormat,
        peer: inFormat === "C Array" ? peerFilter : "All Streams", steps,
      });
      setResult(res);
    } catch (err) { setError(err instanceof Error ? err.message : String(err)); }
    finally { setLoading(false); }
  };

  const openFile = async () => {
    try {
      const selected = await open({ multiple: false });
      if (typeof selected === "string") {
        setLoading(true); setError(null);
        const res = await rpcCall<ConvertResult>("convert_and_transform", {
          file_path: selected, in_format: inFormat, out_format: outFormat,
          peer: inFormat === "C Array" ? peerFilter : "All Streams", steps,
        });
        setResult(res); setInputText(res.output_text);
      }
    } catch (err) { setError(err instanceof Error ? err.message : String(err)); }
    finally { setLoading(false); }
  };

  const copyOutput = async () => {
    if (!result?.output_text) return;
    await navigator.clipboard.writeText(result.output_text);
    setCopied(true); setTimeout(() => setCopied(false), 1500);
  };

  const swapInputOutput = () => {
    if (!result) return;
    setInputText(result.output_text); setInFormat(outFormat); setResult(null);
  };

  const activeTrace = selectedStepIdx !== null ? result?.trace.find((t) => t.index === selectedStepIdx) : null;

  return (
    <div className="flex h-full flex-col gap-3 p-3">
      {error && (
        <div className="flex items-center gap-2 rounded-md border border-red-500/40 bg-red-500/10 px-3 py-2 text-xs text-red-300">
          <AlertCircle className="h-4 w-4 shrink-0 text-red-400" /><span className="font-mono">{error}</span>
        </div>
      )}
      <div className="grid flex-1 grid-cols-1 gap-3 lg:grid-cols-12 overflow-hidden">
        <section className="flex flex-col rounded-lg border border-borderSubtle bg-surface lg:col-span-5 overflow-hidden">
          <div className="flex flex-wrap items-center justify-between gap-2 border-b border-borderSubtle bg-elevated/60 px-3 py-2">
            <div className="flex items-center gap-2">
              <span className="text-[11px] font-semibold uppercase tracking-wider text-textSecondary">Input</span>
              <select value={inFormat} onChange={(e) => setInFormat(e.target.value)} className="rounded border border-borderSubtle bg-canvas px-2 py-1 text-xs text-textPrimary outline-none focus:border-accent">
                {formats.map((f) => <option key={f} value={f}>{f}</option>)}
              </select>
              {inFormat === "C Array" && (
                <select value={peerFilter} onChange={(e) => setPeerFilter(e.target.value)} className="rounded border border-borderSubtle bg-canvas px-2 py-1 text-xs text-textPrimary outline-none focus:border-accent">
                  <option value="All Streams">All Streams</option>
                  <option value="peer0">peer0</option>
                  <option value="peer1">peer1</option>
                </select>
              )}
            </div>
            <div className="flex items-center gap-1">
              <button onClick={openFile} className="flex items-center gap-1 rounded border border-borderSubtle bg-canvas px-2 py-1 text-xs text-textSecondary hover:text-textPrimary">
                <FolderOpen className="h-3.5 w-3.5" /><span>Open</span>
              </button>
              <button onClick={() => { setInputText(""); setResult(null); }} className="rounded border border-borderSubtle bg-canvas p-1 text-textSecondary hover:text-textPrimary">
                <Trash2 className="h-3.5 w-3.5" />
              </button>
            </div>
          </div>
          <textarea value={inputText} onChange={(e) => setInputText(e.target.value)} spellCheck={false} placeholder="Paste Hex Dump, C Array, Base64, UTF-8, ASCII, EBCDIC, or open a file..." className="flex-1 resize-none bg-surface p-3 font-mono text-xs leading-relaxed text-textPrimary outline-none placeholder:text-textSecondary/60" />
          <div className="flex items-center justify-between border-t border-borderSubtle px-3 py-1.5 text-[11px] text-textSecondary tabular-nums">
            <span>{inputText.length} chars</span>{result && <span>Parsed: {result.input_bytes} bytes</span>}
          </div>
        </section>

        <section className="flex flex-col rounded-lg border border-borderSubtle bg-surface lg:col-span-3 overflow-hidden">
          <div className="flex items-center justify-between border-b border-borderSubtle bg-elevated/60 px-3 py-2">
            <span className="text-[11px] font-semibold uppercase tracking-wider text-textSecondary">Pipeline</span>
            <button onClick={execute} disabled={loading} className="flex items-center gap-1.5 rounded bg-accent px-2.5 py-1 text-xs font-semibold text-slate-950 hover:opacity-90 disabled:opacity-50">
              <Play className="h-3 w-3 fill-current" /><span>{loading ? "Running..." : "Execute"}</span>
            </button>
          </div>
          <div className="border-b border-borderSubtle p-2">
            <select defaultValue="" onChange={(e) => { if (e.target.value) { setSteps([...steps, { op_id: e.target.value, param: "", enabled: true }]); e.target.value = ""; } }} className="w-full rounded border border-borderSubtle bg-canvas px-2 py-1.5 text-xs text-textPrimary outline-none focus:border-accent">
              <option value="" disabled>+ Add transformation step...</option>
              {(capabilities?.categories ?? []).map((cat) => (
                <optgroup key={cat.id} label={cat.label}>
                  {cat.ops.map((op) => <option key={op.id} value={op.id}>{op.label}</option>)}
                </optgroup>
              ))}
            </select>
          </div>
          <div className="flex-1 space-y-1.5 overflow-y-auto p-2">
            {steps.length === 0 ? (
              <div className="flex h-full flex-col items-center justify-center px-3 text-center text-xs text-textSecondary">
                <Plus className="mb-1.5 h-4 w-4 opacity-50" /><p>Direct format conversion active.</p>
              </div>
            ) : steps.map((step, idx) => (
              <div key={`${step.op_id}-${idx}`} onClick={() => setSelectedStepIdx(selectedStepIdx === idx ? null : idx)} className={`cursor-pointer rounded border p-2 text-xs ${selectedStepIdx === idx ? "border-accent bg-accentMuted/40" : "border-borderSubtle bg-canvas"}`}>
                <div className="flex items-center justify-between gap-2">
                  <span className="truncate font-mono font-medium text-textPrimary">{idx + 1}. {step.op_id}</span>
                  <button onClick={(e) => { e.stopPropagation(); setSteps(steps.filter((_, i) => i !== idx)); }} className="text-textSecondary hover:text-red-400"><Trash2 className="h-3 w-3" /></button>
                </div>
                {step.op_id.toLowerCase().includes("param =") && (
                  <input value={step.param} onClick={(e) => e.stopPropagation()} onChange={(e) => { const next = [...steps]; next[idx] = { ...step, param: e.target.value }; setSteps(next); }} placeholder="Parameter (e.g. 0x55)..." className="mt-1.5 w-full rounded border border-borderSubtle bg-surface px-2 py-1 font-mono text-[11px] text-textPrimary outline-none focus:border-accent" />
                )}
              </div>
            ))}
          </div>
        </section>

        <section className="flex flex-col rounded-lg border border-borderSubtle bg-surface lg:col-span-4 overflow-hidden">
          <div className="flex items-center justify-between border-b border-borderSubtle bg-elevated/60 px-3 py-2">
            <div className="flex items-center gap-2">
              <span className="text-[11px] font-semibold uppercase tracking-wider text-textSecondary">Output</span>
              <select value={outFormat} onChange={(e) => setOutFormat(e.target.value)} className="rounded border border-borderSubtle bg-canvas px-2 py-1 text-xs text-textPrimary outline-none focus:border-accent">
                {formats.map((f) => <option key={f} value={f}>{f}</option>)}
              </select>
            </div>
            <div className="flex items-center gap-1">
              <button onClick={swapInputOutput} disabled={!result} className="rounded border border-borderSubtle bg-canvas p-1 text-textSecondary hover:text-textPrimary disabled:opacity-40"><ArrowLeftRight className="h-3.5 w-3.5" /></button>
              <button onClick={copyOutput} disabled={!result} className="flex items-center gap-1 rounded border border-borderSubtle bg-canvas px-2 py-1 text-xs text-textSecondary hover:text-textPrimary disabled:opacity-40">
                {copied ? <Check className="h-3.5 w-3.5 text-emerald-400" /> : <Copy className="h-3.5 w-3.5" />}<span>{copied ? "Copied" : "Copy"}</span>
              </button>
            </div>
          </div>
          <textarea readOnly value={activeTrace ? activeTrace.preview_utf8 : result?.output_text ?? ""} placeholder="Converted payload output appears here..." className="flex-1 resize-none bg-surface p-3 font-mono text-xs leading-relaxed text-textPrimary outline-none placeholder:text-textSecondary/60" />
          <div className="flex items-center justify-between border-t border-borderSubtle px-3 py-1.5 text-[11px] text-textSecondary tabular-nums">
            <span>{activeTrace ? `Inspecting Step #${activeTrace.index + 1}` : "Final Output"}</span>
            {result && <span>{activeTrace ? activeTrace.byte_length : result.output_bytes} bytes</span>}
          </div>
        </section>
      </div>
    </div>
  );
};
