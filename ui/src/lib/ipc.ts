import { invoke } from "@tauri-apps/api/core";

export interface PipelineStep { op_id: string; param: string; enabled: boolean; }
export interface StepTrace { index: number; op_id: string; byte_length: number; preview_utf8: string; preview_hex: string; }
export interface ConvertResult { output_text: string; input_bytes: number; output_bytes: number; trace: StepTrace[]; }
export interface AnalyzeResult {
  byte_length: number; entropy: number; printable_ratio: number; detected_protocol: string;
  hashes: { md5: string; sha1: string; sha256: string };
  hex_preview: string; ascii_preview: string;
}
export interface PcapStreamItem { index: number; key: string; summary: string; byte_length: number; }
export interface CapabilitiesResult {
  formats: string[];
  categories: { id: string; label: string; ops: { id: string; label: string; has_param: boolean; placeholder?: string }[] }[];
}

export async function rpcCall<T>(method: string, params: Record<string, unknown> = {}): Promise<T> {
  return invoke<T>("python_rpc", { method, params });
}
