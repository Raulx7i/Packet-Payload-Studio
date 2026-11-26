import React, { useState, useEffect } from "react";
import { Search, ArrowLeftRight, Microscope, Network, Layers, GitCompare, Settings } from "lucide-react";
import { WorkspaceId } from "../../store/settings";

interface Props {
  open: boolean; onClose: () => void; onNavigate: (ws: WorkspaceId) => void;
  onOpenSettings: () => void; onRunTransform: () => void;
}

export const CommandPalette: React.FC<Props> = ({ open, onClose, onNavigate, onOpenSettings, onRunTransform }) => {
  const [query, setQuery] = useState("");
  useEffect(() => { if (open) setQuery(""); }, [open]);
  if (!open) return null;

  const actions = [
    { id: "ws-convert", label: "Go to Convert & Transform", icon: ArrowLeftRight, run: () => onNavigate("convert") },
    { id: "ws-analyze", label: "Go to Payload Inspector (Analyze)", icon: Microscope, run: () => onNavigate("analyze") },
    { id: "ws-capture", label: "Go to PCAP Stream Reassembler (Capture)", icon: Network, run: () => onNavigate("capture") },
    { id: "ws-recipes", label: "Go to Recipe Library", icon: Layers, run: () => onNavigate("recipes") },
    { id: "ws-compare", label: "Go to Payload Compare", icon: GitCompare, run: () => onNavigate("compare") },
    { id: "act-run", label: "Execute Current Conversion / Pipeline", icon: ArrowLeftRight, run: onRunTransform },
    { id: "act-settings", label: "Open Appearance & Engine Settings", icon: Settings, run: onOpenSettings },
  ].filter((a) => a.label.toLowerCase().includes(query.toLowerCase()));

  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center bg-black/50 pt-24 backdrop-blur-sm" onClick={onClose}>
      <div className="glass-chrome w-full max-w-lg overflow-hidden rounded-lg border border-borderSubtle" onClick={(e) => e.stopPropagation()}>
        <div className="flex items-center gap-2.5 border-b border-borderSubtle px-3.5 py-2.5">
          <Search className="h-4 w-4 text-accent" />
          <input autoFocus value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Jump to workspace or run action..." className="w-full bg-transparent text-sm text-textPrimary outline-none placeholder:text-textSecondary" />
        </div>
        <div className="max-h-72 overflow-y-auto p-1.5">
          {actions.map((item) => {
            const Icon = item.icon;
            return (
              <button key={item.id} onClick={() => { item.run(); onClose(); }} className="flex w-full items-center gap-2.5 rounded-md px-3 py-2 text-left text-xs text-textPrimary hover:bg-accentMuted hover:text-accent">
                <Icon className="h-4 w-4 text-textSecondary" /><span>{item.label}</span>
              </button>
            );
          })}
        </div>
      </div>
    </div>
  );
};
