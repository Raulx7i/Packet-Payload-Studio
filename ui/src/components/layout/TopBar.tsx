import React from "react";
import { Search, Sun, Moon } from "lucide-react";
import { AppSettings, WorkspaceId } from "../../store/settings";

interface Props {
  workspace: WorkspaceId; settings: AppSettings;
  onToggleTheme: () => void; onOpenCommandBar: () => void; backendReady: boolean;
}

const TITLES: Record<WorkspaceId, { title: string; subtitle: string }> = {
  convert: { title: "Convert & Transform", subtitle: "7-format bidirectional codecs & chained payload pipeline" },
  analyze: { title: "Payload Inspector", subtitle: "Entropy, protocol detection, digests & hex/ASCII layout" },
  capture: { title: "PCAP Stream Reassembler", subtitle: "Directional TCP/UDP flows & payload extraction" },
  recipes: { title: "Recipe Library", subtitle: "Version 2 JSON transformation workflows" },
  compare: { title: "Payload Compare", subtitle: "Side-by-side binary & stream diffing (Planned)" },
};

export const TopBar: React.FC<Props> = ({ workspace, settings, onToggleTheme, onOpenCommandBar, backendReady }) => (
  <header className="glass-chrome flex h-12 shrink-0 items-center justify-between border-b border-borderSubtle px-4">
    <div className="flex items-center gap-3">
      <h1 className="text-sm font-semibold text-textPrimary">{TITLES[workspace].title}</h1>
      <span className="hidden text-xs text-textSecondary md:inline">{TITLES[workspace].subtitle}</span>
    </div>
    <div className="flex items-center gap-2">
      <button onClick={onOpenCommandBar} className="flex items-center gap-2 rounded-md border border-borderSubtle bg-surface/80 px-2.5 py-1 text-xs text-textSecondary hover:border-accent/50 hover:text-textPrimary">
        <Search className="h-3.5 w-3.5" /><span>Command...</span>
        <kbd className="rounded bg-elevated px-1.5 py-0.5 text-[10px] font-mono">⌘K</kbd>
      </button>
      <span className="flex items-center gap-1.5 rounded-md border border-borderSubtle bg-surface/70 px-2 py-1 text-[11px] text-textSecondary">
        <span className={`h-1.5 w-1.5 rounded-full ${backendReady ? "bg-emerald-400" : "bg-amber-400 animate-pulse"}`} />
        <span>Engine</span>
      </span>
      <button onClick={onToggleTheme} className="rounded-md border border-borderSubtle bg-surface/70 p-1.5 text-textSecondary hover:text-textPrimary">
        {settings.theme === "light" ? <Moon className="h-3.5 w-3.5" /> : <Sun className="h-3.5 w-3.5" />}
      </button>
    </div>
  </header>
);
