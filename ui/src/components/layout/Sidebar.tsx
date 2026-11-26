import React from "react";
import { ArrowLeftRight, Microscope, Network, Layers, GitCompare, Settings, PanelLeftClose, PanelLeftOpen, Terminal } from "lucide-react";
import { WorkspaceId } from "../../store/settings";

interface Props {
  active: WorkspaceId; onSelect: (id: WorkspaceId) => void;
  collapsed: boolean; onToggleCollapse: () => void; onOpenSettings: () => void;
}

const ITEMS: { id: WorkspaceId; label: string; shortcut: string; icon: React.ComponentType<{ className?: string }> }[] = [
  { id: "convert", label: "Convert", shortcut: "⌘1", icon: ArrowLeftRight },
  { id: "analyze", label: "Analyze", shortcut: "⌘2", icon: Microscope },
  { id: "capture", label: "Capture", shortcut: "⌘3", icon: Network },
  { id: "recipes", label: "Recipes", shortcut: "⌘4", icon: Layers },
  { id: "compare", label: "Compare", shortcut: "⌘5", icon: GitCompare },
];

export const Sidebar: React.FC<Props> = ({ active, onSelect, collapsed, onToggleCollapse, onOpenSettings }) => (
  <aside className={`glass-chrome flex flex-col border-r border-borderSubtle transition-all duration-150 select-none ${collapsed ? "w-14" : "w-52"}`}>
    <div className="flex h-12 items-center justify-between border-b border-borderSubtle px-3">
      {!collapsed && (
        <div className="flex items-center gap-2 overflow-hidden">
          <Terminal className="h-4 w-4 shrink-0 text-accent" />
          <span className="truncate text-xs font-semibold tracking-wide">PPSTUDIO</span>
        </div>
      )}
      <button onClick={onToggleCollapse} className="rounded p-1.5 text-textSecondary hover:bg-elevated hover:text-textPrimary">
        {collapsed ? <PanelLeftOpen className="h-4 w-4" /> : <PanelLeftClose className="h-4 w-4" />}
      </button>
    </div>
    <nav className="flex-1 space-y-1 p-2">
      {ITEMS.map((item) => {
        const Icon = item.icon;
        const isActive = active === item.id;
        return (
          <button
            key={item.id}
            onClick={() => onSelect(item.id)}
            className={`relative flex w-full items-center justify-between rounded-md px-2.5 py-2 text-xs font-medium transition-colors ${
              isActive ? "bg-accentMuted text-accent" : "text-textSecondary hover:bg-elevated hover:text-textPrimary"
            }`}
          >
            {isActive && <span className="absolute left-0 top-1.5 bottom-1.5 w-0.5 rounded-r bg-accent" />}
            <span className="flex items-center gap-2.5"><Icon className="h-4 w-4 shrink-0" />{!collapsed && <span>{item.label}</span>}</span>
            {!collapsed && <span className="text-[10px] opacity-60">{item.shortcut}</span>}
          </button>
        );
      })}
    </nav>
    <div className="border-t border-borderSubtle p-2">
      <button onClick={onOpenSettings} className="flex w-full items-center gap-2.5 rounded-md px-2.5 py-2 text-xs font-medium text-textSecondary hover:bg-elevated hover:text-textPrimary">
        <Settings className="h-4 w-4 shrink-0" />{!collapsed && <span>Settings</span>}
      </button>
    </div>
  </aside>
);
