import React from "react";
import { X } from "lucide-react";
import { AccentColor, AppSettings, ThemeMode } from "../../store/settings";

interface Props { open: boolean; onClose: () => void; settings: AppSettings; onChange: (next: AppSettings) => void; }

export const SettingsModal: React.FC<Props> = ({ open, onClose, settings, onChange }) => {
  if (!open) return null;
  const update = <K extends keyof AppSettings>(key: K, val: AppSettings[K]) => onChange({ ...settings, [key]: val });

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4 backdrop-blur-sm" onClick={onClose}>
      <div className="glass-chrome w-full max-w-xl rounded-lg border border-borderSubtle p-5" onClick={(e) => e.stopPropagation()}>
        <div className="mb-4 flex items-center justify-between border-b border-borderSubtle pb-3">
          <div>
            <h2 className="text-sm font-semibold text-textPrimary">Application Settings</h2>
            <p className="text-xs text-textSecondary">Theme, Hyprland-style glassmorphism & keyboard shortcuts</p>
          </div>
          <button onClick={onClose} className="rounded p-1 text-textSecondary hover:bg-elevated hover:text-textPrimary"><X className="h-4 w-4" /></button>
        </div>
        <div className="space-y-4 text-xs">
          <div className="flex items-center justify-between">
            <div><div className="font-medium text-textPrimary">Color Theme</div><div className="text-textSecondary">Graphite Dark, Neutral Light, or System</div></div>
            <div className="flex gap-1 rounded-md border border-borderSubtle bg-surface p-1">
              {(["dark", "light", "system"] as ThemeMode[]).map((t) => (
                <button key={t} onClick={() => update("theme", t)} className={`rounded px-2.5 py-1 capitalize ${settings.theme === t ? "bg-accentMuted font-medium text-accent" : "text-textSecondary"}`}>{t}</button>
              ))}
            </div>
          </div>
          <div className="flex items-center justify-between">
            <div><div className="font-medium text-textPrimary">Accent Color</div></div>
            <div className="flex gap-2">
              {(["cyan", "teal", "emerald", "blue", "amber"] as AccentColor[]).map((c) => (
                <button key={c} onClick={() => update("accent", c)} className={`rounded border px-2 py-1 capitalize ${settings.accent === c ? "border-accent bg-accentMuted text-accent" : "border-borderSubtle text-textSecondary"}`}>{c}</button>
              ))}
            </div>
          </div>
          <div className="flex items-center justify-between">
            <div><div className="font-medium text-textPrimary">Translucent Chrome & Blur</div><div className="text-textSecondary">Sidebar & toolbar blur (editors stay solid)</div></div>
            <button onClick={() => update("transparency", !settings.transparency)} className={`rounded-md border px-3 py-1 font-medium ${settings.transparency ? "border-accent bg-accentMuted text-accent" : "border-borderSubtle bg-surface text-textSecondary"}`}>
              {settings.transparency ? "Enabled" : "Solid Fallback"}
            </button>
          </div>
          {settings.transparency && (
            <div className="space-y-2 rounded-md border border-borderSubtle bg-surface/60 p-3">
              <div className="flex items-center justify-between">
                <span className="font-medium text-textPrimary">Chrome Opacity ({settings.glassOpacity ?? 65}%)</span>
                <div className="flex gap-1">
                  {[
                    { label: "High Blur (45%)", val: 45 },
                    { label: "Balanced (65%)", val: 65 },
                    { label: "Subtle (85%)", val: 85 },
                  ].map((p) => (
                    <button key={p.val} onClick={() => update("glassOpacity", p.val)} className={`rounded px-2 py-0.5 text-[11px] ${settings.glassOpacity === p.val ? "bg-accentMuted text-accent" : "text-textSecondary hover:text-textPrimary"}`}>
                      {p.label}
                    </button>
                  ))}
                </div>
              </div>
              <input
                type="range"
                min={25}
                max={100}
                value={settings.glassOpacity ?? 65}
                onChange={(e) => update("glassOpacity", Number(e.target.value))}
                className="w-full accent-[var(--accent)] cursor-pointer"
              />
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
