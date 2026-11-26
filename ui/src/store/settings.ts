export type ThemeMode = "dark" | "light" | "system";
export type AccentColor = "cyan" | "teal" | "emerald" | "blue" | "amber";
export type GlassIntensity = "subtle" | "balanced" | "elevated";
export type WorkspaceId = "convert" | "analyze" | "capture" | "recipes" | "compare";

export interface AppSettings {
  theme: ThemeMode;
  accent: AccentColor;
  transparency: boolean;
  glassOpacity: number;
  glassIntensity: GlassIntensity;
  sidebarCollapsed: boolean;
}

const KEY = "ppstudio.settings.v2";
export const DEFAULT_SETTINGS: AppSettings = {
  theme: "dark",
  accent: "cyan",
  transparency: true,
  glassOpacity: 65,
  glassIntensity: "balanced",
  sidebarCollapsed: false
};

export function loadSettings(): AppSettings {
  try { return { ...DEFAULT_SETTINGS, ...JSON.parse(localStorage.getItem(KEY) || "{}") }; }
  catch { return DEFAULT_SETTINGS; }
}

export function saveSettings(s: AppSettings): void { localStorage.setItem(KEY, JSON.stringify(s)); }

export function applyThemeTokens(s: AppSettings): void {
  const root = document.documentElement;
  const resolved = s.theme === "system"
    ? (window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light")
    : s.theme;
  root.setAttribute("data-theme", resolved);
  root.setAttribute("data-accent", s.accent);
  root.setAttribute("data-transparency", String(s.transparency));
  const alpha = s.transparency ? Math.min(1, Math.max(0.25, (s.glassOpacity ?? 65) / 100)) : 1;
  const blurPx = s.transparency ? Math.round(8 + (1 - alpha) * 24) : 0;
  root.style.setProperty("--glass-alpha", alpha.toFixed(2));
  root.style.setProperty("--glass-blur", `${blurPx}px`);
}
