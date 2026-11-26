import React, { useEffect, useState } from "react";
import { AppSettings, WorkspaceId, applyThemeTokens, loadSettings, saveSettings } from "./store/settings";
import { CapabilitiesResult, PipelineStep, rpcCall } from "./lib/ipc";
import { Sidebar } from "./components/layout/Sidebar";
import { TopBar } from "./components/layout/TopBar";
import { CommandPalette } from "./components/layout/CommandPalette";
import { SettingsModal } from "./components/layout/SettingsModal";
import { ConvertWorkspace } from "./workspaces/ConvertWorkspace";
import { AnalyzeWorkspace } from "./workspaces/AnalyzeWorkspace";
import { CaptureWorkspace } from "./workspaces/CaptureWorkspace";
import { RecipesWorkspace } from "./workspaces/RecipesWorkspace";
import { CompareWorkspace } from "./workspaces/CompareWorkspace";

export const App: React.FC = () => {
  const [settings, setSettings] = useState<AppSettings>(loadSettings);
  const [workspace, setWorkspace] = useState<WorkspaceId>("convert");
  const [commandOpen, setCommandOpen] = useState(false);
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [backendReady, setBackendReady] = useState(false);
  const [capabilities, setCapabilities] = useState<CapabilitiesResult | null>(null);
  const [inputText, setInputText] = useState("");
  const [inFormat, setInFormat] = useState("UTF-8");
  const [outFormat, setOutFormat] = useState("UTF-8");
  const [peerFilter, setPeerFilter] = useState("All Streams");
  const [steps, setSteps] = useState<PipelineStep[]>([]);

  useEffect(() => { applyThemeTokens(settings); saveSettings(settings); }, [settings]);

  useEffect(() => {
    rpcCall("ping").then(() => { setBackendReady(true); return rpcCall<CapabilitiesResult>("list_capabilities"); })
      .then(setCapabilities).catch(() => setBackendReady(false));
  }, []);

  useEffect(() => {
    const onKeyDown = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") { e.preventDefault(); setCommandOpen((v) => !v); }
      else if ((e.metaKey || e.ctrlKey) && ["1", "2", "3", "4", "5"].includes(e.key)) {
        e.preventDefault();
        setWorkspace((["convert", "analyze", "capture", "recipes", "compare"] as WorkspaceId[])[Number(e.key) - 1]);
      } else if (e.key === "Escape") { setCommandOpen(false); setSettingsOpen(false); }
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, []);

  return (
    <div className="flex h-screen w-screen overflow-hidden app-canvas text-textPrimary">
      <Sidebar active={workspace} onSelect={setWorkspace} collapsed={settings.sidebarCollapsed} onToggleCollapse={() => setSettings({ ...settings, sidebarCollapsed: !settings.sidebarCollapsed })} onOpenSettings={() => setSettingsOpen(true)} />
      <div className="flex flex-1 flex-col overflow-hidden">
        <TopBar workspace={workspace} settings={settings} onToggleTheme={() => setSettings({ ...settings, theme: settings.theme === "light" ? "dark" : "light" })} onOpenCommandBar={() => setCommandOpen(true)} backendReady={backendReady} />
        <main className="flex-1 overflow-hidden">
          {workspace === "convert" && <ConvertWorkspace inputText={inputText} setInputText={setInputText} inFormat={inFormat} setInFormat={setInFormat} outFormat={outFormat} setOutFormat={setOutFormat} peerFilter={peerFilter} setPeerFilter={setPeerFilter} steps={steps} setSteps={setSteps} capabilities={capabilities} />}
          {workspace === "analyze" && <AnalyzeWorkspace inputText={inputText} inFormat={inFormat} peerFilter={peerFilter} />}
          {workspace === "capture" && <CaptureWorkspace onSendToConvert={(payload, fmt) => { setInputText(payload); setInFormat(fmt); setWorkspace("convert"); }} />}
          {workspace === "recipes" && <RecipesWorkspace onLoadRecipe={(loadedSteps) => { setSteps(loadedSteps); setWorkspace("convert"); }} />}
          {workspace === "compare" && <CompareWorkspace />}
        </main>
      </div>
      <CommandPalette open={commandOpen} onClose={() => setCommandOpen(false)} onNavigate={setWorkspace} onOpenSettings={() => setSettingsOpen(true)} onRunTransform={() => setWorkspace("convert")} />
      <SettingsModal open={settingsOpen} onClose={() => setSettingsOpen(false)} settings={settings} onChange={setSettings} />
    </div>
  );
};
