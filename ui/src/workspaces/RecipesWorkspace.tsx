import React, { useEffect, useState } from "react";
import { Layers, Play } from "lucide-react";
import { PipelineStep, rpcCall } from "../lib/ipc";

interface RecipeItem { name: string; filename: string; content: { version: number; steps: PipelineStep[] }; }
interface Props { onLoadRecipe: (steps: PipelineStep[]) => void; }

export const RecipesWorkspace: React.FC<Props> = ({ onLoadRecipe }) => {
  const [recipes, setRecipes] = useState<RecipeItem[]>([]);
  useEffect(() => { rpcCall<{ recipes: RecipeItem[] }>("list_example_recipes").then((r) => setRecipes(r.recipes)).catch(() => {}); }, []);

  return (
    <div className="flex h-full flex-col gap-3 overflow-y-auto p-3">
      <div className="rounded-lg border border-borderSubtle bg-surface p-3 text-xs text-textSecondary">
        Load existing <code className="font-mono text-textPrimary">version: 2</code> JSON transformation recipes directly into the Convert pipeline.
      </div>
      <div className="grid grid-cols-1 gap-3 md:grid-cols-2 lg:grid-cols-3">
        {recipes.map((r) => (
          <div key={r.filename} className="flex flex-col justify-between rounded-lg border border-borderSubtle bg-surface p-4">
            <div>
              <div className="flex items-center gap-2 text-sm font-semibold"><Layers className="h-4 w-4 text-accent" /><span>{r.name}</span></div>
              <div className="mt-1 font-mono text-[11px] text-textSecondary">{r.filename}</div>
              <ul className="mt-3 space-y-1 font-mono text-xs">
                {(r.content.steps ?? []).map((s, i) => <li key={i}>{i + 1}. {s.op_id} {s.param ? `(${s.param})` : ""}</li>)}
              </ul>
            </div>
            <button onClick={() => onLoadRecipe(r.content.steps ?? [])} className="mt-4 flex items-center justify-center gap-1.5 rounded bg-accent px-3 py-1.5 text-xs font-semibold text-slate-950 hover:opacity-90">
              <Play className="h-3.5 w-3.5 fill-current" /><span>Load into Convert</span>
            </button>
          </div>
        ))}
      </div>
    </div>
  );
};
