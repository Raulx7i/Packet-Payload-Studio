import React from "react";
import { GitCompare } from "lucide-react";

export const CompareWorkspace: React.FC = () => (
  <div className="flex h-full items-center justify-center p-6">
    <div className="max-w-md rounded-lg border border-borderSubtle bg-surface p-6 text-center">
      <div className="mx-auto mb-3 flex h-10 w-10 items-center justify-center rounded-lg bg-accentMuted text-accent"><GitCompare className="h-5 w-5" /></div>
      <h2 className="text-sm font-semibold">Side-by-Side Payload Compare</h2>
      <p className="mt-1.5 text-xs leading-relaxed text-textSecondary">Byte-level binary diffing and directional stream comparison (`peer0` vs `peer1`) are scheduled for the next milestone.</p>
    </div>
  </div>
);
