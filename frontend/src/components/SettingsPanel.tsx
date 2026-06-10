import { Card } from "./ui/Card";
import type { AppSettings } from "@/lib/types";

interface SettingsPanelProps {
  settings: AppSettings;
  onUpdate: (patch: Partial<AppSettings>) => void;
}

export function SettingsPanel({ settings, onUpdate }: SettingsPanelProps) {
  return (
    <div className="flex flex-col h-full p-6 gap-6 max-w-xl">
      <div>
        <h2 className="text-2xl font-semibold text-white">Settings</h2>
        <p className="text-slate-400 text-sm mt-1">Configure Ollama connection and analysis options.</p>
      </div>

      <Card className="space-y-4">
        <div>
          <label className="block text-sm font-medium text-slate-300 mb-1.5">
            Ollama Host URL
          </label>
          <input
            value={settings.ollamaHost}
            onChange={(e) => onUpdate({ ollamaHost: e.target.value })}
            className="w-full px-3 py-2 rounded-lg bg-slate-900 border border-slate-700 text-sm text-white font-mono focus:outline-none focus:ring-2 focus:ring-indigo-500/50"
            placeholder="http://localhost:11434"
          />
        </div>

        <div>
          <label className="block text-sm font-medium text-slate-300 mb-1.5">
            Active Model
          </label>
          <input
            value={settings.model}
            onChange={(e) => onUpdate({ model: e.target.value })}
            className="w-full px-3 py-2 rounded-lg bg-slate-900 border border-slate-700 text-sm text-white font-mono focus:outline-none focus:ring-2 focus:ring-indigo-500/50"
            placeholder="llama3.2"
          />
          <p className="text-xs text-slate-500 mt-1">
            Select models from the Models page or enter a name manually.
          </p>
        </div>

        <div>
          <label className="block text-sm font-medium text-slate-300 mb-1.5">
            DoS query nesting depth
          </label>
          <div className="flex items-center gap-4">
            <input
              type="range"
              min={2}
              max={20}
              value={settings.dosQueryDepth}
              onChange={(e) => onUpdate({ dosQueryDepth: Number(e.target.value) })}
              className="flex-1 accent-indigo-500"
            />
            <span className="font-mono text-sm text-indigo-300 w-8 text-right">
              {settings.dosQueryDepth}
            </span>
          </div>
          <p className="text-xs text-slate-500 mt-1">
            Depth for nested and circular GraphQL queries used in DoS tests (2–20).
          </p>
        </div>

        <label className="flex items-center gap-3 cursor-pointer">
          <input
            type="checkbox"
            checked={settings.skipLlm}
            onChange={(e) => onUpdate({ skipLlm: e.target.checked })}
            className="rounded border-slate-600 bg-slate-900 text-indigo-500 focus:ring-indigo-500"
          />
          <div>
            <span className="text-sm text-slate-300">Skip LLM analysis</span>
            <p className="text-xs text-slate-500">Run static analysis and query generation only</p>
          </div>
        </label>
      </Card>
    </div>
  );
}
