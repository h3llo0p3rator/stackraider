import { useEffect, useState } from "react";
import { Check, Download, HardDrive, Trash2 } from "lucide-react";
import { Button } from "./ui/Button";
import { Card } from "./ui/Card";
import { deleteModel, fetchRecommendedModels } from "@/lib/api";
import { useModelDownloadContext } from "@/context/ModelDownloadContext";
import type { AppSettings, RecommendedModel } from "@/lib/types";

function formatSize(bytes?: number | null) {
  if (!bytes) return "—";
  const gb = bytes / 1e9;
  return gb >= 1 ? `${gb.toFixed(1)} GB` : `${(bytes / 1e6).toFixed(0)} MB`;
}

interface ModelManagerProps {
  settings: AppSettings;
  onSelectModel: (model: string) => void;
}

export function ModelManager({ settings, onSelectModel }: ModelManagerProps) {
  const {
    models,
    activeJobs,
    jobs,
    error,
    pull,
    refreshModels,
    clearError,
  } = useModelDownloadContext();
  const [recommended, setRecommended] = useState<RecommendedModel[]>([]);
  const [customName, setCustomName] = useState("");
  const [deleteError, setDeleteError] = useState<string | null>(null);

  useEffect(() => {
    fetchRecommendedModels().then(setRecommended);
    refreshModels();
  }, [refreshModels]);

  const isPullingName = (name: string) =>
    activeJobs.some((j) => j.name === name || j.name.startsWith(`${name}:`));

  const handleDelete = async (name: string) => {
    if (!confirm(`Delete model ${name}?`)) return;
    try {
      await deleteModel(name, settings.ollamaHost);
      refreshModels();
      setDeleteError(null);
    } catch (e) {
      setDeleteError((e as Error).message);
    }
  };

  const recentDone = jobs.filter((j) => j.state === "complete").slice(0, 3);

  return (
    <div className="flex flex-col h-full p-6 gap-6 overflow-y-auto">
      <div>
        <h2 className="text-2xl font-semibold text-white">Model Manager</h2>
        <p className="text-slate-400 text-sm mt-1">
          Pull, select, and manage local Ollama models. Downloads continue in the background.
        </p>
      </div>

      {(error || deleteError) && (
        <p className="text-red-400 text-sm">
          {error || deleteError}
          {error && (
            <button onClick={clearError} className="ml-2 text-red-300 underline">
              dismiss
            </button>
          )}
        </p>
      )}

      {activeJobs.length > 0 && (
        <Card className="border-indigo-500/30 space-y-3">
          <p className="text-sm text-indigo-300">Active downloads</p>
          {activeJobs.map((job) => (
            <div key={job.id}>
              <div className="flex justify-between text-sm mb-1">
                <span className="font-mono text-white">{job.name}</span>
                <span className="text-slate-400">
                  {job.percent != null ? `${job.percent.toFixed(1)}%` : job.status}
                </span>
              </div>
              <div className="h-2 bg-slate-800 rounded-full overflow-hidden">
                <div
                  className="h-full bg-gradient-to-r from-indigo-500 to-violet-500 transition-all"
                  style={{ width: `${job.percent ?? 5}%` }}
                />
              </div>
            </div>
          ))}
        </Card>
      )}

      {recentDone.length > 0 && (
        <div className="text-sm text-emerald-400">
          {recentDone.map((j) => (
            <p key={j.id}>✓ {j.name} downloaded</p>
          ))}
        </div>
      )}

      <section>
        <h3 className="text-sm font-medium text-slate-400 uppercase tracking-wider mb-3 flex items-center gap-2">
          <HardDrive className="h-4 w-4" /> Installed Models
        </h3>
        {models.length === 0 ? (
          <Card className="text-slate-500 text-sm">No models installed. Pull one below.</Card>
        ) : (
          <div className="grid gap-3 md:grid-cols-2">
            {models.map((m) => (
              <Card key={m.name} className="flex items-center justify-between gap-3">
                <div>
                  <p className="font-mono text-white text-sm">{m.name}</p>
                  <p className="text-xs text-slate-500">
                    {formatSize(m.size)}
                    {m.parameter_size && ` · ${m.parameter_size}`}
                  </p>
                </div>
                <div className="flex gap-1">
                  <Button
                    variant={settings.model === m.name ? "primary" : "secondary"}
                    size="sm"
                    onClick={() => onSelectModel(m.name)}
                  >
                    {settings.model === m.name ? <Check className="h-3 w-3" /> : "Use"}
                  </Button>
                  <Button variant="ghost" size="sm" onClick={() => handleDelete(m.name)}>
                    <Trash2 className="h-3 w-3 text-red-400" />
                  </Button>
                </div>
              </Card>
            ))}
          </div>
        )}
      </section>

      <section>
        <h3 className="text-sm font-medium text-slate-400 uppercase tracking-wider mb-3">
          Recommended for Security Work
        </h3>
        <div className="grid gap-3 md:grid-cols-2">
          {recommended.map((m) => (
            <Card key={m.name}>
              <div className="flex items-start justify-between gap-2">
                <div>
                  <p className="font-mono text-indigo-300">{m.name}</p>
                  <p className="text-xs text-slate-500">{m.size_hint}</p>
                  <p className="text-sm text-slate-400 mt-2">{m.description}</p>
                </div>
                <Button
                  size="sm"
                  onClick={() => pull(m.name)}
                  disabled={isPullingName(m.name)}
                >
                  <Download className="h-3 w-3" />
                  {isPullingName(m.name) ? "Pulling..." : "Pull"}
                </Button>
              </div>
            </Card>
          ))}
        </div>
      </section>

      <section>
        <h3 className="text-sm font-medium text-slate-400 uppercase tracking-wider mb-3">
          Pull Custom Model
        </h3>
        <div className="flex gap-2 max-w-md">
          <input
            value={customName}
            onChange={(e) => setCustomName(e.target.value)}
            placeholder="e.g. llama3.2:3b"
            className="flex-1 px-3 py-2 rounded-lg bg-slate-900 border border-slate-700 text-sm text-white placeholder:text-slate-600 focus:outline-none focus:ring-2 focus:ring-indigo-500/50"
          />
          <Button
            onClick={() => {
              if (customName) {
                pull(customName);
                setCustomName("");
              }
            }}
            disabled={!customName.trim() || isPullingName(customName)}
          >
            Pull
          </Button>
        </div>
      </section>
    </div>
  );
}
