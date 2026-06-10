import { useEffect, useState } from "react";
import { browseDirectory } from "@/lib/codeApi";
import { Button } from "@/components/ui/Button";

type Props = {
  open: boolean;
  initialPath?: string;
  mode?: "folder" | "file";
  fileExtension?: string;
  title?: string;
  onSelect: (path: string) => void;
  onClose: () => void;
};

export function PathBrowser({
  open,
  initialPath,
  mode = "folder",
  fileExtension = "",
  title,
  onSelect,
  onClose,
}: Props) {
  const [current, setCurrent] = useState("");
  const [parent, setParent] = useState<string | null>(null);
  const [entries, setEntries] = useState<Array<{ name: string; path: string; is_dir: boolean }>>([]);
  const [selectedFile, setSelectedFile] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const isFileMode = mode === "file";

  const load = async (path?: string) => {
    setLoading(true);
    setError(null);
    setSelectedFile("");
    try {
      const data = await browseDirectory(
        path,
        isFileMode ? "files" : "dirs",
        isFileMode ? fileExtension : undefined
      );
      setCurrent(data.current);
      setParent(data.parent);
      setEntries(data.entries);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (open) {
      setSelectedFile("");
      load(isFileMode ? undefined : initialPath);
    }
  }, [open, isFileMode]);

  if (!open) return null;

  const dirs = entries.filter((e) => e.is_dir);
  const files = entries.filter((e) => !e.is_dir);

  return (
    <div className="fixed inset-0 z-50 bg-black/60 flex items-center justify-center p-4" onClick={onClose}>
      <div
        className="bg-[var(--color-surface)] border border-[var(--color-border)] rounded-xl w-full max-w-lg max-h-[80vh] flex flex-col"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="p-4 border-b border-[var(--color-border)] flex justify-between items-center">
          <h3 className="font-medium">{title || (isFileMode ? "Select file" : "Select folder")}</h3>
          <button type="button" onClick={onClose} className="text-slate-400 hover:text-white">×</button>
        </div>
        {error && <p className="p-3 text-red-400 text-sm">{error}</p>}
        <p className="px-4 py-2 text-xs text-slate-500 truncate">{loading ? "Loading..." : current}</p>
        <div className="flex-1 overflow-y-auto px-2">
          {parent && (
            <button type="button" className="w-full text-left px-3 py-2 rounded hover:bg-slate-800" onClick={() => load(parent)}>
              ↑ ..
            </button>
          )}
          {dirs.map((e) => (
            <button key={e.path} type="button" className="w-full text-left px-3 py-2 rounded hover:bg-slate-800" onClick={() => load(e.path)}>
              📁 {e.name}
            </button>
          ))}
          {isFileMode &&
            files.map((e) => (
              <button
                key={e.path}
                type="button"
                className={`w-full text-left px-3 py-2 rounded ${selectedFile === e.path ? "bg-indigo-500/20 border border-indigo-500/40" : "hover:bg-slate-800"}`}
                onClick={() => setSelectedFile(e.path)}
              >
                📄 {e.name}
              </button>
            ))}
        </div>
        <div className="p-4 border-t border-[var(--color-border)] flex gap-2 justify-end">
          <Button variant="ghost" onClick={onClose}>Cancel</Button>
          <Button
            onClick={() => {
              if (isFileMode) {
                if (selectedFile) onSelect(selectedFile);
              } else if (current) {
                onSelect(current);
              }
              onClose();
            }}
            disabled={loading || (isFileMode ? !selectedFile : !current)}
          >
            Select
          </Button>
        </div>
      </div>
    </div>
  );
}
