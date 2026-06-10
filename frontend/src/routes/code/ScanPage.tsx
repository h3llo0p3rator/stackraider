import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { Card } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { PathBrowser } from "@/components/code/PathBrowser";
import { useCodeSession } from "@/context/CodeSessionContext";
import { runScan } from "@/lib/codeApi";

export function ScanPage() {
  const { session, setScanResult, refresh } = useCodeSession();
  const navigate = useNavigate();
  const [path, setPath] = useState(session?.default_path || "");
  const [severity, setSeverity] = useState("INFO");
  const [includeVendor, setIncludeVendor] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [browserOpen, setBrowserOpen] = useState(false);

  useEffect(() => {
    if (session?.default_path) setPath(session.default_path);
  }, [session?.default_path]);

  const handleScan = async () => {
    if (!path.trim()) {
      setError("Select a folder to scan");
      return;
    }
    setLoading(true);
    setError(null);
    try {
      const result = await runScan({ path: path.trim(), severity, include_vendor: includeVendor });
      setScanResult(result);
      await refresh();
      navigate("/code/results");
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="p-6 max-w-3xl">
      <Card className="p-6 space-y-4">
        <h2 className="text-xl font-semibold">Static Code Scan</h2>
        <p className="text-sm text-slate-400">Scan JavaScript, TypeScript, PHP, and Python for vulnerabilities.</p>
        {error && <p className="text-red-400 text-sm">{error}</p>}
        <button
          type="button"
          onClick={() => setBrowserOpen(true)}
          className="w-full text-left px-4 py-3 rounded-lg border border-[var(--color-border)] bg-slate-900/50 hover:border-indigo-500/50 truncate"
        >
          {path || "Click to browse for a project folder..."}
        </button>
        <PathBrowser open={browserOpen} initialPath={path} onSelect={setPath} onClose={() => setBrowserOpen(false)} />
        <div className="flex flex-wrap gap-4 items-center">
          <select value={severity} onChange={(e) => setSeverity(e.target.value)} className="bg-slate-900 border border-[var(--color-border)] rounded px-3 py-2 text-sm">
            <option value="INFO">All severities</option>
            <option value="LOW">LOW+</option>
            <option value="MEDIUM">MEDIUM+</option>
            <option value="HIGH">HIGH+</option>
            <option value="CRITICAL">CRITICAL only</option>
          </select>
          <label className="flex items-center gap-2 text-sm text-slate-400">
            <input type="checkbox" checked={includeVendor} onChange={(e) => setIncludeVendor(e.target.checked)} />
            Include vendor
          </label>
        </div>
        <Button onClick={handleScan} disabled={loading || !path.trim()}>
          {loading ? "Scanning..." : "Run Scan"}
        </Button>
      </Card>
    </div>
  );
}
