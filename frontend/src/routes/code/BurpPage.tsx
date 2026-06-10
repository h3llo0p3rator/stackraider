import { useCallback, useEffect, useState } from "react";
import { Card } from "@/components/ui/Card";
import { PathBrowser } from "@/components/code/PathBrowser";
import { useCodeSession } from "@/context/CodeSessionContext";
import { getBurpConfig, getBurpTraffic, setBurpConfig, uploadBurp } from "@/lib/codeApi";

export function BurpPage() {
  const { scanResult, burpTraffic, setBurpTraffic } = useCodeSession();
  const [burpJar, setBurpJar] = useState("");
  const [jarValid, setJarValid] = useState(false);
  const [jarBrowserOpen, setJarBrowserOpen] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [dragover, setDragover] = useState(false);

  useEffect(() => {
    getBurpConfig().then((c) => {
      if (c.burp_jar) setBurpJar(c.burp_jar);
      setJarValid(c.valid);
    }).catch(() => {});
    if (!burpTraffic) {
      getBurpTraffic().then((t) => {
        if (t.summary?.total > 0) setBurpTraffic(t);
      }).catch(() => {});
    }
  }, []);

  const handleFile = useCallback(async (file: File) => {
    setLoading(true);
    setError(null);
    try {
      const data = await uploadBurp(file);
      setBurpTraffic(data);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  }, [setBurpTraffic]);

  return (
    <div className="p-6 max-w-4xl space-y-4">
      {burpTraffic?.summary?.total ? (
        <Card className="p-3 bg-green-500/10 border-green-500/30 text-sm">
          <strong>{burpTraffic.summary.total} requests loaded</strong>
          {burpTraffic.summary.matched_routes > 0 && ` — ${burpTraffic.summary.matched_routes} matched routes`}
        </Card>
      ) : null}
      <Card className="p-4 space-y-3">
        <h2 className="font-semibold">Burp Suite JAR (.burp files)</h2>
        <button type="button" onClick={() => setJarBrowserOpen(true)} className="w-full text-left px-3 py-2 rounded border border-[var(--color-border)] text-sm truncate">
          {burpJar || "Browse for burpsuite_pro.jar..."}
        </button>
        {jarValid && <span className="text-green-400 text-sm">✓ JAR valid</span>}
        <PathBrowser open={jarBrowserOpen} mode="file" fileExtension=".jar" title="Select burpsuite_pro.jar" onSelect={async (p) => {
          const c = await setBurpConfig(p);
          setBurpJar(c.burp_jar);
          setJarValid(c.valid);
        }} onClose={() => setJarBrowserOpen(false)} />
      </Card>
      {error && <p className="text-red-400 text-sm">{error}</p>}
      <div
        className={`border-2 border-dashed rounded-xl p-8 text-center cursor-pointer ${dragover ? "border-indigo-500 bg-indigo-500/10" : "border-slate-600"}`}
        onDragOver={(e) => { e.preventDefault(); setDragover(true); }}
        onDragLeave={() => setDragover(false)}
        onDrop={(e) => { e.preventDefault(); setDragover(false); const f = e.dataTransfer.files[0]; if (f) handleFile(f); }}
        onClick={() => document.getElementById("burp-file")?.click()}
      >
        {loading ? "Parsing..." : "Drop .burp, .xml, or .har — or click to browse"}
        <input id="burp-file" type="file" accept=".burp,.xml,.har" className="hidden" onChange={(e) => e.target.files?.[0] && handleFile(e.target.files[0])} />
      </div>
      {!scanResult && burpTraffic?.summary?.total ? (
        <p className="text-slate-500 text-sm">Run a code scan to match traffic against discovered routes.</p>
      ) : null}
    </div>
  );
}
