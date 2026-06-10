import { useMemo } from "react";
import { Link } from "react-router-dom";
import { ArrowRight, ShieldAlert } from "lucide-react";
import { Badge } from "./ui/Badge";
import { Button } from "./ui/Button";
import { Card } from "./ui/Card";
import { findRelatedQuery } from "@/lib/findRelatedQuery";
import type { Finding, GeneratedQuery } from "@/lib/types";
import { CATEGORY_LABELS } from "@/lib/types";

const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"] as const;

export function FindingsDashboard({
  findings,
  queries = [],
}: {
  findings: Finding[];
  queries?: GeneratedQuery[];
}) {
  const grouped = useMemo(() => {
    const map = new Map<string, Finding[]>();
    for (const f of findings) {
      const key = f.category;
      if (!map.has(key)) map.set(key, []);
      map.get(key)!.push(f);
    }
    for (const [, list] of map) {
      list.sort(
        (a, b) =>
          SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity)
      );
    }
    return map;
  }, [findings]);

  const counts = useMemo(() => {
    const c: Record<string, number> = {};
    for (const s of SEVERITY_ORDER) {
      c[s] = findings.filter((f) => f.severity === s).length;
    }
    return c;
  }, [findings]);

  if (!findings.length) {
    return (
      <div className="flex flex-col items-center justify-center h-full text-slate-500 p-8">
        <ShieldAlert className="h-12 w-12 mb-4 opacity-40" />
        <p>No findings yet — run an analysis first</p>
      </div>
    );
  }

  return (
    <div className="flex flex-col h-full p-6 gap-4 overflow-hidden">
      <div>
        <h2 className="text-2xl font-semibold text-white">Findings</h2>
        <div className="flex gap-3 mt-2 flex-wrap">
          {SEVERITY_ORDER.map((s) =>
            counts[s] > 0 ? (
              <Badge key={s} severity={s}>
                {counts[s]} {s}
              </Badge>
            ) : null
          )}
        </div>
      </div>

      <div className="flex-1 overflow-y-auto space-y-6">
        {Array.from(grouped.entries()).map(([category, items]) => (
          <section key={category}>
            <h3 className="text-sm font-medium text-slate-400 uppercase tracking-wider mb-3">
              {CATEGORY_LABELS[category as keyof typeof CATEGORY_LABELS] ?? category}
            </h3>
            <div className="grid gap-3 md:grid-cols-2">
              {items.map((f) => {
                const related = findRelatedQuery(f, queries);
                return (
                  <Card key={f.id} className="space-y-2">
                    <div className="flex items-start justify-between gap-2">
                      <h4 className="font-medium text-white text-sm leading-snug">{f.title}</h4>
                      <Badge severity={f.severity}>{f.severity}</Badge>
                    </div>
                    <p className="text-sm text-slate-400 leading-relaxed">{f.description}</p>
                    {(f.affected_types.length > 0 || f.affected_fields.length > 0) && (
                      <p className="text-xs font-mono text-slate-500">
                        {[...f.affected_types, ...f.affected_fields].join(" · ")}
                      </p>
                    )}
                    {f.recommendation && (
                      <p className="text-xs text-indigo-300/80 border-t border-slate-700 pt-2">
                        {f.recommendation}
                      </p>
                    )}
                    <div className="flex items-center justify-between pt-1">
                      <span className="text-[10px] text-slate-600 uppercase">{f.source}</span>
                      {related && (
                        <Link to={`/queries?q=${related.id}`}>
                          <Button variant="ghost" size="sm" className="text-indigo-400">
                            View test query
                            <ArrowRight className="h-3 w-3" />
                          </Button>
                        </Link>
                      )}
                    </div>
                  </Card>
                );
              })}
            </div>
          </section>
        ))}
      </div>
    </div>
  );
}
