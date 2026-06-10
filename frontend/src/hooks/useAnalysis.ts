import { useCallback, useEffect, useRef, useState } from "react";
import { analyzeIntrospection } from "@/lib/api";
import type {
  AnalysisLogEntry,
  AnalysisPhase,
  AppSettings,
  Finding,
  GeneratedQuery,
  ParsedSchema,
} from "@/lib/types";

let logId = 0;

function makeLogEntry(
  level: AnalysisLogEntry["level"],
  message: string,
  extra?: Partial<AnalysisLogEntry>
): AnalysisLogEntry {
  return {
    id: String(++logId),
    level,
    message,
    time: new Date().toLocaleTimeString(),
    ...extra,
  };
}

export function useAnalysis(settings: AppSettings) {
  const [schema, setSchema] = useState<ParsedSchema | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [queries, setQueries] = useState<GeneratedQuery[]>([]);
  const [logs, setLogs] = useState<AnalysisLogEntry[]>([]);
  const [phase, setPhase] = useState<AnalysisPhase>("idle");
  const [status, setStatus] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const abortRef = useRef<AbortController | null>(null);

  useEffect(() => {
    fetch("/api/graphql/state", { credentials: "include" })
      .then((r) => (r.ok ? r.json() : null))
      .then((data) => {
        if (!data) return;
        if (data.schema) setSchema(data.schema);
        if (data.findings?.length) setFindings(data.findings);
        if (data.queries?.length) setQueries(data.queries);
      })
      .catch(() => {});
  }, []);

  const reset = useCallback(() => {
    setSchema(null);
    setFindings([]);
    setQueries([]);
    setLogs([]);
    setPhase("idle");
    setStatus(null);
    setError(null);
  }, []);

  const appendLog = useCallback((entry: AnalysisLogEntry) => {
    setLogs((prev) => [...prev, entry]);
    if (entry.message) {
      setStatus(entry.message);
    }
  }, []);

  const analyze = useCallback(
    async (introspection: unknown) => {
      abortRef.current?.abort();
      abortRef.current = new AbortController();
      reset();
      setLoading(true);
      setPhase("parsing");
      appendLog(makeLogEntry("info", "Submitting introspection for analysis..."));

      try {
        await analyzeIntrospection(
          introspection,
          settings,
          {
            onSchema: (s) => {
              setSchema(s);
              setPhase("static");
              appendLog(
                makeLogEntry(
                  "success",
                  `Schema received — ${s.type_count} types, ${s.query_count} queries`
                )
              );
            },
            onFindings: (source, newFindings) => {
              setFindings((prev) => {
                const next =
                  source === "llm_finalize"
                    ? [...prev.filter((f) => f.source !== "llm"), ...newFindings]
                    : [...prev, ...newFindings];
                const label =
                  source === "static"
                    ? "Static"
                    : source === "llm_finalize"
                      ? "LLM (consolidated)"
                      : "LLM";
                appendLog(
                  makeLogEntry(
                    "success",
                    `${label} findings: +${newFindings.length} (total ${next.length})`
                  )
                );
                return next;
              });
              if (source === "static") setPhase("queries");
              else if (source === "llm") setPhase("llm");
            },
            onQueriesBatch: (batch) => {
              setQueries((prev) => {
                const next = [...prev, ...batch];
                appendLog(
                  makeLogEntry(
                    "success",
                    `+${batch.length} test queries (${next.length} total — available on Queries tab)`
                  )
                );
                return next;
              });
              setPhase("queries");
            },
            onQueries: (q) => {
              setQueries(q);
              setPhase("queries");
              appendLog(makeLogEntry("success", `Received ${q.length} test queries`));
            },
            onLog: (payload) => {
              const msg = payload.message.toLowerCase();
              if (payload.level === "error") setPhase("error");
              if (msg.includes("llm analyzing") || msg.includes("connecting to ollama")) {
                setPhase("llm");
              }
              if (msg.includes("generating exploit")) setPhase("queries");
              if (msg.includes("analysis complete")) setPhase("complete");

              appendLog(
                makeLogEntry(payload.level, payload.message, {
                  chunk: payload.chunk,
                  stream_start: payload.stream_start,
                })
              );
            },
            onComplete: (summary) => {
              setPhase("complete");
              setStatus(
                `Done — ${summary.finding_count} findings, ${summary.query_count} queries`
              );
            },
            onError: (err) => {
              setError(err);
              setPhase("error");
            },
          },
          abortRef.current.signal
        );
      } catch (e) {
        if ((e as Error).name !== "AbortError") {
          const msg = (e as Error).message;
          setError(msg);
          setPhase("error");
          appendLog(makeLogEntry("error", msg));
        }
      } finally {
        setLoading(false);
      }
    },
    [settings, reset, appendLog]
  );

  const cancel = useCallback(() => {
    abortRef.current?.abort();
    setLoading(false);
    appendLog(makeLogEntry("info", "Analysis cancelled"));
    setPhase("idle");
  }, [appendLog]);

  return {
    schema,
    findings,
    queries,
    logs,
    phase,
    status,
    loading,
    error,
    analyze,
    reset,
    cancel,
  };
}
