import { useCallback, useEffect, useRef, useState } from "react";
import { fetchModels, fetchPullJobs, startModelPull } from "@/lib/api";
import type { AppSettings, ModelInfo, PullJob } from "@/lib/types";

const POLL_MS = 1000;
const DONE_TTL_MS = 8000;

export function useModelDownloads(settings: AppSettings) {
  const [jobs, setJobs] = useState<PullJob[]>([]);
  const [models, setModels] = useState<ModelInfo[]>([]);
  const [error, setError] = useState<string | null>(null);
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const refreshModels = useCallback(async () => {
    try {
      const list = await fetchModels(settings.ollamaHost);
      setModels(list);
    } catch {
      // Ollama may be offline during pull
    }
  }, [settings.ollamaHost]);

  const refreshJobs = useCallback(async () => {
    try {
      const list = await fetchPullJobs();
      setJobs(list);

      const hasActive = list.some((j) => j.state === "pending" || j.state === "running");
      if (!hasActive) {
        await refreshModels();
      }

      const recentError = list.find((j) => j.state === "error" && j.error);
      if (recentError?.error) {
        setError(recentError.error);
      }
    } catch (e) {
      setError((e as Error).message);
    }
  }, [refreshModels]);

  const startPolling = useCallback(() => {
    if (pollRef.current) return;
    pollRef.current = setInterval(refreshJobs, POLL_MS);
  }, [refreshJobs]);

  const stopPolling = useCallback(() => {
    if (pollRef.current) {
      clearInterval(pollRef.current);
      pollRef.current = null;
    }
  }, []);

  useEffect(() => {
    refreshJobs();
    refreshModels();
    return () => stopPolling();
  }, [refreshJobs, refreshModels, stopPolling]);

  useEffect(() => {
    const hasActive = jobs.some((j) => j.state === "pending" || j.state === "running");
    if (hasActive) {
      startPolling();
    } else {
      stopPolling();
    }
  }, [jobs, startPolling, stopPolling]);

  useEffect(() => {
    const timers = jobs
      .filter((j) => j.state === "complete" || j.state === "error")
      .map((j) =>
        setTimeout(() => {
          setJobs((prev) => prev.filter((x) => x.id !== j.id));
        }, DONE_TTL_MS)
      );
    return () => timers.forEach(clearTimeout);
  }, [jobs]);

  const pull = useCallback(
    async (name: string) => {
      setError(null);
      try {
        const job = await startModelPull(name, settings.ollamaHost);
        setJobs((prev) => {
          const without = prev.filter((j) => j.id !== job.id);
          return [job, ...without];
        });
        startPolling();
      } catch (e) {
        setError((e as Error).message);
      }
    },
    [settings.ollamaHost, startPolling]
  );

  const activeJobs = jobs.filter((j) => j.state === "pending" || j.state === "running");
  const isPulling = activeJobs.length > 0;

  return {
    jobs,
    activeJobs,
    isPulling,
    models,
    error,
    pull,
    refreshModels,
    refreshJobs,
    clearError: () => setError(null),
  };
}
