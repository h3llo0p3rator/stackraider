import { useEffect, useState } from "react";
import type { AppSettings } from "@/lib/types";

const STORAGE_KEY = "graphraider-settings";

const defaults: AppSettings = {
  ollamaHost: "http://localhost:11434",
  model: "llama3.2",
  skipLlm: false,
  dosQueryDepth: 3,
};

export function useSettings() {
  const [settings, setSettings] = useState<AppSettings>(() => {
    try {
      const raw = localStorage.getItem(STORAGE_KEY);
      return raw ? { ...defaults, ...JSON.parse(raw) } : defaults;
    } catch {
      return defaults;
    }
  });

  useEffect(() => {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(settings));
  }, [settings]);

  const update = (patch: Partial<AppSettings>) => {
    setSettings((s) => ({ ...s, ...patch }));
  };

  return { settings, update };
}
