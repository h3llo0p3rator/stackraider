import { createContext, useContext } from "react";
import type { useModelDownloads } from "@/hooks/useModelDownloads";

type ModelDownloadContextValue = ReturnType<typeof useModelDownloads>;

export const ModelDownloadContext = createContext<ModelDownloadContextValue | null>(null);

export function useModelDownloadContext() {
  const ctx = useContext(ModelDownloadContext);
  if (!ctx) throw new Error("useModelDownloadContext must be used within provider");
  return ctx;
}
