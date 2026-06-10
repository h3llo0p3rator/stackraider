import { createContext, useContext } from "react";
import type { useAnalysis } from "@/hooks/useAnalysis";

type AnalysisContextValue = ReturnType<typeof useAnalysis>;

export const AnalysisContext = createContext<AnalysisContextValue | null>(null);

export function useAnalysisContext() {
  const ctx = useContext(AnalysisContext);
  if (!ctx) throw new Error("useAnalysisContext must be used within provider");
  return ctx;
}
