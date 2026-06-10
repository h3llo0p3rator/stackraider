import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useState,
  type ReactNode,
} from "react";
import {
  getBurpTraffic,
  getScanResult,
  getSession,
  type ScanResult,
  type SessionInfo,
} from "@/lib/codeApi";

type BurpTraffic = {
  summary: { total: number; matched_routes: number };
  transactions: unknown[];
};

type CodeSessionValue = {
  session: SessionInfo | null;
  scanResult: ScanResult | null;
  burpTraffic: BurpTraffic | null;
  refresh: () => Promise<void>;
  setScanResult: (r: ScanResult) => void;
  setBurpTraffic: (t: BurpTraffic) => void;
};

const CodeSessionContext = createContext<CodeSessionValue | null>(null);

export function CodeSessionProvider({ children }: { children: ReactNode }) {
  const [session, setSession] = useState<SessionInfo | null>(null);
  const [scanResult, setScanResult] = useState<ScanResult | null>(null);
  const [burpTraffic, setBurpTraffic] = useState<BurpTraffic | null>(null);

  const refresh = useCallback(async () => {
    try {
      const s = await getSession();
      setSession(s);
      if (s.has_scan) {
        const r = await getScanResult();
        setScanResult(r);
      }
      if (s.has_burp) {
        const t = await getBurpTraffic();
        setBurpTraffic(t);
      }
    } catch {
      // fresh session
    }
  }, []);

  useEffect(() => {
    refresh();
  }, [refresh]);

  return (
    <CodeSessionContext.Provider
      value={{ session, scanResult, burpTraffic, refresh, setScanResult, setBurpTraffic }}
    >
      {children}
    </CodeSessionContext.Provider>
  );
}

export function useCodeSession() {
  const ctx = useContext(CodeSessionContext);
  if (!ctx) throw new Error("useCodeSession outside provider");
  return ctx;
}
