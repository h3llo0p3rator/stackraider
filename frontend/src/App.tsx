import { useState } from "react";
import { BrowserRouter, Navigate, Route, Routes } from "react-router-dom";
import { Layout } from "@/components/Layout";
import { IntrospectionInput } from "@/components/IntrospectionInput";
import { SchemaExplorer } from "@/components/SchemaExplorer";
import { FindingsDashboard } from "@/components/FindingsDashboard";
import { QueryPanel } from "@/components/QueryPanel";
import { ChatPanel } from "@/components/ChatPanel";
import { ModelManager } from "@/components/ModelManager";
import { SettingsPanel } from "@/components/SettingsPanel";
import { AnalysisContext, useAnalysisContext } from "@/context/AnalysisContext";
import { CodeSessionProvider } from "@/context/CodeSessionContext";
import { ModelDownloadContext } from "@/context/ModelDownloadContext";
import { useAnalysis } from "@/hooks/useAnalysis";
import { useModelDownloads } from "@/hooks/useModelDownloads";
import { useSettings } from "@/hooks/useSettings";
import { ScanPage } from "@/routes/code/ScanPage";
import { ResultsPage } from "@/routes/code/ResultsPage";
import { BurpPage } from "@/routes/code/BurpPage";
import { AnalysisPage } from "@/routes/code/AnalysisPage";
import { CorrelationPage } from "@/routes/code/CorrelationPage";

function GraphqlAnalyzePage() {
  const { analyze, loading, status, error, cancel, logs, phase, findings, queries } = useAnalysisContext();
  return (
    <IntrospectionInput
      onAnalyze={analyze}
      loading={loading}
      status={status}
      error={error}
      onCancel={cancel}
      logs={logs}
      phase={phase}
      findingCount={findings.length}
      queryCount={queries.length}
    />
  );
}

function GraphqlSchemaPage() {
  const { schema } = useAnalysisContext();
  return <SchemaExplorer schema={schema} />;
}

function GraphqlFindingsPage() {
  const { findings, queries } = useAnalysisContext();
  return <FindingsDashboard findings={findings} queries={queries} />;
}

function GraphqlQueriesPage() {
  const { queries, loading, phase } = useAnalysisContext();
  const streaming = loading && (phase === "queries" || phase === "llm" || phase === "static");
  return <QueryPanel queries={queries} streaming={streaming} />;
}

export default function App() {
  const { settings, update } = useSettings();
  const analysis = useAnalysis(settings);
  const downloads = useModelDownloads(settings);
  const [chatOpen, setChatOpen] = useState(false);

  return (
    <CodeSessionProvider>
      <ModelDownloadContext.Provider value={downloads}>
        <AnalysisContext.Provider value={analysis}>
          <BrowserRouter>
            <Routes>
              <Route element={<Layout settings={settings} onOpenChat={() => setChatOpen(true)} />}>
                <Route index element={<Navigate to="/code/scan" replace />} />
                <Route path="code/scan" element={<ScanPage />} />
                <Route path="code/results" element={<ResultsPage />} />
                <Route path="code/burp" element={<BurpPage />} />
                <Route path="code/analysis" element={<AnalysisPage settings={settings} />} />
                <Route path="code/correlation" element={<CorrelationPage />} />
                <Route path="graphql" element={<GraphqlAnalyzePage />} />
                <Route path="graphql/schema" element={<GraphqlSchemaPage />} />
                <Route path="graphql/findings" element={<GraphqlFindingsPage />} />
                <Route path="graphql/queries" element={<GraphqlQueriesPage />} />
                <Route
                  path="models"
                  element={<ModelManager settings={settings} onSelectModel={(m) => update({ model: m })} />}
                />
                <Route path="settings" element={<SettingsPanel settings={settings} onUpdate={update} />} />
                <Route path="*" element={<Navigate to="/code/scan" replace />} />
              </Route>
            </Routes>
            <ChatPanel
              open={chatOpen}
              onClose={() => setChatOpen(false)}
              settings={settings}
              schema={analysis.schema}
              findings={analysis.findings}
              queries={analysis.queries}
            />
          </BrowserRouter>
        </AnalysisContext.Provider>
      </ModelDownloadContext.Provider>
    </CodeSessionProvider>
  );
}
