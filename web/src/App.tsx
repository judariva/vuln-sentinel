import { lazy, Suspense } from "react";
import { Route, Routes } from "react-router";
import { Layout } from "@/components/Layout";
import { Loading } from "@/components/States";
import { AdminPage } from "@/pages/Admin";
import { AlertDetailPage } from "@/pages/AlertDetail";
import { NotFoundPage } from "@/pages/NotFound";
import { SourcesPage } from "@/pages/Sources";
import { TodayPage } from "@/pages/Today";

// Las gráficas (Recharts) solo se descargan al abrir Métricas.
const MetricsPage = lazy(() => import("@/pages/Metrics").then((m) => ({ default: m.MetricsPage })));

export function App() {
  return (
    <Layout>
      <Routes>
        <Route path="/" element={<TodayPage />} />
        <Route path="/alertas/:id" element={<AlertDetailPage />} />
        <Route
          path="/metricas"
          element={
            <Suspense fallback={<Loading />}>
              <MetricsPage />
            </Suspense>
          }
        />
        <Route path="/fuentes" element={<SourcesPage />} />
        <Route path="/admin" element={<AdminPage />} />
        <Route path="*" element={<NotFoundPage />} />
      </Routes>
    </Layout>
  );
}
