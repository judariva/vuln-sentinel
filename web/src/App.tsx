import { lazy, Suspense, type ReactNode } from "react";
import { Route, Routes } from "react-router";
import { Layout } from "@/components/Layout";
import { Loading } from "@/components/States";
import { NotFoundPage } from "@/pages/NotFound";
import { TodayPage } from "@/pages/Today";
import { PATHS } from "@/routes";

// Solo Hoy va en el JS inicial. Las demás pantallas se descargan al abrirlas (T8b: presupuesto y
// Lighthouse); Recharts, solo con Métricas.
const MetricsPage = lazy(() => import("@/pages/Metrics").then((m) => ({ default: m.MetricsPage })));
const AlertDetailPage = lazy(() => import("@/pages/AlertDetail").then((m) => ({ default: m.AlertDetailPage })));
const SourcesPage = lazy(() => import("@/pages/Sources").then((m) => ({ default: m.SourcesPage })));
const AdminPage = lazy(() => import("@/pages/Admin").then((m) => ({ default: m.AdminPage })));

function Page({ children }: { children: ReactNode }) {
  return <Suspense fallback={<Loading />}>{children}</Suspense>;
}

export function App() {
  return (
    <Layout>
      <Routes>
        <Route path={PATHS.today} element={<TodayPage />} />
        <Route
          path={`${PATHS.detail}/:id`}
          element={
            <Page>
              <AlertDetailPage />
            </Page>
          }
        />
        <Route
          path={PATHS.metrics}
          element={
            <Page>
              <MetricsPage />
            </Page>
          }
        />
        <Route
          path={PATHS.sources}
          element={
            <Page>
              <SourcesPage />
            </Page>
          }
        />
        <Route
          path={PATHS.admin}
          element={
            <Page>
              <AdminPage />
            </Page>
          }
        />
        <Route path="*" element={<NotFoundPage />} />
      </Routes>
    </Layout>
  );
}
