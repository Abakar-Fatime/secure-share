import { lazy, Suspense, type ReactNode } from "react";
import { Link, Navigate, Route, Routes } from "react-router-dom";
import Layout from "./components/Layout";
import { useAuth } from "./lib/auth";
import { useI18n } from "./lib/i18n";
import Files from "./pages/Files";
import Invite from "./pages/Invite";
import Login from "./pages/Login";
import PublicLink from "./pages/PublicLink";
import Shared from "./pages/Shared";

const Account = lazy(() => import("./pages/Account"));
const Audit = lazy(() => import("./pages/Audit"));
const People = lazy(() => import("./pages/People"));
const Security = lazy(() => import("./pages/Security"));

function RequireUser({ children }: { children: ReactNode }) {
  const { user, loading } = useAuth();
  const { t } = useI18n();
  if (loading) return <p className="empty">{t("loading")}</p>;
  if (!user) return <Navigate to="/login" replace />;
  return <Suspense fallback={<p className="empty">{t("loading")}</p>}>{children}</Suspense>;
}

function RequireAdmin({ children }: { children: ReactNode }) {
  const { user } = useAuth();
  const { t } = useI18n();
  if (user?.role !== "admin") return <Navigate to="/files" replace />;
  if (!user.session_mfa) {
    return (
      <div className="stack" style={{ maxWidth: 560 }}>
        <h1>{t("mfaSection")}</h1>
        <p className="notice">{t("mfaAdminNote")}</p>
        <div>
          <Link className="btn seal" to="/account">
            {t("navAccount")}
          </Link>
        </div>
      </div>
    );
  }
  return <>{children}</>;
}

function Home() {
  const { user } = useAuth();
  return <Navigate to={user?.role === "viewer" ? "/shared" : "/files"} replace />;
}

function NotFound() {
  const { t } = useI18n();
  return (
    <div className="stack">
      <h1>{t("notFoundTitle")}</h1>
      <div>
        <Link className="btn" to="/">
          {t("goHome")}
        </Link>
      </div>
    </div>
  );
}

export default function App() {
  return (
    <Routes>
      <Route path="/login" element={<Login />} />
      <Route path="/invite/:token" element={<Invite />} />
      <Route path="/s/:token" element={<PublicLink />} />
      <Route
        element={
          <RequireUser>
            <Layout />
          </RequireUser>
        }
      >
        <Route index element={<Home />} />
        <Route path="/files" element={<Files />} />
        <Route path="/shared" element={<Shared />} />
        <Route path="/account" element={<Account />} />
        <Route path="/admin/security" element={<RequireAdmin><Security /></RequireAdmin>} />
        <Route path="/admin/people" element={<RequireAdmin><People /></RequireAdmin>} />
        <Route path="/admin/audit" element={<RequireAdmin><Audit /></RequireAdmin>} />
        <Route path="*" element={<NotFound />} />
      </Route>
    </Routes>
  );
}
