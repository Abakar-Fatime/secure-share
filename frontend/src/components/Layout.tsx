import { Suspense, useEffect, useState } from "react";
import { Link, NavLink, Outlet, useNavigate } from "react-router-dom";
import { api, type Alert } from "../lib/api";
import { useAuth } from "../lib/auth";
import { useI18n } from "../lib/i18n";
import { LockIcon } from "./ui";

export default function Layout() {
  const { user, signOut } = useAuth();
  const { t, toggle } = useI18n();
  const navigate = useNavigate();
  const [openAlerts, setOpenAlerts] = useState(0);
  const isAdmin = user?.role === "admin";
  const adminReady = isAdmin && user?.session_mfa;

  useEffect(() => {
    if (!adminReady) return;
    api<Alert[]>("/admin/alerts?status=open")
      .then((a) => setOpenAlerts(a.length))
      .catch(() => setOpenAlerts(0));
  }, [adminReady]);

  if (!user) return null;

  return (
    <div className="shell">
      <aside className="sidebar guilloche">
        <Link to="/files" className="brand">
          <LockIcon size={28} />
          {t("appName")}
        </Link>
        <nav className="nav" aria-label="Main">
          {user.role !== "viewer" && <NavLink to="/files">{t("navFiles")}</NavLink>}
          <NavLink to="/shared">{t("navShared")}</NavLink>
          <NavLink to="/account">{t("navAccount")}</NavLink>
          {isAdmin && (
            <>
              <div className="group">Admin</div>
              <NavLink to="/admin/security">
                {t("navSecurity")}
                {openAlerts > 0 && <span className="badge-count">{openAlerts}</span>}
              </NavLink>
              <NavLink to="/admin/people">{t("navPeople")}</NavLink>
              <NavLink to="/admin/audit">{t("navAudit")}</NavLink>
            </>
          )}
        </nav>
        <div className="sidebar-foot">
          <span className="who">
            {user.name}
            <br />
            {user.email}
          </span>
          <button onClick={toggle} lang={t("language") === "Français" ? "fr" : "en"}>
            {t("language")}
          </button>
          <button
            onClick={async () => {
              await signOut();
              navigate("/login");
            }}
          >
            {t("signOut")}
          </button>
        </div>
      </aside>
      <main className="main">
        <Suspense fallback={null}>
          <Outlet />
        </Suspense>
      </main>
    </div>
  );
}
