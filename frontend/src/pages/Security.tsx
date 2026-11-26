import { useState } from "react";
import { Bar, CartesianGrid, ComposedChart, Legend, Line, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { ErrorText, useAsync, useToast } from "../components/ui";
import { api, type Alert, type Summary } from "../lib/api";
import { formatDate, formatDay } from "../lib/format";
import { useI18n, type TKey } from "../lib/i18n";

const SEVERITY_KEY: Record<Alert["severity"], TKey> = { high: "severityHigh", medium: "severityMedium", low: "severityLow" };

function BarList({ title, rows }: { title: string; rows: [string, number][] }) {
  const max = Math.max(1, ...rows.map((r) => r[1]));
  return (
    <section className="section stack">
      <h3>{title}</h3>
      <div className="barlist">
        {rows.map(([label, n]) => (
          <div key={label}>
            <span>{label}</span>
            <span className="muted">{n}</span>
            <span className="track">
              <i style={{ width: `${(n / max) * 100}%` }} />
            </span>
          </div>
        ))}
      </div>
    </section>
  );
}

export default function Security() {
  const { t, lang } = useI18n();
  const toast = useToast();
  const summary = useAsync(() => api<Summary>("/admin/summary?days=14"), []);
  const alerts = useAsync(() => api<Alert[]>("/admin/alerts"), []);
  const [showResolved, setShowResolved] = useState(false);

  const s = summary.data;
  const chart = s?.days.map((d, i) => ({
    day: formatDay(d, lang),
    [t("logins")]: s.series.logins[i],
    [t("downloadsLabel")]: s.series.downloads[i],
    [t("uploads")]: s.series.uploads[i],
    [t("failed")]: s.series.failed_logins[i],
  }));
  const visible = (alerts.data ?? []).filter((a) => showResolved || a.status === "open");

  async function resolve(id: string) {
    try {
      await api(`/admin/alerts/${id}/resolve`, { method: "POST" });
      toast(t("resolved"));
      alerts.reload();
      summary.reload();
    } catch (e) {
      toast((e as Error).message);
    }
  }

  return (
    <>
      <div className="page-head">
        <div>
          <h1>{t("securityTitle")}</h1>
          <p className="muted">{t("last14")}</p>
        </div>
      </div>
      <ErrorText error={summary.error ?? alerts.error} />
      {s && (
        <div className="stats">
          <div className={`stat${s.totals.open_alerts ? " alarm" : ""}`}>
            <b>{s.totals.open_alerts}</b>
            <span className="small muted">{t("openAlerts")}</span>
          </div>
          <div className={`stat${s.totals.high_alerts ? " alarm" : ""}`}>
            <b>{s.totals.high_alerts}</b>
            <span className="small muted">{t("highAlerts")}</span>
          </div>
          <div className="stat">
            <b>{s.totals.failed_logins}</b>
            <span className="small muted">{t("failedLogins")}</span>
          </div>
          <div className="stat">
            <b>{s.totals.external_downloads}</b>
            <span className="small muted">{t("externalDownloads")}</span>
          </div>
        </div>
      )}

      <div className="grid-2">
        <div className="sheet">
          <section className="section row">
            <h2>{t("alerts")}</h2>
            <span className="spacer" />
            <label className="row" style={{ display: "flex", fontWeight: 500 }}>
              <input type="checkbox" checked={showResolved} onChange={(e) => setShowResolved(e.target.checked)} />
              {t("showResolved")}
            </label>
          </section>
          {alerts.data && visible.length === 0 && <p className="empty">{t("alertsEmpty")}</p>}
          <div style={{ borderTop: visible.length ? "1px solid var(--rule)" : 0 }}>
            {visible.map((a) => (
              <article key={a.id} className={`alert-item ${a.severity}${a.status === "resolved" ? " resolved" : ""}`}>
                <span className="bar" aria-hidden="true" />
                <div className="stack" style={{ gap: 6 }}>
                  <div className="row">
                    <strong>{a.title}</strong>
                    <span className={`pill ${a.severity === "high" ? "bad" : a.severity === "medium" ? "warn" : ""}`}>
                      {t(SEVERITY_KEY[a.severity])}
                    </span>
                    <span className="small muted">{formatDate(a.at, lang)}</span>
                  </div>
                  <p className="muted">{a.reason}</p>
                  {a.status === "open" ? (
                    <div>
                      <button className="btn ghost small" onClick={() => resolve(a.id)}>
                        {t("resolve")}
                      </button>
                    </div>
                  ) : (
                    <span className="small muted">
                      {t("resolved")} ({a.resolved_by})
                    </span>
                  )}
                </div>
              </article>
            ))}
          </div>
        </div>

        <div className="stack" style={{ gap: 20 }}>
          {chart && (
            <div className="sheet">
              <section className="section stack">
                <h3>{t("activityChart")}</h3>
                <div style={{ height: 220 }}>
                  <ResponsiveContainer>
                    <ComposedChart data={chart} margin={{ left: -24, right: 4, top: 4 }}>
                      <CartesianGrid stroke="#eceff4" vertical={false} />
                      <XAxis dataKey="day" tick={{ fontSize: 11, fill: "#7a8299" }} interval={2} tickLine={false} />
                      <YAxis tick={{ fontSize: 11, fill: "#7a8299" }} allowDecimals={false} tickLine={false} axisLine={false} />
                      <Tooltip />
                      <Legend wrapperStyle={{ fontSize: 12 }} />
                      <Bar dataKey={t("downloadsLabel")} fill="#9fd8c6" />
                      <Bar dataKey={t("uploads")} fill="#1f6f5c" />
                      <Line dataKey={t("logins")} stroke="#18213b" strokeWidth={2} dot={false} />
                      <Line dataKey={t("failed")} stroke="#b7412e" strokeWidth={2} dot={false} />
                    </ComposedChart>
                  </ResponsiveContainer>
                </div>
              </section>
            </div>
          )}
          {s && (
            <div className="sheet">
              <BarList title={t("topCountries")} rows={s.countries} />
              <BarList title={t("topUsers")} rows={s.top_users} />
            </div>
          )}
        </div>
      </div>
    </>
  );
}
