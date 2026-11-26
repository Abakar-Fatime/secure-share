import { useState } from "react";
import { ErrorText, useAsync } from "../components/ui";
import { api, type AuditEvent } from "../lib/api";
import { ACTION_LABELS, useI18n } from "../lib/i18n";

function today() {
  return new Date().toISOString().slice(0, 10);
}

export default function Audit() {
  const { t, lang, action } = useI18n();
  const [day, setDay] = useState(today());
  const [act, setAct] = useState("");
  const [actor, setActor] = useState("");
  const [outcome, setOutcome] = useState("");
  const params = new URLSearchParams({ day });
  if (act) params.set("action", act);
  if (actor) params.set("actor", actor);
  if (outcome) params.set("outcome", outcome);
  const qs = params.toString();
  const log = useAsync(() => api<{ events: AuditEvent[] }>(`/admin/audit?${qs}`), [qs]);
  const events = log.data?.events ?? [];

  return (
    <>
      <div className="page-head">
        <h1>{t("auditTitle")}</h1>
      </div>
      <div className="row" style={{ marginBottom: 16, alignItems: "end" }}>
        <label>
          {t("day")}
          <input type="date" value={day} max={today()} onChange={(e) => setDay(e.target.value || today())} />
        </label>
        <label>
          {t("filterAction")}
          <select value={act} onChange={(e) => setAct(e.target.value)}>
            <option value="">{t("all")}</option>
            {Object.keys(ACTION_LABELS).map((a) => (
              <option key={a} value={a}>
                {action(a)}
              </option>
            ))}
          </select>
        </label>
        <label>
          {t("filterPerson")}
          <input type="search" placeholder="name@…" value={actor} onChange={(e) => setActor(e.target.value)} />
        </label>
        <label>
          {t("filterOutcome")}
          <select value={outcome} onChange={(e) => setOutcome(e.target.value)}>
            <option value="">{t("all")}</option>
            <option value="success">{t("success")}</option>
            <option value="failure">{t("failure")}</option>
          </select>
        </label>
      </div>
      <ErrorText error={log.error} />
      <div className="sheet" style={{ overflowX: "auto" }}>
        {log.loading && !log.data ? (
          <p className="empty">{t("loading")}</p>
        ) : events.length === 0 ? (
          <p className="empty">{t("auditEmpty")}</p>
        ) : (
          <table className="table">
            <thead>
              <tr>
                <th>{t("when")}</th>
                <th>{t("who")}</th>
                <th>{t("what")}</th>
                <th>{t("where")}</th>
              </tr>
            </thead>
            <tbody>
              {events.map((e) => {
                const detailName = (e.details?.name ?? e.details?.email ?? e.details?.to) as string | undefined;
                return (
                  <tr key={e.id}>
                    <td className="muted" style={{ whiteSpace: "nowrap" }}>
                      {new Date(e.at).toLocaleTimeString(lang === "fr" ? "fr-FR" : "en-GB")}
                    </td>
                    <td>{e.actor_email ?? <span className="muted">{t("anonymous")}</span>}</td>
                    <td>
                      {action(e.action)}
                      {e.outcome === "failure" && <span className="pill bad" style={{ marginLeft: 8 }}>{t("failure")}</span>}
                      {detailName && <div className="small muted">{detailName}</div>}
                    </td>
                    <td className="muted" style={{ whiteSpace: "nowrap" }}>
                      {e.country ? `${e.country} ` : ""}
                      {e.ip}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </div>
    </>
  );
}
