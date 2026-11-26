import { useEffect, useRef, useState, type FormEvent } from "react";
import { api, type FileItem, type Grant, type Link } from "../lib/api";
import { formatBytes } from "../lib/format";
import { useI18n } from "../lib/i18n";
import Ticket from "./Ticket";
import { copyText, ErrorText, FileBadge, useAsync, useToast } from "./ui";

export default function ShareDrawer({ file, onClose }: { file: FileItem; onClose: () => void }) {
  const { t } = useI18n();
  const toast = useToast();
  const closeRef = useRef<HTMLButtonElement>(null);
  const grants = useAsync(() => api<Grant[]>(`/files/${file.id}/grants`), [file.id]);
  const links = useAsync(() => api<Link[]>(`/files/${file.id}/links`), [file.id]);

  const [email, setEmail] = useState("");
  const [grantError, setGrantError] = useState<string | null>(null);
  const [hours, setHours] = useState(24);
  const [maxDownloads, setMaxDownloads] = useState("");
  const [password, setPassword] = useState("");
  const [linkError, setLinkError] = useState<string | null>(null);
  const [fresh, setFresh] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    closeRef.current?.focus();
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  async function addGrant(e: FormEvent) {
    e.preventDefault();
    setGrantError(null);
    try {
      await api(`/files/${file.id}/grants`, { method: "POST", body: { email } });
      setEmail("");
      grants.reload();
    } catch (err) {
      setGrantError((err as Error).message);
    }
  }

  async function createLink(e: FormEvent) {
    e.preventDefault();
    setLinkError(null);
    setBusy(true);
    try {
      const link = await api<Link>(`/files/${file.id}/links`, {
        method: "POST",
        body: {
          expires_in_hours: hours,
          max_downloads: maxDownloads ? Number(maxDownloads) : null,
          password: password || null,
        },
      });
      setFresh(link.url ?? null);
      setPassword("");
      links.reload();
    } catch (err) {
      setLinkError((err as Error).message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <div className="scrim" onClick={onClose} />
      <aside className="drawer" role="dialog" aria-modal="true" aria-labelledby="share-title">
        <div className="drawer-head">
          <FileBadge name={file.name} />
          <div className="stack" style={{ gap: 2, flex: 1 }}>
            <h2 id="share-title">{file.name}</h2>
            <span className="small muted">{formatBytes(file.size)}</span>
          </div>
          <button ref={closeRef} className="btn ghost small" onClick={onClose}>
            {t("close")}
          </button>
        </div>

        <section className="sheet section stack">
          <div>
            <h3>{t("colleagues")}</h3>
            <p className="small muted">{t("colleaguesHelp")}</p>
          </div>
          <form className="row" onSubmit={addGrant}>
            <input
              type="email"
              required
              placeholder={t("colleagueEmail")}
              aria-label={t("colleagueEmail")}
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              style={{ flex: 1 }}
            />
            <button className="btn">{t("addPerson")}</button>
          </form>
          <ErrorText error={grantError} />
          {grants.data && grants.data.length === 0 && <p className="small muted">{t("noColleagues")}</p>}
          {grants.data?.map((g) => (
            <div key={g.user_id} className="row">
              <div style={{ flex: 1 }}>
                <strong>{g.name}</strong> <span className="small muted">{g.email}</span>
              </div>
              <button
                className="btn danger small"
                onClick={async () => {
                  await api(`/files/${file.id}/grants/${g.user_id}`, { method: "DELETE" });
                  grants.reload();
                }}
              >
                {t("remove")}
              </button>
            </div>
          ))}
        </section>

        <section className="sheet section stack">
          <div>
            <h3>{t("publicLinks")}</h3>
            <p className="small muted">{t("publicLinksHelp")}</p>
          </div>
          <form className="stack" onSubmit={createLink}>
            <div className="row" style={{ alignItems: "end" }}>
              <label style={{ flex: 1 }}>
                {t("expiresIn")}
                <select value={hours} onChange={(e) => setHours(Number(e.target.value))}>
                  <option value={1}>{t("hours1")}</option>
                  <option value={24}>{t("hours24")}</option>
                  <option value={168}>{t("hours168")}</option>
                  <option value={720}>{t("hours720")}</option>
                </select>
              </label>
              <label style={{ flex: 1 }}>
                {t("maxDownloads")}
                <input
                  type="number"
                  min={1}
                  max={1000}
                  placeholder={t("unlimited")}
                  value={maxDownloads}
                  onChange={(e) => setMaxDownloads(e.target.value)}
                />
              </label>
            </div>
            <label>
              {t("linkPassword")}
              <input
                type="password"
                autoComplete="new-password"
                minLength={4}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
              />
            </label>
            <div>
              <button className="btn seal" disabled={busy}>
                {t("createLink")}
              </button>
            </div>
          </form>
          <ErrorText error={linkError} />
          {fresh && (
            <div className="stack" style={{ gap: 6 }}>
              <p className="notice">{t("linkOnce")}</p>
              <div className="fresh-link">
                <input readOnly value={fresh} aria-label="Share link" onFocus={(e) => e.target.select()} />
                <button
                  className="btn"
                  onClick={async () => toast((await copyText(fresh)) ? t("copied") : fresh)}
                >
                  {t("copy")}
                </button>
              </div>
            </div>
          )}
          {links.data && links.data.length === 0 && <p className="small muted">{t("noLinks")}</p>}
          <div className="stack" style={{ gap: 10 }}>
            {links.data?.map((l) => (
              <Ticket
                key={l.id}
                link={l}
                onRevoke={async () => {
                  await api(`/links/${l.id}`, { method: "DELETE" });
                  links.reload();
                }}
              />
            ))}
          </div>
        </section>
      </aside>
    </>
  );
}
