import type { Link } from "../lib/api";
import { formatDate, relative } from "../lib/format";
import { useI18n, type TKey } from "../lib/i18n";

const STATE_KEY: Record<Link["state"], TKey> = {
  active: "stateActive",
  expired: "stateExpired",
  revoked: "stateRevoked",
  used_up: "stateUsed_up",
  locked: "stateLocked",
};

/** A share link shown as a ticket: details on the left, downloads "punched" on the stub. */
export default function Ticket({ link, onRevoke }: { link: Link; onRevoke?: () => void }) {
  const { t, lang } = useI18n();
  const live = link.state === "active";
  const max = link.max_downloads;
  const showPunches = max !== null && max <= 20;
  return (
    <article className={`ticket${live ? "" : " dead"}`} aria-label={`${t("share")} ${t(STATE_KEY[link.state])}`}>
      <div className="ticket-body">
        <div className="row">
          <span className={`pill ${live ? "ok" : link.state === "locked" ? "bad" : ""}`}>
            {t(STATE_KEY[link.state])}
          </span>
          {link.password_protected && <span className="pill">{t("passwordProtected")}</span>}
        </div>
        <span className="small muted">
          {live ? `${t("expires")} ${relative(link.expires_at, lang)}` : `${t("expires")} ${formatDate(link.expires_at, lang)}`}
        </span>
        {live && onRevoke && (
          <div>
            <button className="btn danger small" onClick={onRevoke}>
              {t("revoke")}
            </button>
          </div>
        )}
      </div>
      <div className="ticket-stub">
        <strong>
          {link.download_count}
          {max !== null && <span className="muted">/{max}</span>}
        </strong>
        <span className="small muted">{t("downloads")}</span>
        {showPunches && (
          <div className="punches" aria-hidden="true">
            {Array.from({ length: max }, (_, i) => (
              <i key={i} className={i < link.download_count ? "used" : ""} />
            ))}
          </div>
        )}
      </div>
    </article>
  );
}
