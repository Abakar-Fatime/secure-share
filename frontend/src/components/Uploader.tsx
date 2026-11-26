import { useRef, useState, type DragEvent } from "react";
import { api, uploadToS3, type FileItem } from "../lib/api";
import { useI18n } from "../lib/i18n";
import { ErrorText, useToast } from "./ui";

interface Pending {
  name: string;
  progress: number;
}

export default function Uploader({ onUploaded }: { onUploaded: () => void }) {
  const { t } = useI18n();
  const toast = useToast();
  const input = useRef<HTMLInputElement>(null);
  const [over, setOver] = useState(false);
  const [pending, setPending] = useState<Pending[]>([]);
  const [error, setError] = useState<string | null>(null);

  async function uploadOne(file: File) {
    setPending((p) => [...p, { name: file.name, progress: 0 }]);
    const update = (progress: number) =>
      setPending((p) => p.map((x) => (x.name === file.name ? { ...x, progress } : x)));
    try {
      const { file: meta, upload } = await api<{ file: FileItem; upload: { url: string; fields: Record<string, string> } }>(
        "/files/upload-url",
        { method: "POST", body: { name: file.name, size: file.size, content_type: file.type || "application/octet-stream" } },
      );
      await uploadToS3(upload, file, update);
      await api(`/files/${meta.id}/complete`, { method: "POST" });
      toast(`${t("uploaded")}: ${file.name}`);
      onUploaded();
    } catch (e) {
      setError(`${file.name}: ${(e as Error).message}`);
    } finally {
      setPending((p) => p.filter((x) => x.name !== file.name));
    }
  }

  function handle(files: FileList | null) {
    setError(null);
    Array.from(files ?? []).forEach(uploadOne);
  }

  function onDrop(e: DragEvent) {
    e.preventDefault();
    setOver(false);
    handle(e.dataTransfer.files);
  }

  return (
    <div className="stack" style={{ gap: 10, marginBottom: 20 }}>
      <div
        className={`drop${over ? " over" : ""}`}
        onDragOver={(e) => {
          e.preventDefault();
          setOver(true);
        }}
        onDragLeave={() => setOver(false)}
        onDrop={onDrop}
      >
        <svg width="34" height="34" viewBox="0 0 24 24" aria-hidden="true">
          <path d="M12 16V4m0 0-4.5 4.5M12 4l4.5 4.5M4 15v3a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-3" fill="none" stroke="#1f6f5c" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" />
        </svg>
        <div>
          <p>
            {t("dropHere")}{" "}
            <button className="linklike" onClick={() => input.current?.click()}>
              {t("chooseFiles")}
            </button>
          </p>
          <p className="small muted">{t("maxSize")}</p>
        </div>
        <input ref={input} type="file" multiple hidden onChange={(e) => handle(e.target.files)} data-testid="file-input" />
      </div>
      {pending.map((p) => (
        <div key={p.name} className="stack" style={{ gap: 4 }}>
          <span className="small">
            {t("uploading")} {p.name}
          </span>
          <div className="progress" role="progressbar" aria-valuenow={Math.round(p.progress * 100)} aria-valuemin={0} aria-valuemax={100}>
            <span style={{ width: `${p.progress * 100}%` }} />
          </div>
        </div>
      ))}
      <ErrorText error={error} />
    </div>
  );
}
