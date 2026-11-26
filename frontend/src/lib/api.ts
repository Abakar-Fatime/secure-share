export type Role = "admin" | "member" | "viewer";

export interface User {
  id: string;
  email: string;
  name: string;
  role: Role;
  status: "active" | "invited" | "disabled";
  mfa_enabled: boolean;
  google_linked: boolean;
  created_at: string;
  last_login_at?: string | null;
  session_mfa?: boolean;
}

export interface FileItem {
  id: string;
  name: string;
  size: number;
  content_type: string;
  status: string;
  owner_id: string;
  created_at: string;
  is_owner: boolean;
}

export interface Link {
  id: string;
  file_id: string;
  expires_at: string;
  max_downloads: number | null;
  download_count: number;
  password_protected: boolean;
  state: "active" | "expired" | "revoked" | "used_up" | "locked";
  created_at: string;
  url?: string;
}

export interface Grant {
  user_id: string;
  email: string;
  name: string;
  created_at?: string;
}

export interface AuditEvent {
  id: string;
  at: string;
  action: string;
  outcome: "success" | "failure";
  actor_id: string | null;
  actor_email: string | null;
  ip: string | null;
  country: string | null;
  target_type: string | null;
  target_id: string | null;
  details: Record<string, unknown> | null;
}

export interface Alert {
  id: string;
  at: string;
  rule: string;
  severity: "high" | "medium" | "low";
  title: string;
  reason: string;
  status: "open" | "resolved";
  subject: string;
  user_id?: string | null;
  resolved_by?: string;
  evidence?: Record<string, unknown>;
}

export interface Summary {
  days: string[];
  series: { logins: number[]; failed_logins: number[]; uploads: number[]; downloads: number[] };
  totals: {
    events: number;
    failed_logins: number;
    external_downloads: number;
    open_alerts: number;
    high_alerts: number;
  };
  top_users: [string, number][];
  countries: [string, number][];
  alerts_by_rule: [string, number][];
}

export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

function csrfToken(): string {
  const match = document.cookie.match(/(?:^|; )ss_csrf=([^;]+)/);
  return match ? decodeURIComponent(match[1]) : "";
}

async function ensureCsrf() {
  // The API sets the CSRF cookie on any response; fetch one if it is missing.
  if (!csrfToken()) await fetch("/api/health", { credentials: "same-origin" });
}

export async function api<T>(path: string, options: { method?: string; body?: unknown } = {}): Promise<T> {
  const method = options.method ?? "GET";
  const headers: Record<string, string> = { Accept: "application/json" };
  if (method !== "GET") {
    await ensureCsrf();
    headers["X-CSRF-Token"] = csrfToken();
  }
  if (options.body !== undefined) headers["Content-Type"] = "application/json";
  const res = await fetch(`/api${path}`, {
    method,
    headers,
    credentials: "same-origin",
    body: options.body === undefined ? undefined : JSON.stringify(options.body),
  });
  const data = res.status === 204 ? null : await res.json().catch(() => null);
  if (!res.ok) {
    const detail = data?.detail;
    const message = Array.isArray(detail)
      ? detail.map((d: { msg: string }) => d.msg).join(". ")
      : typeof detail === "string"
        ? detail
        : `Request failed (${res.status})`;
    throw new ApiError(res.status, message);
  }
  return data as T;
}

/** Upload straight to S3 with the presigned form the API returned, reporting progress. */
export function uploadToS3(
  upload: { url: string; fields: Record<string, string> },
  file: File,
  onProgress: (fraction: number) => void,
): Promise<void> {
  return new Promise((resolve, reject) => {
    const form = new FormData();
    Object.entries(upload.fields).forEach(([k, v]) => form.append(k, v));
    form.append("file", file);
    const xhr = new XMLHttpRequest();
    xhr.open("POST", upload.url);
    xhr.upload.onprogress = (e) => e.lengthComputable && onProgress(e.loaded / e.total);
    xhr.onload = () => (xhr.status < 300 ? resolve() : reject(new ApiError(xhr.status, "Upload was rejected by storage")));
    xhr.onerror = () => reject(new ApiError(0, "Network error while uploading"));
    xhr.send(form);
  });
}
