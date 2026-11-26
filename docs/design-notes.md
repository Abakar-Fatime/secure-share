# Design notes

How the main flows work, and why the system is built this way.

## Three flows, step by step

### Signing in with two-step verification

1. The browser sends email and password to `POST /api/auth/login`, with the CSRF token from the `ss_csrf` cookie copied into the `X-CSRF-Token` header.
2. The API checks the lock first: five failures for this email in the last 15 minutes (since the last successful login) means "try again later".
3. The password is verified against its Argon2id hash. If the email does not exist, a dummy hash is checked anyway so both cases take the same time and return the same message.
4. If two-step verification is on, the API does **not** create a session yet. It sets a short-lived (5 minutes) signed `ss_mfa` cookie that only says "this person passed the password step".
5. The browser sends the 6-digit code to `POST /api/auth/mfa/verify`. The API computes the TOTP code for the current 30-second window (and one window either side for clock drift) and compares in constant time. It then records the window number on the user; a code from the same or an earlier window is refused, so an intercepted code cannot be reused.
6. Now the session cookie is set: a signed JWT (HS256) with the user ID, a `token_version`, and whether two-step verification was passed. It is `HttpOnly`, `Secure` and `SameSite=Lax`.
7. Every later request reloads the user and compares `token_version`. Changing a password or role bumps the version, which ends all other sessions immediately, even though JWTs are stateless.

### Uploading a file

1. `POST /api/files/upload-url` with name, size and type. The API checks the role (viewers cannot upload) and the size limit, records the file as `pending`, and asks S3 for a **presigned POST** policy. The policy fixes the exact object key and the allowed size range, and expires in 5 minutes.
2. The browser uploads straight to S3 with that policy. The file bytes never touch Lambda, so large files do not hit Lambda's payload limits or cost compute time.
3. `POST /api/files/{id}/complete`: the API checks the object really exists in S3, reads its real size, marks the file `ready`, and writes an audit event.

### Someone outside downloads through a link

1. The owner creates a link. The API generates 32 random bytes as the token, stores only its **SHA-256 hash**, and returns the full URL once. Anyone reading the database cannot rebuild working links.
2. The visitor opens `/s/<token>`. The page calls `GET /api/public/links/<token>`; the API hashes the token, finds the link and checks it is not revoked, expired, locked or used up.
3. On download, a wrong password increments a counter; at 5 the link locks and an alert is raised. Otherwise the download count is incremented with a **conditional DynamoDB update** (`download_count < max_downloads`), so two visitors clicking at the same moment cannot both take the last download.
4. The API returns a presigned GET URL valid for 60 seconds, forcing `Content-Disposition: attachment` so a file is downloaded rather than rendered by the browser.

## Decisions and trade-offs

**DynamoDB instead of PostgreSQL.** The access patterns are known in advance (a user's files, a file's links, a day's audit events, a person's recent events), which suits a single-table design with one secondary index. It needs no network setup: a relational database would sit in a VPC, and Lambda would then need a NAT gateway to reach Google and S3, which costs more than the rest of the app combined. The cost is that ad-hoc queries are harder; the admin summary reads day partitions and aggregates in Python, which is fine at this scale but would move to a stream into an analytics store for a large organisation.

**Lambda behind CloudFront.** Pay-per-request fits a tool that is idle most of the day. CloudFront serves the app and the API from one HTTPS address, so cookies are first-party and the API needs no CORS. Because API Gateway is still publicly reachable, CloudFront adds a secret header and the API rejects requests without it; otherwise a caller could bypass CloudFront and forge the viewer IP and country headers the detector relies on.

**Cookies, not tokens in localStorage.** An `HttpOnly` cookie cannot be read by injected JavaScript. Cookies bring CSRF risk, handled by `SameSite=Lax` plus a double-submit token on every state-changing request.

**Rules, not a machine-learning model, for detection.** Admins need to know *why* something was flagged, and there is no labelled history of attacks to train on. Each rule is explainable, testable and cheap to run on every event. The download rule still adapts to each person by comparing with their own two-week baseline (mean + 4 standard deviations, at least 20 per hour). The evaluation script measures the trade-off honestly, including attacks designed to evade the thresholds.

**Invite-only accounts.** A file-sharing tool for an organisation should not let anyone sign up. Google sign-in only links to accounts an admin already created, matched by verified email.

## What I would add next

- Malware scanning of uploads (S3 event → scanning Lambda) before files become downloadable.
- Encrypting TOTP secrets with KMS rather than relying on DynamoDB's encryption at rest.
- Daily per-person download totals to catch the slow exfiltration the current hourly rule misses.
- Email notifications for high-severity alerts (Amazon SES).
- Passkeys (WebAuthn) as a phishing-resistant second factor.
