# Google Drive data source

The `google_drive` connector imports selected folders and files from a Google account: My Drive, items shared with the account and shared drives. Google Docs, Sheets and Slides are exported to formats WeKnora can parse. Synchronization is scheduled, incremental and resumable, and reconciles deletions. See [Data source synchronization](10-datasource.md) for common scheduling and conflict settings.

Access is read-only and is granted by signing in at Google. WeKnora never sees the account password; it stores a refresh token that the account owner can revoke at any time.

## Create an OAuth client in Google Cloud

Each deployment uses its own OAuth client. Creating one takes a few minutes and is free.

1. Open [Google Cloud Console](https://console.cloud.google.com/), create or pick a project, and enable the **Google Drive API** under **APIs & Services → Library**.
2. Configure the consent screen under **APIs & Services → OAuth consent screen**. For accounts in your own Google Workspace choose the **Internal** user type. Otherwise choose **External** and add the accounts that will connect as **Test users**.
3. Under **APIs & Services → Credentials** create an **OAuth client ID** of type **Web application**.
4. Add the **Authorized redirect URI** shown in the WeKnora dialog. It is the address users open WeKnora at, followed by `/api/v1/datasource-oauth/callback`, for example `https://kb.example.com/api/v1/datasource-oauth/callback`. Google compares it exactly, including scheme, host and port.
5. Copy the client ID and client secret.

> **Refresh tokens of a consent screen in "Testing" status expire after 7 days** when the user type is External. The data source then fails with an invalid-credentials error until it is reconnected. Publish the app ("In production") or use the Internal user type for unattended synchronization. `drive.readonly` is a restricted scope, so a published External app shows an "unverified app" warning until Google has verified it; for a self-hosted deployment used by your own accounts that warning can be accepted.

Official references: [OAuth 2.0 for web server applications](https://developers.google.com/identity/protocols/oauth2/web-server) and [Drive API scopes](https://developers.google.com/workspace/drive/api/guides/api-specific-auth).

## Configure in WeKnora

1. Open **Knowledge base settings → Data sources → Add**, then choose **Google Drive**.
2. Enter the OAuth client ID and client secret.
3. Click **Connect Google Drive**. A window opens at Google; sign in with the account whose files should be synchronized and grant read access. The dialog then shows the connected account.
4. Expand the resource tree and select at least one folder or file. The top level lists **My Drive**, **Shared with me** and every shared drive the account is a member of. A selected folder includes future descendants.
5. Choose the sync schedule, conflict policy and **Sync deletions** setting. Save and manually sync a small folder first.

The connection belongs to the data source, not to the WeKnora user who made it: every member of the workspace searches the synchronized documents. Connect an account that may share those files with the whole workspace.

Changing the client ID or secret requires connecting again. **Reconnect** renews the grant with the stored client; **Disconnect** revokes the token at Google and removes it from WeKnora while keeping the client values.

## How authorization works

The data source stores the OAuth client and, after authorization, a refresh token together with the account's email and ID. All of it lives in the existing encrypted data-source credential JSON; API responses expose only whether the source is connected and to which account.

| Endpoint | Purpose |
| --- | --- |
| `POST /api/v1/datasource/{id}/oauth/authorize-url` | Returns the Google URL to open and an attempt ID |
| `GET /api/v1/datasource-oauth/callback` | Public redirect target; exchanges the code and stores the grant |
| `GET /api/v1/datasource/{id}/oauth/status` | Connection status; with `authorization_attempt`, the status of that attempt only |
| `DELETE /api/v1/datasource/{id}/oauth/token` | Revokes and removes the grant |

The callback is unauthenticated because the browser arrives from Google without a WeKnora session. It is protected by a random single-use `state` value that expires after 10 minutes and by PKCE (S256); the code verifier never leaves the server. In-flight authorizations are kept in Redis when available, so the callback may reach any replica, and in memory otherwise. The redirect URI must be this deployment's callback route, and the page the browser returns to must be a path inside the application.

The flow is implemented once for all connectors (`datasource.OAuthConnector`); Google Drive is its first user.

## What is synchronized

| Drive item | Result |
| --- | --- |
| File with a supported extension | Downloaded as is |
| Google Docs | Exported as Markdown (`.md`) |
| Google Sheets | Exported as Excel (`.xlsx`) |
| Google Slides | Exported as PowerPoint (`.pptx`) |
| Forms, Drawings, Sites, Apps Script, Vids and other editor formats | Skipped |
| Shortcuts | Skipped; select the target itself |
| Items in the trash | Skipped |
| Files with unsupported extensions | Skipped |

Supported extensions follow `internal/utils/import_filetypes.go`, the same list used for knowledge uploads. Knowledge files keep the Drive hierarchy under `Google Drive/`, starting at the selected folder, so the folder structure is mirrored in the knowledge base.

## Incremental synchronization and deletion

Documents are identified by their Drive file ID, which survives renames and moves. Each run lists the complete selected scope; unchanged files are not downloaded.

| Source change | Result |
| --- | --- |
| Added file | Downloaded and imported |
| Edited file | Downloaded and replaced |
| Binary file touched without a content change | Skipped: binary files are compared by Drive's MD5 checksum |
| Renamed or moved inside the selection | Replaced under the new path; the document keeps its identity |
| Deleted, trashed or moved outside the selection | Removed after a complete successful scan, if **Sync deletions** is on |
| Selected folder deleted or trashed | The run continues; documents from that folder are reconciled as deletions |
| Different Google account connected | The existing cursor is rejected; create a new data source |
| Same account reconnected | Cursor and document identities are kept |

Google editor files have no checksum, so they are compared by modification time.

Replacing a document re-parses and re-indexes it, and regenerates what was derived from it: graph entities and wiki pages built only from that document are rebuilt, including manual edits to those pages.

The connector holds one file body at a time. Checkpoints contain the complete cursor and are saved every 50 changes, before deletions and at completion, so an interrupted run resumes from acknowledged items. A forced full sync re-downloads everything while keeping the previous state as its deletion baseline.

A folder that cannot be listed, a traversal limit and exhausted quota stop the run without deleting anything: an incomplete scan is never taken as evidence that files are gone. Per-file failures produce localized error items; the other files continue and failed ones are retried on the next run.

## Limits and errors

- Files use `MAX_FILE_SIZE_MB` (default **50 MiB**). Larger files are rejected before download.
- The Drive API exports at most **10 MB** per Google editor file. Larger documents are reported as `google_drive_export_too_large`; split the document or store it as a regular file.
- Downloads are verified against the size and MD5 checksum Drive listed; a mismatch is retried on the next run.
- Rate limits (`429`, and `403` with a rate-limit reason) and server errors are retried up to 5 times with exponential backoff, honoring `Retry-After`. When the quota stays exhausted the run stops and the next one continues from the last checkpoint.
- A run lists at most **1,000,000** entries and descends at most **256** folder levels.
- Requests go only to `www.googleapis.com`, `accounts.google.com` and `oauth2.googleapis.com` through the shared SSRF-aware HTTP client. Outbound access to these hosts is required; no `SSRF_WHITELIST` entry is needed.

Sync error codes are `google_drive_permission_denied`, `google_drive_not_found`, `google_drive_file_too_large`, `google_drive_export_too_large`, `google_drive_empty_file`, `google_drive_rate_limited` and `google_drive_fetch_failed`. A revoked or expired grant is reported at the data-source level as invalid credentials. Google's response bodies, tokens and the client secret are never included in connector errors.

## Verification

Unit tests use an in-process Drive and OAuth server and need no Google account:

```bash
go test ./internal/datasource/connector/googledrive ./internal/datasource -count=1
go test ./internal/application/service ./internal/handler -run DataSourceOAuth -count=1
```
