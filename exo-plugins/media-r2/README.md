# exo.media.r2 — Cloudflare R2 media storage for Launch CMS

Storage adapter `exo.media.r2.storage` (roles `original`, `variant`, serving mode `signed-redirect`).

- **Uploads:** `beginWrite` returns one SigV4-presigned `PUT` (15 min, `UNSIGNED-PAYLOAD`, only `host` signed). The CMS host streams the bytes; nothing crosses the QuickJS sandbox.
- **Reads:** pages emit `/_instatic/media/exo.media.r2.storage/<key>`; the host calls `getReadUrl` per request and 302s to a presigned `GET` (≤ 1 h). The bucket stays private.
- **Delete / abort / verify:** presigned `DELETE` / `PUT` probe through the sandbox `fetch` (`network.outbound`, allowlist `*.r2.cloudflarestorage.com`). Delete is idempotent.
- **SigV4** is plain JS in `server/sigv4.ts` on top of the sandbox's `crypto.subtle` (SHA-256 digest + HMAC), path-style, region `auto`.

## Settings

| Setting | Value |
|---|---|
| S3 endpoint | `https://<account-id>.r2.cloudflarestorage.com` (no bucket) |
| Bucket | `exo-media` |
| Access key ID / Secret access key | R2 API token with Object Read & Write on the bucket (secret is encrypted at rest by the CMS) |
| Key prefix | `launch-cms/` |

Object keys are `<prefix><host-suggested path>`; the full key is stored on the asset row, so changing the prefix later doesn't orphan old assets.

## Build and install

```sh
cd exo-plugins/media-r2
bun ../../src/core/plugin-sdk/cli/index.ts lint
bun ../../src/core/plugin-sdk/cli/index.ts build   # writes dist/; zip step needs `zip` on PATH
```

On Windows, zip `dist/` with forward-slash entry names (`plugin.json`, `server/index.js`). Install in **Plugins → Upload** (grants `media.storage.adapter`, `network.outbound`), fill the settings, then **Media → Storage → Test connection** and elect it for Originals and Variants.

## Verified (2026-11-18, cms.exoflowos.com)

Verify: probe written, read and deleted. Real upload: original + 5 variants landed in R2; `/_instatic/media/...` 302 → R2 200, bytes identical; delete + purge removed the object (old signed URL → 404). Wrong secret → 403.
