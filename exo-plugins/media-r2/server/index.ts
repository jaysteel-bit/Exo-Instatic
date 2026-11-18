import type { ServerPluginModule } from '@core/plugin-sdk'
import { presign, type R2Credentials } from './sigv4'

/** Upload plans must be used within this window (host checks before PUT). */
const UPLOAD_TTL_SECONDS = 15 * 60
const DELETE_TTL_SECONDS = 60

type Api = Parameters<NonNullable<ServerPluginModule['activate']>>[0]

function readCredentials(api: Api): R2Credentials & { keyPrefix: string } {
  const get = (id: string): string => {
    const value = api.cms.settings.get(id)
    return typeof value === 'string' ? value.trim() : ''
  }
  const creds = {
    endpoint: get('endpoint').replace(/\/+$/, ''),
    bucket: get('bucket'),
    accessKeyId: get('accessKeyId'),
    secretAccessKey: get('secretAccessKey'),
    keyPrefix: get('keyPrefix').replace(/^\/+/, ''),
  }
  const missing = (['endpoint', 'bucket', 'accessKeyId', 'secretAccessKey'] as const)
    .filter((k) => !creds[k])
  if (missing.length > 0) {
    throw new Error(`R2 storage is not configured: missing ${missing.join(', ')}`)
  }
  return creds
}

/** Object key for a host-suggested path: `<prefix><path>`, no leading slash, no `..`. */
function objectKey(prefix: string, suggested: string): string {
  const clean = suggested
    .replace(/\\/g, '/')
    .split('/')
    .filter((seg) => seg && seg !== '.' && seg !== '..')
    .join('/')
  if (!clean) throw new Error('Empty storage path')
  const p = prefix && !prefix.endsWith('/') ? prefix + '/' : prefix
  return p + clean
}

async function deleteObject(creds: R2Credentials, key: string): Promise<void> {
  const url = await presign(creds, 'DELETE', key, DELETE_TTL_SECONDS)
  const res = await fetch(url, { method: 'DELETE' })
  // S3 semantics: 204 on delete, also 204 when already gone. Treat 404 as gone.
  if (!res.ok && res.status !== 404) {
    const text = await res.text().catch(() => '')
    throw new Error(`R2 DELETE ${res.status}: ${text.slice(0, 200)}`)
  }
}

const mod: ServerPluginModule = {
  activate(api) {
    api.cms.media.registerStorageAdapter({
      id: 'exo.media.r2.storage',
      label: 'Cloudflare R2 (Exo)',
      roles: ['original', 'variant'],
      servingMode: 'signed-redirect',

      async beginWrite(input) {
        const creds = readCredentials(api)
        // storagePath is what the host persists and hands back to every
        // other method; it is the full object key, so it stays valid even
        // if the prefix setting changes later.
        const storagePath = objectKey(creds.keyPrefix, input.suggestedStoragePath)
        const url = await presign(creds, 'PUT', storagePath, UPLOAD_TTL_SECONDS)
        return {
          storagePath,
          steps: [
            {
              method: 'PUT',
              url,
              headers: { 'Content-Type': input.mimeType },
            },
          ],
          // Leave a margin so the host never starts a PUT on a URL that
          // expires mid-flight.
          expiresAt: Date.now() + (UPLOAD_TTL_SECONDS - 60) * 1000,
        }
      },

      async finalizeWrite(input) {
        // The host substitutes its own /_instatic/media/... URL for
        // signed-redirect adapters; this value is not served.
        const etag = input.uploadReceipts[0]?.etag
        return {
          publicUrl: `/uploads/${input.storagePath}`,
          ...(etag ? { metadata: { etag } } : {}),
        }
      },

      async abortWrite(input) {
        try {
          await deleteObject(readCredentials(api), input.storagePath)
        } catch (err) {
          api.plugin.log(`abortWrite: could not remove ${input.storagePath}: ${String(err)}`)
        }
      },

      async getReadUrl(storagePath, ttlSeconds) {
        const ttl = Math.max(60, Math.min(ttlSeconds || 3600, 3600))
        const url = await presign(readCredentials(api), 'GET', storagePath, ttl)
        return { url, expiresAt: Date.now() + ttl * 1000 }
      },

      async delete(storagePath) {
        await deleteObject(readCredentials(api), storagePath)
      },

      async verify() {
        let creds: ReturnType<typeof readCredentials>
        try {
          creds = readCredentials(api)
        } catch (err) {
          return { ok: false, reason: String(err instanceof Error ? err.message : err), hint: 'Fill in the plugin settings first.' }
        }
        const key = objectKey(creds.keyPrefix, `.verify/${Date.now()}-${crypto.randomUUID()}.txt`)
        try {
          const putUrl = await presign(creds, 'PUT', key, 60)
          const put = await fetch(putUrl, {
            method: 'PUT',
            headers: { 'Content-Type': 'text/plain' },
            body: 'launch-cms r2 verify',
          })
          if (!put.ok) {
            const text = await put.text().catch(() => '')
            return {
              ok: false,
              reason: `Write test failed (HTTP ${put.status}).`,
              hint: put.status === 403
                ? 'Check the access key, secret and that the token has Object Read & Write on this bucket.'
                : text.slice(0, 160) || 'Check the endpoint and bucket name.',
            }
          }
          const getUrl = await presign(creds, 'GET', key, 60)
          const get = await fetch(getUrl)
          await deleteObject(creds, key)
          if (!get.ok) {
            return { ok: false, reason: `Read test failed (HTTP ${get.status}).` }
          }
          return { ok: true, reason: `Wrote, read and deleted a probe in ${creds.bucket}.` }
        } catch (err) {
          return {
            ok: false,
            reason: String(err instanceof Error ? err.message : err).slice(0, 200),
            hint: 'Is the endpoint an *.r2.cloudflarestorage.com host?',
          }
        }
      },
    })
  },
}

export default mod
