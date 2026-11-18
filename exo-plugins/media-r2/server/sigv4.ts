/**
 * AWS Signature V4 query-string presigning for S3-compatible stores (R2).
 *
 * Written for the QuickJS sandbox: the only crypto is `crypto.subtle.digest`
 * (SHA-256) and `crypto.subtle.importKey`/`sign` (HMAC-SHA256), both bridged
 * to the host. No Node/Bun APIs, no Buffer.
 *
 * Only `host` is signed and the payload is `UNSIGNED-PAYLOAD`, so the host's
 * uploader can add `Content-Type` / `Content-Length` freely.
 */

export interface R2Credentials {
  endpoint: string
  bucket: string
  accessKeyId: string
  secretAccessKey: string
}

export type PresignMethod = 'GET' | 'PUT' | 'DELETE' | 'HEAD'

const REGION = 'auto'
const SERVICE = 's3'
/** S3 caps presigned URLs at 7 days. */
const MAX_EXPIRES = 604_800

type Bytes = Uint8Array<ArrayBuffer>

function utf8(input: string): Bytes {
  return new TextEncoder().encode(input) as Bytes
}

function toHex(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer)
  let out = ''
  for (let i = 0; i < bytes.length; i++) {
    out += bytes[i].toString(16).padStart(2, '0')
  }
  return out
}

async function sha256Hex(input: string): Promise<string> {
  return toHex(await crypto.subtle.digest('SHA-256', utf8(input)))
}

async function hmac(key: Bytes | ArrayBuffer, data: string): Promise<ArrayBuffer> {
  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    key,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  )
  return crypto.subtle.sign('HMAC', cryptoKey, utf8(data))
}

/**
 * RFC 3986 encoding as SigV4 wants it: everything except A-Z a-z 0-9 - _ . ~
 * is percent-encoded (uppercase hex). `/` is kept only for path segments.
 */
export function uriEncode(input: string, keepSlash: boolean): string {
  const bytes = utf8(input)
  let out = ''
  for (let i = 0; i < bytes.length; i++) {
    const b = bytes[i]
    const c = String.fromCharCode(b)
    if (
      (b >= 0x41 && b <= 0x5a) ||
      (b >= 0x61 && b <= 0x7a) ||
      (b >= 0x30 && b <= 0x39) ||
      c === '-' || c === '_' || c === '.' || c === '~' ||
      (keepSlash && c === '/')
    ) {
      out += c
    } else {
      out += '%' + b.toString(16).toUpperCase().padStart(2, '0')
    }
  }
  return out
}

/** `20261118T120000Z` and `20261118` for a given instant. */
export function amzDates(now: Date): { amzDate: string; dateStamp: string } {
  const iso = now.toISOString().replace(/[-:]/g, '').replace(/\.\d{3}/, '')
  return { amzDate: iso, dateStamp: iso.slice(0, 8) }
}

function endpointHost(endpoint: string): { origin: string; host: string } {
  const url = new URL(endpoint)
  if (url.protocol !== 'https:') {
    throw new Error('R2 endpoint must be https://')
  }
  return { origin: `${url.protocol}//${url.host}`, host: url.host }
}

/**
 * Presign a path-style request: `<endpoint>/<bucket>/<key>`.
 * `now` is injectable so tests can compare against a known vector.
 */
export async function presign(
  creds: R2Credentials,
  method: PresignMethod,
  key: string,
  expiresSeconds: number,
  now: Date = new Date(),
): Promise<string> {
  const { origin, host } = endpointHost(creds.endpoint)
  const { amzDate, dateStamp } = amzDates(now)
  const expires = Math.max(1, Math.min(MAX_EXPIRES, Math.floor(expiresSeconds)))
  const scope = `${dateStamp}/${REGION}/${SERVICE}/aws4_request`

  const canonicalUri = '/' + uriEncode(creds.bucket, false) + '/' + uriEncode(key, true)

  const query: Array<[string, string]> = [
    ['X-Amz-Algorithm', 'AWS4-HMAC-SHA256'],
    ['X-Amz-Credential', `${creds.accessKeyId}/${scope}`],
    ['X-Amz-Date', amzDate],
    ['X-Amz-Expires', String(expires)],
    ['X-Amz-SignedHeaders', 'host'],
  ]
  query.sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0))
  const canonicalQuery = query
    .map(([k, v]) => `${uriEncode(k, false)}=${uriEncode(v, false)}`)
    .join('&')

  const canonicalRequest = [
    method,
    canonicalUri,
    canonicalQuery,
    `host:${host}\n`,
    'host',
    'UNSIGNED-PAYLOAD',
  ].join('\n')

  const stringToSign = [
    'AWS4-HMAC-SHA256',
    amzDate,
    scope,
    await sha256Hex(canonicalRequest),
  ].join('\n')

  const kDate = await hmac(utf8('AWS4' + creds.secretAccessKey), dateStamp)
  const kRegion = await hmac(kDate, REGION)
  const kService = await hmac(kRegion, SERVICE)
  const kSigning = await hmac(kService, 'aws4_request')
  const signature = toHex(await hmac(kSigning, stringToSign))

  return `${origin}${canonicalUri}?${canonicalQuery}&X-Amz-Signature=${signature}`
}
