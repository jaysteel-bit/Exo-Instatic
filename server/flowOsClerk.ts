/**
 * Exo: sign in to Launch CMS with the Flow OS (Clerk) session.
 *
 * Flow OS opens `/admin/connect#token=<Clerk session token>` in its Launch CMS
 * pane. The fragment never reaches a server or a log; the page posts the token
 * here, same-origin. The server verifies it against the Clerk instance's JWKS
 * (Backend API, `CLERK_SECRET_KEY`), looks up that Clerk user's verified email
 * addresses, and signs in the CMS user with one of them, through the same
 * `respondLoginSuccess` path as a password login (session cookie, MFA step if
 * enrolled, audit events). Clerk says who the person is; the CMS users table
 * still decides who may come in. Password login stays as the owner's backup.
 *
 * Off unless `CLERK_SECRET_KEY` is set. Optional `LAUNCH_CMS_CLERK_AZP`: the
 * comma-separated origins a token must have been issued to (Flow OS's).
 */

import { createPublicKey, verify as verifySig, type JsonWebKey } from 'node:crypto'
import type { DbClient } from './db/client'
import { clientIp, originAllowed } from './auth/security'
import { createAuditEvent } from './repositories/audit'
import { findUserByEmail } from './repositories/users'
import { respondLoginSuccess } from './handlers/cms/auth'
import { requestAuditContext } from './handlers/cms/shared'
import { jsonResponse, readValidatedBody } from './http'
import { Type } from '@core/utils/typeboxHelpers'

export const CONNECT_PATH = '/admin/connect'
export const CLERK_LOGIN_PATH = '/admin/api/flow-os/clerk'

type Jwks = { keys: (JsonWebKey & { kid?: string })[] }
type Claims = { sub?: string; exp?: number; nbf?: number; iss?: string; azp?: string; sid?: string; iat?: number }
type ClerkUser = { id: string; email_addresses?: { email_address: string; verification?: { status?: string } | null }[] }

const secret = () => process.env.CLERK_SECRET_KEY?.trim() || null

let jwksCache: { at: number; jwks: Jwks } | null = null

async function clerkJwks(key: string, force = false): Promise<Jwks> {
  if (!force && jwksCache && Date.now() - jwksCache.at < 600_000) return jwksCache.jwks
  const r = await fetch('https://api.clerk.com/v1/jwks', {
    headers: { Authorization: `Bearer ${key}` },
    signal: AbortSignal.timeout(5000),
  })
  if (!r.ok) throw new Error(`Clerk JWKS: HTTP ${r.status}`)
  jwksCache = { at: Date.now(), jwks: (await r.json()) as Jwks }
  return jwksCache.jwks
}

function decode<T>(part: string): T {
  return JSON.parse(Buffer.from(part, 'base64url').toString('utf8')) as T
}

/** RS256 signature, expiry, not-before, and (when configured) the issuing origin. */
export function verifyClerkToken(token: string, jwks: Jwks, now = Date.now() / 1000, azp: string[] = []): Claims & { sub: string } {
  const parts = token.split('.')
  if (parts.length !== 3) throw new Error('malformed token')
  const [h, p, sig] = parts
  const header = decode<{ alg?: string; kid?: string }>(h)
  if (header.alg !== 'RS256') throw new Error('unsupported token algorithm')
  const jwk = jwks.keys.find((k) => k.kid === header.kid)
  if (!jwk) throw new Error('unknown signing key')
  const key = createPublicKey({ key: jwk, format: 'jwk' })
  if (!verifySig('RSA-SHA256', Buffer.from(`${h}.${p}`), key, Buffer.from(sig, 'base64url'))) {
    throw new Error('bad signature')
  }
  const claims = decode<Claims>(p)
  if (typeof claims.exp !== 'number' || claims.exp < now - 5) throw new Error('token expired')
  if (typeof claims.nbf === 'number' && claims.nbf > now + 5) throw new Error('token not yet valid')
  if (azp.length > 0 && !azp.includes(claims.azp ?? '')) throw new Error('token issued to another app')
  if (!claims.sub) throw new Error('token has no subject')
  return claims as Claims & { sub: string }
}

async function verifiedEmails(key: string, userId: string): Promise<string[]> {
  const r = await fetch(`https://api.clerk.com/v1/users/${encodeURIComponent(userId)}`, {
    headers: { Authorization: `Bearer ${key}` },
    signal: AbortSignal.timeout(5000),
  })
  if (!r.ok) throw new Error(`Clerk user lookup: HTTP ${r.status}`)
  const user = (await r.json()) as ClerkUser
  return (user.email_addresses ?? [])
    .filter((e) => e.verification?.status === 'verified')
    .map((e) => e.email_address.trim().toLowerCase())
}

// A Clerk session token lives ~60 s; each one signs in once.
const used = new Map<string, number>()
function firstUse(token: string, exp: number): boolean {
  const now = Date.now() / 1000
  for (const [k, until] of used) if (until < now) used.delete(k)
  const id = new Bun.CryptoHasher('sha256').update(token).digest('hex')
  if (used.has(id)) return false
  used.set(id, exp + 5)
  return true
}

// At most 20 attempts per IP per 10 minutes.
const attempts = new Map<string, { n: number; since: number }>()
function allowAttempt(ip: string): boolean {
  const now = Date.now()
  const entry = attempts.get(ip)
  if (!entry || now - entry.since > 600_000) {
    attempts.set(ip, { n: 1, since: now })
    return true
  }
  entry.n += 1
  return entry.n <= 20
}

const CONNECT_HTML = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="referrer" content="no-referrer">
<title>Signing in to Launch CMS</title>
<style>html,body{margin:0;height:100%;background:#0a0a0a;color:#bbb;font:14px system-ui,sans-serif;display:grid;place-items:center}</style>
</head><body><p id="m">Signing in with Flow OS…</p>
<script>
(async () => {
  const token = new URLSearchParams(location.hash.slice(1)).get('token')
  history.replaceState(null, '', location.pathname)
  const to = '/admin'
  if (!token) { location.replace(to); return }
  try {
    const r = await fetch(${JSON.stringify(CLERK_LOGIN_PATH)}, {
      method: 'POST', credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ token }),
    })
    if (!r.ok) document.getElementById('m').textContent = 'Flow OS sign-in did not work; use your password.'
  } catch {}
  setTimeout(() => location.replace(to), 400)
})()
</script></body></html>`

const ClerkLoginBodySchema = Type.Object({ token: Type.String({ maxLength: 8192 }) })

async function handleClerkLogin(req: Request, db: DbClient): Promise<Response> {
  const key = secret()
  if (!key) return jsonResponse({ error: 'Flow OS sign-in is not configured' }, { status: 404 })
  if (!originAllowed(req)) return jsonResponse({ error: 'Origin not allowed' }, { status: 403 })
  const ip = clientIp(req)
  if (!allowAttempt(ip ?? 'unknown')) return jsonResponse({ error: 'Too many attempts' }, { status: 429 })

  const body = await readValidatedBody(req, ClerkLoginBodySchema)
  if (!body) return jsonResponse({ error: 'Bad request' }, { status: 400 })
  const token = body.token

  const azp = (process.env.LAUNCH_CMS_CLERK_AZP ?? '').split(',').map((s) => s.trim()).filter(Boolean)
  let claims: Claims & { sub: string }
  try {
    try {
      claims = verifyClerkToken(token, await clerkJwks(key), undefined, azp)
    } catch (error) {
      // A rotated key: refetch once.
      if (!(error instanceof Error) || error.message !== 'unknown signing key') throw error
      claims = verifyClerkToken(token, await clerkJwks(key, true), undefined, azp)
    }
  } catch (error) {
    await createAuditEvent(db, {
      actorUserId: null,
      action: 'login.failure',
      targetType: 'user',
      targetId: null,
      metadata: { via: 'flow-os-clerk', reason: error instanceof Error ? error.message : 'invalid token' },
      ...requestAuditContext(req),
    })
    return jsonResponse({ error: 'Invalid Flow OS session' }, { status: 401 })
  }
  if (!firstUse(token, claims.exp ?? 0)) return jsonResponse({ error: 'Token already used' }, { status: 401 })

  let emails: string[]
  try {
    emails = await verifiedEmails(key, claims.sub)
  } catch {
    return jsonResponse({ error: 'Clerk is unreachable; use your password' }, { status: 503 })
  }
  for (const email of emails) {
    const user = await findUserByEmail(db, email)
    if (user && user.status === 'active') {
      return respondLoginSuccess(db, req, user, email, ip, `${ip ?? 'unknown'}|${email}`)
    }
  }
  await createAuditEvent(db, {
    actorUserId: null,
    action: 'login.failure',
    targetType: 'user',
    targetId: null,
    metadata: { via: 'flow-os-clerk', reason: 'no CMS user for this Flow OS account', clerkUserId: claims.sub },
    ...requestAuditContext(req),
  })
  return jsonResponse({ error: 'No Launch CMS account for this Flow OS user' }, { status: 403 })
}

export function tryServeFlowOsClerk(req: Request, db: DbClient, pathname: string): Promise<Response> | Response | null {
  if (pathname === CONNECT_PATH && req.method === 'GET') {
    return new Response(CONNECT_HTML, {
      headers: { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store', 'referrer-policy': 'no-referrer' },
    })
  }
  if (pathname === CLERK_LOGIN_PATH && req.method === 'POST') return handleClerkLogin(req, db)
  return null
}
