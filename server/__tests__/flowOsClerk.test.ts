import { describe, expect, it } from 'bun:test'
import { generateKeyPairSync, sign } from 'node:crypto'
import { verifyClerkToken } from '../flowOsClerk'

const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 })
const jwk = { ...publicKey.export({ format: 'jwk' }), kid: 'k1', alg: 'RS256', use: 'sig' }
const jwks = { keys: [jwk] }
const b64 = (value: unknown) => Buffer.from(JSON.stringify(value)).toString('base64url')

function token(claims: Record<string, unknown>, kid = 'k1'): string {
  const head = b64({ alg: 'RS256', kid, typ: 'JWT' })
  const body = b64(claims)
  const sig = sign('RSA-SHA256', Buffer.from(`${head}.${body}`), privateKey).toString('base64url')
  return `${head}.${body}.${sig}`
}

const now = 1_800_000_000
const good = { sub: 'user_123', iat: now - 5, nbf: now - 10, exp: now + 55, azp: 'http://tauri.localhost' }

describe('verifyClerkToken (Flow OS sign-in)', () => {
  it('accepts a fresh token from an allowed origin', () => {
    expect(verifyClerkToken(token(good), jwks, now, ['http://tauri.localhost']).sub).toBe('user_123')
    expect(verifyClerkToken(token(good), jwks, now).sub).toBe('user_123')
  })

  it('refuses expired, not-yet-valid, wrong-origin and subject-less tokens', () => {
    expect(() => verifyClerkToken(token({ ...good, exp: now - 60 }), jwks, now)).toThrow('token expired')
    expect(() => verifyClerkToken(token({ ...good, nbf: now + 60 }), jwks, now)).toThrow('not yet valid')
    expect(() => verifyClerkToken(token(good), jwks, now, ['http://localhost:3000'])).toThrow('another app')
    expect(() => verifyClerkToken(token({ ...good, sub: undefined }), jwks, now)).toThrow('no subject')
  })

  it('refuses a tampered payload, an unknown key and other algorithms', () => {
    const [h, , s] = token(good).split('.')
    expect(() => verifyClerkToken(`${h}.${b64({ ...good, sub: 'user_evil' })}.${s}`, jwks, now)).toThrow('bad signature')
    expect(() => verifyClerkToken(token(good, 'other'), jwks, now)).toThrow('unknown signing key')
    const none = `${b64({ alg: 'none', kid: 'k1' })}.${b64(good)}.`
    expect(() => verifyClerkToken(none, jwks, now)).toThrow('unsupported token algorithm')
    expect(() => verifyClerkToken('not-a-jwt', jwks, now)).toThrow('malformed')
  })
})
