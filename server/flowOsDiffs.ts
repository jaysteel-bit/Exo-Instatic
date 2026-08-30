/**
 * Bridge Launch CMS audit rows into Flow OS diffs.
 *
 * Audit stays the CMS record. Flow OS memory only accepts emit_diff() RPC
 * with vocabulary events. Missing env = no-op (CMS still works offline).
 */
const CLIENT_ZERO = 'e0000000-0000-4000-8000-000000000001'

type BrandEvent = {
  event: 'content=published' | 'post=published' | 'post=scheduled'
  entityPrefix: 'content' | 'post'
}

const AUDIT_TO_BRAND: Record<string, BrandEvent> = {
  publish: { event: 'content=published', entityPrefix: 'content' },
  'data.row.publish': { event: 'post=published', entityPrefix: 'post' },
  'data.row.schedule': { event: 'post=scheduled', entityPrefix: 'post' },
}

function supabaseEnv(): { url: string; anon: string } | null {
  const url = (
    process.env.FLOW_OS_SUPABASE_URL ?? process.env.NEXT_PUBLIC_SUPABASE_URL ?? ''
  ).replace(/\/$/, '')
  const anon =
    process.env.FLOW_OS_SUPABASE_ANON_KEY ?? process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY ?? ''
  if (!url || !anon) return null
  return { url, anon }
}

export function emitBrandDiffFromAudit(input: {
  actorUserId: string | null
  action: string
  targetType?: string | null
  targetId?: string | null
  metadata?: Record<string, unknown>
}): void {
  const mapped = AUDIT_TO_BRAND[input.action]
  if (!mapped) return
  const env = supabaseEnv()
  if (!env) return

  const entityId = `${mapped.entityPrefix}_${input.targetId || input.targetType || 'site'}`
  const after =
    mapped.event === 'post=scheduled'
      ? { status: 'scheduled' }
      : { status: 'published', source: 'launch-cms' }

  void fetch(`${env.url}/rest/v1/rpc/emit_diff`, {
    method: 'POST',
    headers: {
      apikey: env.anon,
      Authorization: `Bearer ${env.anon}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      p_client_id: CLIENT_ZERO,
      p_namespace: 'brand',
      p_entity_id: entityId,
      p_event: mapped.event,
      p_value_before: { status: 'draft' },
      p_value_after: after,
      p_actor: input.actorUserId ? `cms:${input.actorUserId}` : 'system',
      p_metadata: {
        source: 'launch-cms-audit',
        auditAction: input.action,
      },
    }),
  }).catch((err: unknown) => {
    console.error('[flow-os-diffs] emit_diff failed:', err)
  })
}
