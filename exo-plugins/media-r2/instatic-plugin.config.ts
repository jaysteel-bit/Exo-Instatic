import { definePlugin, permissions } from '@core/plugin-sdk'

/**
 * Exo · Cloudflare R2 media storage.
 *
 * Registers the storage adapter `exo.media.r2.storage`. Uploads go straight
 * from the CMS host to a private R2 bucket via SigV4-presigned PUTs; reads
 * are 302s to short-lived presigned GETs minted per request by the host
 * (`/_instatic/media/...`). No media bytes cross the QuickJS sandbox.
 *
 * `network.outbound` is only for `delete` and `verify` (presigned DELETE /
 * PUT probe), limited to R2's S3 endpoints.
 */
export default definePlugin({
  id: 'exo.media.r2',
  name: 'Exo R2 Media Storage',
  version: '0.1.0',
  description:
    'Store Launch CMS media in a private Cloudflare R2 bucket. Uploads use presigned PUTs; reads are signed redirects.',

  permissions: [
    permissions.mediaStorageAdapter,
    permissions.networkOutbound,
  ],

  networkAllowedHosts: ['*.r2.cloudflarestorage.com'],

  settings: [
    {
      id: 'endpoint',
      type: 'url',
      label: 'S3 endpoint',
      description: 'https://<account-id>.r2.cloudflarestorage.com (no bucket in the path).',
      required: true,
    },
    {
      id: 'bucket',
      type: 'text',
      label: 'Bucket',
      default: 'exo-media',
      required: true,
    },
    {
      id: 'accessKeyId',
      type: 'text',
      label: 'Access key ID',
      required: true,
    },
    {
      id: 'secretAccessKey',
      type: 'password',
      label: 'Secret access key',
      secret: true,
      required: true,
    },
    {
      id: 'keyPrefix',
      type: 'text',
      label: 'Key prefix',
      description: 'Folder inside the bucket for this site, e.g. "exoent/". Leave empty for the bucket root.',
      default: 'launch-cms/',
    },
  ],
})
