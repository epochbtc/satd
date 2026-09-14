import { setupManifest } from '@start9labs/start-sdk'
import { long, short } from './i18n'

export const manifest = setupManifest({
  id: 'satd',
  title: 'satd',
  license: 'MIT',
  donationUrl: null,
  packageRepo: 'https://github.com/epochbtc/satd/tree/master/contrib/packaging/startos',
  upstreamRepo: 'https://github.com/epochbtc/satd',
  marketingUrl: 'https://epochbtc.github.io/satd/',
  description: { short, long },
  volumes: ['main'],
  images: {
    satd: {
      source: {
        // The published runtime image, unmodified. It already carries
        // satd-init and mkca.sh, so this package's first run is the same one
        // the reference stack and the appliance perform and cannot drift from
        // them.
        //
        // 0.5.2 is the first release whose image carries satd-init; before it
        // this pinned a per-commit `sha-` tag. The digest pins the OCI index,
        // which resolves per architecture, so one pin covers amd64 and arm64.
        //
        // The `.s9pk` that was installed on a StartOS server was packed from
        // this digest — `pack` resolves the tag and embeds the layers, so the
        // server itself never contacts a registry.
        //
        // Bumping it, with versions/current.ts, is a step in the release
        // checklist.
        dockerTag: 'ghcr.io/epochbtc/satd:0.5.2@sha256:70d73fd51eded5be17272d1065b5409d6b296661c6bcee2e38b517ed505a595a',
      },
      // The image publishes linux/amd64 and linux/arm64 and nothing else, so
      // there is no riscv64 here and nothing to emulate it from.
      arch: ['x86_64', 'aarch64'],
    },
  },
  // satd is standalone: it needs no other service on the box, and nothing it
  // serves is contingent on one being installed.
  dependencies: {},
})
