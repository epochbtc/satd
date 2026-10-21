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
        // This pins the 0.6.2 release, the image release.yml built and
        // cosign-signed for the v0.6.2 tag. Between releases it may pin a
        // master commit's `sha-` image instead, which docker.yml publishes
        // unsigned for that purpose; sync-store.sh refuses a `sha-` pin, so
        // such a pin cannot be published. The digest pins the OCI index,
        // which resolves per architecture, so one pin covers amd64 and arm64.
        //
        // The `.s9pk` that was installed on a StartOS server was packed from
        // this digest — `pack` resolves the tag and embeds the layers, so the
        // server itself never contacts a registry.
        //
        // Moving the pin to the next release, with versions/current.ts, is a
        // step in the release checklist.
        dockerTag: 'ghcr.io/epochbtc/satd:0.6.2@sha256:8a7a1e0a224015c15416a0f533fb0f7293a4045959e730d3e9f7704ba7c975c3',
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
