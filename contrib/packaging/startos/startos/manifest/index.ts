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
        // Pinned to a release that exists. The registry publishes bare tags
        // only — there has never been a `v`-prefixed one — and the tag is
        // bumped as a step in the release checklist.
        dockerTag: 'ghcr.io/epochbtc/satd:0.5.1',
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
