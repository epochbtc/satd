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
        // A per-commit tag, not a release tag: no release contains satd-init,
        // which this branch adds, so `0.5.1` — what this line used to say —
        // could not have started. `docker.yml` publishes `sha-<short>` on
        // every build, the short sha names a real commit on the branch, and
        // the digest pins the manifest list, which resolves per architecture
        // so one pin covers amd64 and arm64.
        //
        // The `.s9pk` that was installed on a StartOS server was packed from
        // this digest — `pack` resolves the tag and embeds the layers, so the
        // server itself never contacts a registry.
        //
        // Bumping it to the release tag is a step in the release checklist.
        dockerTag: 'ghcr.io/epochbtc/satd:sha-8246eb9@sha256:88b7489a76a11aebf57b805f6fa97b002141fa712b530083bfa081a7dc4ec4b6',
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
