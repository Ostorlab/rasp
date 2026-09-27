#ifndef RASP_BUILD_CONFIG_H
#define RASP_BUILD_CONFIG_H

/* Per-build identity for the sealed report.
 *
 * In a hardened build the hardener regenerates these for every build and registers the pair
 * (RASP_BUILD_ID -> RASP_BUILD_KEY_HEX, signer digest, code hashes) with the trust service's build
 * registry. The key MACs the RASP report so the trust service can tell a genuine build's report from a
 * repackaged app's (which cannot know this key) and from a forged or replayed report.
 *
 * The values below are DEVELOPMENT DEFAULTS, committed so the sample builds and the host tests run. They
 * are not secret. A release must override them (e.g. -DRASP_BUILD_ID=... -DRASP_BUILD_KEY_HEX=... via a
 * generated header) and register the matching build with the trust service.
 */
#ifndef RASP_BUILD_ID
#define RASP_BUILD_ID "test-build"
#endif

#ifndef RASP_BUILD_KEY_HEX
#define RASP_BUILD_KEY_HEX "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
#endif

#endif
