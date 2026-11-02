# Standalone encoded AES implementation and blind attack

The requested deliverable extends the reference-only foundation into a Linux executable and an observed attack. It is a research baseline: encoded AES T-boxes and nibble XOR tables, followed by ordinary GCM composition. It does not implement S5 or claim resistance beyond published white-box designs. The native GCM hash key and counter-mode outputs are observable boundaries.

## Implementation contract

- Python library and CLI: generate a 16-byte key; encrypt/decrypt arbitrary files up to 16 MiB using AES-128-GCM; compile a binary specialized to a supplied key.
- Native CLI: `whitebox encrypt|decrypt INPUT OUTPUT`; no key parameter, Python runtime, or external crypto library needed at execution time. Linux host libc is required.
- File format: `WBX1` (4 bytes), random nonce (12 bytes), ciphertext, GCM tag (16 bytes). Authenticate the 16-byte magic/nonce header. Never release unauthenticated plaintext or overwrite existing output files.
- Different fresh random nonces support repeated standalone encryption. The APK-specific v2 format remains a separate integration design.
- Generate nine rounds of encoded 32-bit contribution tables, encoded nibble XOR trees, and final keyed substitution tables. Keep the raw key/key schedule on the generation host. Encode intermediate AES round state; document the representation and known limitations.
- Tests: independent AES/GCM vectors, multiple keys/encodings, boundary sizes, header/ciphertext/tag tampering, malformed keys and output preservation. Exercise the real generated executable.

## Work sequence

1. Add the standalone reference codec and command-line tests, observe their initial failures, then implement them.
2. Generate and validate the encoded AES tables and native block primitive.
3. Compile native GCM/file processing, and cross-check both directions with the independent Python library.
4. Review spec compliance, then code quality; fix findings and rerun targeted checks.
5. Generate a fresh random challenge key and high-entropy original text. Put only the binary, ciphertext, format/usage description, and artifact hashes in the attack directory.
6. Spawn `gpt-6.1-sol` with no inherited history. Request plaintext recovery, then separate key extraction or a portable implementation. Limit its permitted reads to the challenge directory and system tools. Record that this is instruction-based blinding on a shared host, not OS-enforced isolation.
7. Independently compare recovered bytes/key to private evaluator values; verify any clone on new messages. Report elapsed time, commands and exact success scope. Plaintext recovery through the advertised decrypt operation is an expected API capability, not proof of cryptanalysis.

The user explicitly authorized the sol attack. No production runtime integration, publishing, or external messages are needed for this experiment.
