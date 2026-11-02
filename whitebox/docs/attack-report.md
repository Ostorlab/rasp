# White-box AES evaluation

## Confirmed break of revision 1

After the initial public-decrypt experiment, OpenCode DeepSeek Flash recovered
the exact embedded AES-128 key using static final-table analysis. The evaluator
matched its candidate against the privately stored key hash and reran independent
AES-GCM verification on the supplied record and a fresh binary-encrypted message.
Both checks passed. The binary and original ciphertext remained unchanged.

For each final table T and candidate final key byte k, the attacker evaluated
`inverse_sbox(T[x] XOR k)`. The correct k produced a permutation whose high nibble
depended only on the high input nibble and whose low nibble depended only on the
low input nibble. XOR with the penultimate key byte preserves this property.
Trying 256 candidates at each of 16 positions recovered the last round key;
reversing the AES-128 key schedule recovered the master key. This attack needs
about one million inverse-S-box evaluations, not an AES brute-force search.

No raw key or plaintext is included in this report. The old report's initial
“no key recovered” outcome is superseded by this confirmed extraction.

## Revision 2 and regression

The generator now uses arbitrary byte permutations throughout the table network,
including all four bytes of every MixColumns contribution and encoded XOR join.
Final input decoding is an arbitrary byte permutation. For a final table alone,
any candidate final key byte can be absorbed into an arbitrary input permutation;
the original nibble-separation distinguisher no longer applies.

`analysis.final_key_candidates` reproduces the observed predicate without relying
on hardcoded ELF addresses. Tests recover all 256 possible final key-byte values
from legacy-shaped tables. The same predicate finds no candidates in the revised
final tables for four key/seed combinations, whose native AES outputs are also
compared with independent AES on known vectors and generated blocks.

The data grows to 28,463,104 bytes. It is embedded with the GNU assembler at build
time, avoiding a huge C++ initializer. No runtime table file is required.

This is targeted hardening, not a general security result. The XOR network is
still algebraically structured, and this regression does not test adapted attacks
using multiple tables, fault injection, or execution traces. See the primary
research [A Tutorial on White-box AES](https://eprint.iacr.org/2013/104.pdf)
for the broader attacks on encoded-table constructions. The adaptive attempt below supersedes the initial limited regression result.

## Confirmed break of revision 2

The fresh binary was supplied to the same DeepSeek Flash evaluator, with prior
knowledge of the first attack but no generator source or private evaluator data.
Its reported run took about 95 seconds. It recovered the exact new key: the
independent evaluator matched its SHA-256 to the private key hash. Supplied input
hashes remained unchanged. The agent also verified original and freshly encrypted
records through independent AES-GCM.

Let X(a,b) be the last encoded XOR table and T its consuming final table. For
candidate k, define Y(a,b) = inverse_sbox(T[X(a,b)] XOR k). The true k satisfies
`Y(a,b) XOR Y(a,0) XOR Y(0,b) XOR Y(0,0) = 0` for every input pair. Testing 256
candidates again recovers each last-round key byte. Arbitrary encodings disappear
when these adjacent tables are composed. This is a local structural attack; no
full BGE implementation or runtime faults are necessary.

`analysis.xor_key_candidates` reproduces this adaptive predicate without NumPy,
private challenge material, or hardcoded ELF addresses. Tests explicitly assert
recovery of the true last-round key for all four native test builds. Passing these
tests documents the failure; it must not be presented as a security pass.

**Revision 2 is also broken.** Its approximately 76-fold storage increase did not
produce demonstrated protection against adaptive extraction. A stronger design
must remove the cheaply separable AES-round/XOR boundaries and undergo new attacks;
wider encodings or relocated tables alone do not address this root cause.
