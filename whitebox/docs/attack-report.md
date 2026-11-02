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
for the broader attacks on encoded-table constructions. A further independent
attack against revision 2 is required before making any broader comparison.
