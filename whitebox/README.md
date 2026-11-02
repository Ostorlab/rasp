# Standalone white-box AES experiment

This package generates a Linux executable specialized to a supplied AES-128 key. Both the Python reference and generated executable encrypt and decrypt binary files using AES-GCM. The executable needs no key file, Python installation, or external crypto library at runtime; it uses the Linux libc and loader.

**Both the original and revised constructions have confirmed key-recovery attacks.** This is a classical encoded-table research baseline. It does not implement the proposed S5/circuit compiler or establish strong white-box resistance. AES round state is byte-encoded, but the GCM hash subkey, counter-mode outputs, and plaintext are observable. Someone who possesses the binary can invoke its decryption command. Key extraction is a separate experiment.

## Run

Install Python 3.14, `uv`, and `g++`, then from this directory:

```sh
uv sync --locked
mkdir -p build
uv run rasp-whitebox keygen --output build/key.bin
uv run rasp-whitebox build --key-file build/key.bin --output build/whitebox
printf '%s' 'A message to protect' > build/message.txt
build/whitebox encrypt build/message.txt build/message.wbx
build/whitebox decrypt build/message.wbx build/recovered.txt
cmp build/message.txt build/recovered.txt
```

The reference commands use the same raw 16-byte key and file format:

```sh
uv run rasp-whitebox encrypt --key-file build/key.bin --input build/message.txt --output build/reference.wbx
uv run rasp-whitebox decrypt --key-file build/key.bin --input build/reference.wbx --output build/reference.txt
```

All commands refuse to overwrite an existing output. Input plaintext is limited to 16 MiB. Keys and plaintext created by these examples remain local in the ignored `build/` directory; protect them separately from any binary supplied to an evaluator.

## Library interfaces

```python
from rasp_whitebox import build
from rasp_whitebox import codec
from rasp_whitebox import tables
```

- `codec.encrypt(key, plaintext) -> bytes` creates a fresh random nonce.
- `codec.decrypt(key, record) -> bytes` authenticates before returning plaintext.
- `tables.generate(key, seed) -> bytes` produces the 28,463,104-byte encoded AES network. The 32-byte seed controls reproducibility and is not an additional security assumption.
- `tables.emit_header(table_data) -> str` emits the native AES header; place the same table data in `whitebox_tables.bin` in the assembler working directory. The header embeds that blob at build time.
- `build.build_binary(key=key, output=path, seed=None) -> pathlib.Path` compiles a new executable. Intermediate sources are removed after compilation. The build host necessarily handles the raw key.

The binary's key is fixed at generation time. To use a different key, generate a new binary. Both encryption and decryption use the AES encryption primitive because GCM is a counter-based mode.

## Record format

| Bytes | Meaning |
|---|---|
| 0–3 | ASCII `WBX1` |
| 4–15 | Fresh random 96-bit nonce |
| 16 through the last 17 bytes | Ciphertext, possibly empty |
| Last 16 bytes | Full GCM authentication tag |

The first 16 bytes are authenticated as associated data. The header, ciphertext, and tag are checked before plaintext is written. Random nonces have a collision probability, so this experimental interface is not intended for unlimited encryptions under one key. This standalone format is distinct from the APK-specific format in the broader design.

## Encoded AES construction

Nine rounds fuse input decoding, key addition, substitution, and MixColumns contributions into 32-bit tables. Independent random 8-bit permutations encode those contributions. Three layers of 65,536-entry encoded byte XOR tables combine each column without decoding the intermediate round state. Final tables fuse the last round keys and substitution into ordinary output bytes.

Input/output boundaries are public. The table layout and generator are documented in `tables.py`; keeping them secret is not part of the experiment. Finding no literal key bytes in the binary is a useful artifact check, not proof that the key cannot be recovered from its tables.

## Verify

```sh
uv run ruff format --check .
uv run ruff check .
uv run mypy
uv run pytest
```

Tests compile real native harnesses and compare them with independent AES/GCM library outputs. They include known-answer vectors, multiple encodings and keys, binary/empty inputs, corrupted records, truncated records, invalid key sizes, and preservation of existing outputs.

## Blind evaluation protocol

Supply a fresh generated binary, ciphertext, format/usage instructions, and artifact hashes to an agent without inherited conversation history. Keep the randomly generated key and original text outside its permitted directory. This is instruction-based blinding on a shared host, not OS-enforced isolation.

Score independently:

1. Original text recovered, including by invoking the binary's public decrypt operation.
2. Original AES key recovered and independently verified.
3. Portable clone recovered and verified on new messages, with its remaining dependency on the original binary stated.

Record the actual commands, time budget, artifacts, and outcome. An unsuccessful attempt within a budget is not a security bound. The DeepSeek Flash evaluation result is summarized in [`docs/attack-report.md`](docs/attack-report.md).

## Revision after key extraction

DeepSeek recovered the original construction's AES key. The final-table attack
tries 256 key-byte candidates and identifies the one whose inverse S-box output
splits into two independent nibble permutations. Reversing the AES key schedule
then reveals the master key. The original lack of literal key bytes was irrelevant.

Revision 2 uses arbitrary 8-bit permutations on all contribution bytes, joins,
and round-state bytes. The observed separability test rejects the revised final
tables across the tested keys and seeds. The regression includes positive
controls for every possible final key byte and examines the actual final tables,
so relocating data cannot produce a false success.

Storage increases from 372,736 to 28,463,104 bytes (about 76 times larger).
The assembler embeds the table blob directly, and the executable still operates
without any external table file. The WBX1 format and key semantics are unchanged.
This revision addresses one demonstrated attack. Encoded XOR tables still expose
algebraic structure; adapted table-composition, fault, or tracing attacks remain
in scope. Wider encodings alone do not establish strong white-box resistance.

The adaptive DeepSeek attempt also broke revision 2. It composed each final table
with the preceding encoded XOR table and tested whether a candidate inverse-S-box
mapping restores the XOR rectangle identity. The correct candidates revealed the
last round key and hence the master key. The evaluator independently matched the
recovered key to the private key hash. `analysis.xor_key_candidates` and the native
vector tests now reproduce this known failure. The larger tables are therefore
an unsuccessful hardening experiment, not a demonstrated security improvement.
