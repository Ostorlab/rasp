# Blind binary evaluation

## Result

The OpenCode DeepSeek Flash agent ran the binary's documented command:

```sh
./whitebox decrypt ciphertext.wbx recovered.txt
```

The recovered file contained 155 bytes and matched the private evaluator's original-text hash. This is successful use of the binary's public decryption interface; it is not a cryptanalytic recovery of plaintext from ciphertext alone.

The agent did **not** recover the embedded AES key. It produced no candidate key, so no key claim or independent candidate-key verification is possible. Plaintext recovery and key recovery are separate outcomes.

## Static analysis reported by the agent

The agent identified a table-driven AES implementation and traced table regions in the executable. It reported that the round tables do not match a simple standard-AES-T-table-plus-constant form and that table columns appear to be byte permutations. It did not complete an algebraic/table-decomposition attack, and these observations do not establish a security bound.

The binary and ciphertext hashes matched the public challenge manifest after evaluation. The recovered plaintext, generated binary, ciphertext, and private evaluator materials are intentionally excluded from this report and from source control.

## Interpretation

The experiment demonstrates that anyone holding the executable can request decryption of authenticated records through its supported interface. It does not demonstrate AES key extraction. This prototype remains a research baseline, not a production white-box cryptographic implementation. A failed key-extraction attempt by one model is not evidence that the implementation is secure.
