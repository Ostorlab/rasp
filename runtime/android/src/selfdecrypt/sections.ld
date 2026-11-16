/* Additive linker script (INSERT keeps the default NDK script) for the self-decrypt bootstrap. It forces the clear
 * bootstrap (.stubcode) onto its own whole page(s), placed right after .text. That page isolation matters: when the
 * bootstrap flips the library's .text writable (and non-executable) to decrypt it, the page the bootstrap is running from
 * must not be in that range. MAXPAGESIZE follows the linker's -z max-page-size, so this is correct for 4 KB and 16 KB
 * page devices alike.
 *
 * O-MVLL emits read-only data the bootstrap reads at load (indirect-call mask shares in .rodata..icall.shares1*, SIMD
 * constant pools in .rodata.cst* for its opaque-constant and arithmetic passes). Left in .rodata those bytes would be
 * encrypted and read as ciphertext before decryption, breaking the bootstrap. So all read-only data contributed by the
 * bootstrap objects is pulled into the clear, self-hashed .stubcode here (their source rodata already lives in
 * .stubrodata via #pragma clang section). This read-only data carries no relocations; the packer refuses to pack if a
 * relocation ever lands in .stubcode, so a mistake here fails loudly rather than shipping a broken library.
 */
SECTIONS
{
  .stubcode : ALIGN(CONSTANT(MAXPAGESIZE))
  {
    *(.stubcode .stubcode.*)
    *(.stubrodata .stubrodata.*)
    *selfdecrypt.cpp.o(.rodata .rodata.* .rodata..*)
    *chacha20.cpp.o(.rodata .rodata.* .rodata..*)
    *kdf_shovel.cpp.o(.rodata .rodata.* .rodata..*)
    . = ALIGN(CONSTANT(MAXPAGESIZE));
  }
} INSERT AFTER .text;
