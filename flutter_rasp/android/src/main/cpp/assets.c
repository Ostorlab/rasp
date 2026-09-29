#include "assets.h"
#include "wbaes.h"
#include "vm.h"
#include <string.h>

static void asset_wipe(void *buffer, size_t length) {
    volatile uint8_t *bytes = buffer;
    while (length-- > 0) *bytes++ = 0;
}
static int asset_equal(const uint8_t *left, const uint8_t *right, size_t length) {
    uint8_t difference = 0;
    for (size_t i = 0; i < length; i++) difference |= left[i] ^ right[i];
    return difference == 0;
}
int rasp_asset_open(const uint32_t *type2, const uint8_t *last, const uint8_t base_key[32],
                    const rasp_region_t *regions, size_t region_count, const char *identity,
                    const uint8_t *package, size_t package_len, uint8_t *out, size_t out_len) {
    if (!type2 || !last || !base_key || !regions || region_count == 0 || region_count > 16 ||
        !identity || identity[0] == '\0' || !package || !out || package_len < 80 ||
        package_len > 16777216 + 80 || out_len < package_len - 80) return -1;
    for (size_t i = 0; i < region_count; i++) if (!regions[i].data || regions[i].len == 0) return -1;
    RASP_LIT(ASSET_MAC_DOMAIN, domain);
    RASP_LIT(ASSET_MAGIC, magic);
    uint8_t root[32], material[RASP_LIT_MAXLEN + 32], authentication[32], tag[32], identity_hash[32];
    size_t domain_len = strlen(domain);
    rasp_guard_root(regions, region_count, root);
    memcpy(material, domain, domain_len);
    memcpy(material + domain_len, root, 32);
    rasp_hmac_sha256(base_key, 32, material, domain_len + 32, authentication);
    rasp_hmac_sha256(authentication, 32, package, package_len - 32, tag);
    asset_wipe(authentication, sizeof(authentication));
    asset_wipe(material, sizeof(material));
    rasp_sha256((const uint8_t *)identity, strlen(identity), identity_hash);
    if (!asset_equal(tag, package + package_len - 32, 32) ||
        !asset_equal((const uint8_t *)magic, package, 4) || !asset_equal(identity_hash, package + 16, 32)) return -1;
    size_t length = package_len - 80;
    rasp_wbaes_ctr(type2, last, package + 4, package + 48, length, out);
    return (int)length;
}

int rasp_asset_vm_run(const uint32_t *type2, const uint8_t *last, const uint8_t base_key[32],
                      const rasp_region_t *regions, size_t region_count, const char *identity,
                      const uint8_t *package, size_t package_len, const uint32_t inputs[8],
                      uint32_t max_steps, uint32_t *result) {
    uint8_t program[8192 + 16];
    int length = rasp_asset_open(type2, last, base_key, regions, region_count, identity,
                                package, package_len, program, sizeof(program));
    int status = -1;
    if (length > 16) status = rasp_vm_run(program + 16, (size_t)length - 16, program, inputs, max_steps, result);
    asset_wipe(program, sizeof(program));
    return status;
}
