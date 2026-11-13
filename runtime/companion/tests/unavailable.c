/// Real primitive C consumer; a companion with no platform attachment never succeeds.
#include <stdint.h>
#include <stdlib.h>

#include "rasp/scoped_key.h"

int main(void) {
  RaspScopedKeyClientSpecV1* input = calloc(1, sizeof(*input));
  RaspScopedKeyClientOpenedV1* output = calloc(1, sizeof(*output));
  if (input == NULL || output == NULL) {
    free(output);
    free(input);
    return 1;
  }
  input->abi_version = 1;
  input->struct_size = sizeof(*input);
  int32_t status = rasp_scoped_key_client_open_v1(input, sizeof(*input), output, sizeof(*output));
  int failed = status != RASP_SK_CALL_NOT_READY || output->operation_status != RASP_SK_OP_UNAVAILABLE;
  free(output);
  free(input);
  return failed;
}
