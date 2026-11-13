/// Installed primitive API compile/link consumer; no platform attachment or key creation.
#include <stdlib.h>

#include "layout.h"
#ifdef __cplusplus
#define RASP_KEYS_ZERO \
  {                    \
  }
#else
#define RASP_KEYS_ZERO {0}
#endif

int main(void) {
  RaspScopedKeyClientSpecV1 spec = RASP_KEYS_ZERO;
  RaspScopedKeyClientOpenedV1 opened = RASP_KEYS_ZERO;
  RaspScopedKeyAdmissionV1 admission = RASP_KEYS_ZERO;
  RaspScopedKeyTakeRequestV1 take = RASP_KEYS_ZERO;
  RaspScopedKeyControlV1 control = RASP_KEYS_ZERO;
  RaspScopedKeyControlResultV1 controlled = RASP_KEYS_ZERO;
#ifdef __cplusplus
  RaspScopedKeySubmitV1* submit = static_cast<RaspScopedKeySubmitV1*>(calloc(1, sizeof(RaspScopedKeySubmitV1)));
  RaspScopedKeyTakeResultV1* taken =
      static_cast<RaspScopedKeyTakeResultV1*>(calloc(1, sizeof(RaspScopedKeyTakeResultV1)));
#else
  RaspScopedKeySubmitV1* submit = calloc(1, sizeof(RaspScopedKeySubmitV1));
  RaspScopedKeyTakeResultV1* taken = calloc(1, sizeof(RaspScopedKeyTakeResultV1));
#endif
  if (submit == NULL || taken == NULL) {
    free(submit);
    free(taken);
    return 1;
  }
  spec.abi_version = submit->abi_version = take.abi_version = control.abi_version = 1;
  spec.struct_size = sizeof(spec);
  submit->struct_size = sizeof(*submit);
  take.struct_size = sizeof(take);
  control.struct_size = sizeof(control);
  control.action = RASP_SK_CLOSE_CLIENT;
  int failed = rasp_scoped_key_client_open_v1(&spec, sizeof(spec), &opened, sizeof(opened)) != RASP_SK_CALL_NOT_READY;
  failed |= rasp_scoped_key_submit_v1(submit, sizeof(*submit), &admission, sizeof(admission)) != RASP_SK_CALL_NOT_READY;
  failed |= rasp_scoped_key_take_v1(&take, sizeof(take), taken, sizeof(*taken)) != RASP_SK_CALL_NOT_READY;
  failed |=
      rasp_scoped_key_control_v1(&control, sizeof(control), &controlled, sizeof(controlled)) != RASP_SK_CALL_NOT_READY;
  failed |= opened.operation_status != RASP_SK_OP_UNAVAILABLE;
  free(taken);
  free(submit);
  return failed;
}
