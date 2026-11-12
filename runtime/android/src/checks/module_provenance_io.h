/// Fixed-signature C boundary for the inactive collector's own-process file open.
#pragma once
#ifdef __cplusplus
extern "C" {
#endif
/// Opens only own-process maps; returns a descriptor or negative captured errno.
__attribute__((visibility("hidden"))) int rasp_module_open_maps(void);
#ifdef __cplusplus
}
#endif
