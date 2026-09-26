#ifndef RASP_DETECTORS_H
#define RASP_DETECTORS_H

#include "signals.h"

/* Each detector appends zero or more signals to `list`. None of them modify process state. */
void rasp_detect_su_binaries(rasp_signal_list_t *list);
void rasp_detect_root_mounts(rasp_signal_list_t *list);
void rasp_detect_selinux_permissive(rasp_signal_list_t *list);
void rasp_detect_emulator_files(rasp_signal_list_t *list);
void rasp_detect_tracer(rasp_signal_list_t *list);
void rasp_detect_instrumentation_maps(rasp_signal_list_t *list);
void rasp_detect_instrumentation_threads(rasp_signal_list_t *list);
void rasp_detect_instrumentation_port(rasp_signal_list_t *list);

/* Runs every native detector. */
void rasp_run_all(rasp_signal_list_t *list);

/* Exposed for host unit tests. */
int rasp_parse_tracer_pid(const char *status_text);
const char *rasp_match_any(const char *haystack, const char *const *needles, size_t count);

#endif
