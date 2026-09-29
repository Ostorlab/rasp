#ifndef RASP_DETECTORS_H
#define RASP_DETECTORS_H

#include "hardening.h"
#include "literals.h"

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
void rasp_detect_maps_exec_suspicious(rasp_signal_list_t *list);

/* Added detectors (design §4: broaden toward >=3 independent per threat). */
void rasp_detect_cpuinfo_emulator(rasp_signal_list_t *list);        /* emulator */
void rasp_detect_ttydrivers_emulator(rasp_signal_list_t *list);     /* emulator */
void rasp_detect_ksu_wchan(rasp_signal_list_t *list);              /* root-hiding side channel */
void rasp_detect_self_ptrace(rasp_signal_list_t *list);            /* debugger (behavioral) */

/* Runs every native detector. */
void rasp_run_all(rasp_signal_list_t *list);

/* Exposed for host unit tests. */
int rasp_parse_tracer_pid(const char *status_text);
const char *rasp_match_any(const char *haystack, const char *const *needles, size_t count);
int rasp_cpuinfo_is_emulator(const char *cpuinfo);
int rasp_ttydrivers_is_emulator(const char *drivers);
int rasp_wchan_is_suspicious(const char *wchan);
int rasp_selfptrace_is_debugged(long traceme_ret);

#endif
