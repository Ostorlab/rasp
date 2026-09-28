#ifndef RASP_HARDENING_H
#define RASP_HARDENING_H

/* Umbrella for build-time hardening; included first by every core header so all translation units see the
 * same macro renames and literal API (mismatched renames would fail to link). */

#if defined(__has_include)
#if __has_include("build_names.h")
#include "build_names.h"
#endif
#endif

#endif
