#ifndef RASP_VM_H
#define RASP_VM_H
#include "hardening.h"
#include <stddef.h>
#include <stdint.h>
/* Eight uint32 registers. Opcode table follows seed.BASE_OPCODES order. Whole
 * program validation precedes execution; result is unchanged on every failure. */
int rasp_vm_run(const uint8_t *code, size_t length, const uint8_t opcodes[16],
                const uint32_t inputs[8], uint32_t max_steps, uint32_t *result);
#endif
