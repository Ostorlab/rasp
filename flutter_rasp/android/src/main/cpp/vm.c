#include "vm.h"
#include <string.h>

static int vm_decode(uint8_t byte, const uint8_t opcodes[16]) {
    for (int i = 0; i < 16; i++) if (byte == opcodes[i]) return i;
    return -1;
}
static uint32_t vm_immediate(const uint8_t *instruction) {
    return (uint32_t)instruction[4] | ((uint32_t)instruction[5] << 8) |
           ((uint32_t)instruction[6] << 16) | ((uint32_t)instruction[7] << 24);
}
int rasp_vm_run(const uint8_t *code, size_t length, const uint8_t opcodes[16],
                const uint32_t inputs[8], uint32_t max_steps, uint32_t *result) {
    if (!code || !opcodes || !inputs || !result || length == 0 || length % 8 != 0 ||
        length > 8192 || max_steps == 0 || max_steps > 1000000) return -1;
    for (int i = 0; i < 16; i++) for (int j = i + 1; j < 16; j++)
        if (opcodes[i] == opcodes[j]) return -1;
    for (size_t offset = 0; offset < length; offset += 8) {
        const uint8_t *instruction = code + offset;
        int op = vm_decode(instruction[0], opcodes);
        if (op < 0 || op == 7 || op == 10 || op == 11 || instruction[1] >= 8 ||
            instruction[2] >= 8 || instruction[3] >= 8 ||
            (op == 9 && vm_immediate(instruction) >= length / 8)) return -1;
    }
    uint32_t registers[8];
    memcpy(registers, inputs, sizeof(registers));
    size_t pc = 0;
    for (uint32_t step = 0; step < max_steps; step++) {
        if (pc >= length / 8) return -1;
        const uint8_t *instruction = code + pc++ * 8;
        int op = vm_decode(instruction[0], opcodes);
        uint8_t destination = instruction[1];
        uint32_t left = registers[instruction[2]], right = registers[instruction[3]];
        switch (op) {
            case 0: break;
            case 1: registers[destination] = left + right; break;
            case 2: registers[destination] = left - right; break;
            case 3: registers[destination] = left ^ right; break;
            case 4: registers[destination] = left & right; break;
            case 5: registers[destination] = left | right; break;
            case 6: registers[destination] = vm_immediate(instruction); break;
            case 8: registers[destination] = left == right; break;
            case 9: if (registers[destination] != 0) pc = vm_immediate(instruction); break;
            case 12: registers[destination] = left; break;
            case 13: registers[destination] = left << (right & 31); break;
            case 14: registers[destination] = left >> (right & 31); break;
            case 15: *result = registers[destination]; return 0;
            default: return -1;
        }
    }
    return -1;
}
