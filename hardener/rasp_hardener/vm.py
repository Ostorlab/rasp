"""Constrained 32-bit arithmetic virtualization with per-build opcodes.

Eight registers, fixed eight-byte instructions, no memory access or system calls,
whole-program validation and an explicit execution budget. This is a bounded VM,
not a translator for arbitrary native functions.
"""
from __future__ import annotations

import ast
import dataclasses
import struct

from rasp_hardener import seed

MAX_INSTRUCTIONS = 1024
MAX_STEPS = 1_000_000
SUPPORTED = {"NOP", "ADD", "SUB", "XOR", "AND", "OR", "LOAD", "CMP", "JMP", "MOV", "SHL", "SHR", "RET"}
BINARY = {"ADD", "SUB", "XOR", "AND", "OR", "CMP", "SHL", "SHR"}


@dataclasses.dataclass(frozen=True, slots=True)
class Instruction:
    op: str
    dst: int = 0
    left: int = 0
    right: int = 0
    immediate: int = 0


def opcode_bytes(profile: seed.BuildProfile) -> bytes:
    return bytes(profile.opcode_map[name] for name in seed.BASE_OPCODES)


def decode(code: bytes, opcodes: bytes) -> list[Instruction]:
    if len(opcodes) != 16 or len(set(opcodes)) != 16:
        raise ValueError("opcode table must contain 16 distinct bytes")
    if len(code) == 0 or len(code) % 8 != 0 or len(code) > MAX_INSTRUCTIONS * 8:
        raise ValueError("invalid program size")
    names = {opcode: name for opcode, name in zip(opcodes, seed.BASE_OPCODES)}
    program = []
    for offset in range(0, len(code), 8):
        opcode, dst, left, right, immediate = struct.unpack_from("<BBBBI", code, offset)
        op = names.get(opcode)
        if op not in SUPPORTED or dst >= 8 or left >= 8 or right >= 8:
            raise ValueError("invalid opcode or register")
        if op == "JMP" and immediate >= len(code) // 8:
            raise ValueError("jump target outside program")
        program.append(Instruction(op, dst, left, right, immediate))
    return program


def assemble(program: list[Instruction], profile: seed.BuildProfile) -> bytes:
    try:
        code = b"".join(struct.pack("<BBBBI", profile.opcode_map[item.op], item.dst, item.left, item.right, item.immediate) for item in program)
    except (KeyError, struct.error) as error:
        raise ValueError("invalid instruction") from error
    decode(code, opcode_bytes(profile))
    return code


def execute(code: bytes, opcodes: bytes, inputs: list[int], max_steps: int = 10000) -> int:
    program = decode(code, opcodes)
    if len(inputs) != 8 or any(value < 0 or value > 0xFFFFFFFF for value in inputs):
        raise ValueError("eight unsigned 32-bit input registers required")
    if max_steps <= 0 or max_steps > MAX_STEPS:
        raise ValueError("invalid execution budget")
    registers = list(inputs)
    pc = 0
    for _ in range(max_steps):
        if pc >= len(program):
            raise ValueError("program fell through without RET")
        item = program[pc]
        left, right = registers[item.left], registers[item.right]
        pc += 1
        if item.op == "RET":
            return registers[item.dst]
        if item.op == "JMP":
            if registers[item.dst] != 0:
                pc = item.immediate
            continue
        if item.op == "NOP":
            continue
        values = {"LOAD": item.immediate, "MOV": left, "ADD": left + right, "SUB": left - right,
                  "XOR": left ^ right, "AND": left & right, "OR": left | right, "CMP": int(left == right),
                  "SHL": left << (right & 31), "SHR": left >> (right & 31)}
        registers[item.dst] = values[item.op] & 0xFFFFFFFF
    raise ValueError("execution budget exhausted")


def compile_expression(expression: str, profile: seed.BuildProfile) -> bytes:
    """Compile an arithmetic expression over r0..r3; r4..r7 are scratch registers.

    Only integer constants, +, -, ^, &, |, << and >> are accepted. Shift counts are
    reduced modulo 32. Excessive nesting/register pressure is rejected.
    """
    if len(expression) > 2048:
        raise ValueError("expression too long")
    tree = ast.parse(expression, mode="eval")
    program: list[Instruction] = []
    free = [7, 6, 5, 4]
    operators = {ast.Add: "ADD", ast.Sub: "SUB", ast.BitXor: "XOR", ast.BitAnd: "AND", ast.BitOr: "OR", ast.LShift: "SHL", ast.RShift: "SHR"}

    def emit(node: ast.AST, depth: int = 0) -> int:
        if depth > 32:
            raise ValueError("expression nesting too deep")
        if isinstance(node, ast.Name) and node.id in {"r0", "r1", "r2", "r3"}:
            return int(node.id[1])
        if isinstance(node, ast.Constant) and type(node.value) is int and 0 <= node.value <= 0xFFFFFFFF:
            if len(free) == 0:
                raise ValueError("expression exceeds scratch registers")
            register = free.pop()
            program.append(Instruction("LOAD", register, immediate=node.value))
            return register
        if isinstance(node, ast.BinOp) and type(node.op) in operators:
            left, right = emit(node.left, depth + 1), emit(node.right, depth + 1)
            if left >= 4:
                destination = left
            elif right >= 4:
                destination = right
            elif len(free) > 0:
                destination = free.pop()
            else:
                raise ValueError("expression exceeds scratch registers")
            program.append(Instruction(operators[type(node.op)], destination, left, right))
            for register in {left, right} - {destination}:
                if register >= 4:
                    free.append(register)
            return destination
        raise ValueError("unsupported expression")

    result = emit(tree.body)
    program.append(Instruction("RET", result))
    return assemble(program, profile)
