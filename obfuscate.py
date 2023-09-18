# Implementação das instruções aleatórias em x86_64

from keystone import *
import random

# Registradores
regs = ["rdi", "rsi", "rax", "rbx", "rcx", "rdx", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"]

# Inicialize o Keystone com a arquitetura x86_64
ks = Ks(KS_ARCH_X86, KS_MODE_64)

# Retorna o código de máquina x86_64 de uma instrução 'mov rx, int' aleatória (por exemplo, "mov rbx, 42")
def random_mov_rx_int():
    assembly_code = f"mov {random.choice(regs)}, {random.randint(-10000, 10000)}"
    print(f"Inserindo código x86_64 da instrução: {assembly_code}")
    bytecode, _ = ks.asm(assembly_code)
    return bytes(bytecode)

import ctypes
import mmap

# Cabeçalhos para uso do mmap
PROT_READ = 0x1
PROT_WRITE = 0x2
PROT_EXEC = 0x4
MAP_PRIVATE = 0x2
MAP_ANONYMOUS = 0x20

# Insere instrução no final do bytecode
def append_instruction(instructions_array, instruction):
    instructions_array.append(instruction)
    
# Insere instrução em uma posição específica do bytecode
def insert_instruction_in_position(instructions_array, instruction, position):
    instructions_array.insert(position, instruction)

# Gera código x86_64
def generate_code_x86(code, instructions_array):
    for instruction in instructions_array:
        code.extend(instruction)
    
# Compila e executa o bytecode
def compile_and_execute(code):
    try:
        # Aloca memória executável
        mem = mmap.mmap(-1, len(code)+1, prot=PROT_READ | PROT_WRITE | PROT_EXEC, flags=MAP_PRIVATE | MAP_ANONYMOUS)
        
        # Copia o código gerado para a memória alocada
        mem.write(code)
        
        # Cria um protótipo de função em Python que chama o código de máquina
        prototype = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_int, ctypes.c_int, use_errno=True)
        jit = prototype(ctypes.addressof(ctypes.c_void_p.from_buffer(mem)))
        
        # Chama a função gerada
        a = 5
        b = 7
        result = jit(a, b)
        print(f"A soma de {a} e {b} é: {result}")
        
        # Libera a memória alocada
        mem.close()
    
    except Exception as error:
        print(error)
        
# Main code

instructions_array = []
code_x86 = bytearray()

# Insere instruções no array de instruções
append_instruction(instructions_array, b"\x48\x89\xf8")
append_instruction(instructions_array, b"\x48\x01\xf0")
append_instruction(instructions_array, b"\xc3")

# Gera código x86_64
generate_code_x86(code_x86, instructions_array)

print(f"Bytecode antes da ofuscação: {code_x86}")

# Insere instrução aleatória na posição X
insert_instruction_in_position(instructions_array, random_mov_rx_int(), 1)

# Gera código x86_64
generate_code_x86(code_x86, instructions_array)

print(f"Bytecode depois da ofuscação: {code_x86}")

# Compila e executa código
print("Execução do bytecode:")
compile_and_execute(code_x86)
