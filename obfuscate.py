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
    
    except error:
        print(error)
        
# Main

instructions_array = []
code_x86 = bytearray()

# Insere instruções no array de instruções
append_instruction(instructions_array, b"\x48\x89\xf8")
append_instruction(instructions_array, b"\x48\x01\xf0")
append_instruction(instructions_array, b"\xc3")

# Insere instrução NOP na posição 2
#code_x86 = insert_instruction_in_position(code_x86, b"\x90", 2)

# Gera código x86_64
generate_code_x86(code_x86, instructions_array)

# Compila e executa código
compile_and_execute(code_x86)

print(code_x86)
print(instructions_array)
