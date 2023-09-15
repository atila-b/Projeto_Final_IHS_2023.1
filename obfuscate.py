import ctypes
import mmap

# Cabeçalhos para uso do mmap
PROT_READ = 0x1
PROT_WRITE = 0x2
PROT_EXEC = 0x4
MAP_PRIVATE = 0x2
MAP_ANONYMOUS = 0x20

def insert_instruction(bytecode, instruction):
    bytecode.extend(instruction)
    
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
        print(f"A soma de {a} e {b} é {result}")
        
        # Libera a memória alocada
        mem.close()
    
    except error:
        print(error)
        
# Main
    
code_x86 = bytearray()

# Inserindo instruções no bytearray
insert_instruction(code_x86, b"\x48\x89\xf8")
insert_instruction(code_x86, b"\x48\x01\xf0")
insert_instruction(code_x86, b"\xc3")

compile_and_execute(code_x86)
