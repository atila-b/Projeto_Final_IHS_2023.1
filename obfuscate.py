import ctypes
import mmap

# Cabeçalhos para uso do mmap
PROT_READ = 0x1
PROT_WRITE = 0x2
PROT_EXEC = 0x4
MAP_PRIVATE = 0x2
MAP_ANONYMOUS = 0x20

# Monta o código de máquina x86_64
def generate_x86_64_code():
    code = bytearray()
    
    # Código de máquina x86_64 para a função soma
    # int soma(int a, int b) {
    #     return a + b;
    # }
    code.extend(b"\x48\x89\xf8")  # mov rax, rdi 
    code.extend(b"\x48\x01\xf0")  # add rax, rsi 
    code.extend(b"\xc3")          # ret 
    
    return code

# Aloca memória executável
code = generate_x86_64_code()
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
