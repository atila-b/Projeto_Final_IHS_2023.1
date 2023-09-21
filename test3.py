import ctypes
from keystone import *
from iced_x86 import *
import ctypes
import mmap

# Cabeçalhos para uso do mmap
PROT_READ = 0x1
PROT_WRITE = 0x2
PROT_EXEC = 0x4
MAP_PRIVATE = 0x2
MAP_ANONYMOUS = 0x20

# Inicialize o Keystone com a arquitetura x86_64
ks = Ks(KS_ARCH_X86, KS_MODE_64)

def disassemble_binary_file(file_path):
    with open(file_path, 'rb') as f:
        binary_data = f.read()

    decoder = Decoder(64, binary_data, 0)
    formatter = FastFormatter()
    code = bytearray()

    # Monta o código de máquina a partir do arquivo binário
    for instr in decoder:
        disassembly = formatter.format(instr)
        #print(disassembly)
        if disassembly != "(bad)":
            try:
                bytecode, _ = ks.asm(disassembly)
                code.extend(bytes(bytecode))
            except Exception as e:
                pass
    '''    
     # Cria uma memória executável
    executable_memory = ctypes.create_string_buffer(code)

    # Obtém um ponteiro para a memória executável
    executable_function = ctypes.CFUNCTYPE(ctypes.c_void_p)(ctypes.addressof(executable_memory))

    # Executa o código gerado
    result = executable_function()
    
    '''
    # Aloca memória executável
    mem = mmap.mmap(-1, len(code)+1, prot=PROT_READ | PROT_WRITE | PROT_EXEC, flags=MAP_PRIVATE | MAP_ANONYMOUS)
    
    # Copia o código gerado para a memória alocada
    mem.write(code)
    
    # Cria um protótipo de função em Python que chama o código de máquina
    prototype = ctypes.CFUNCTYPE(ctypes.c_int, use_errno=True)
    jit = prototype(ctypes.addressof(ctypes.c_void_p.from_buffer(mem)))
    
    result = jit()
    
    # Libera a memória alocada
    mem.close()
    

    print(f"Resultado da execução: {result}")
    
    return


binary_file_path = "hello.bin"  # Substitua pelo caminho do seu arquivo binário
disassemble_binary_file(binary_file_path)
