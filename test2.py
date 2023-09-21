from iced_x86 import *

def disassemble_binary_file(file_path):
    with open(file_path, 'rb') as f:
        binary_data = f.read()
    
    decoder = Decoder(64, binary_data, 0)
    formatter = FastFormatter()
    
    for instr in decoder:
        # Desmonta a instrução
        disassembly = formatter.format(instr)
        print(disassembly)

if __name__ == "__main__":
    binary_file_path = "hello.bin"  # Substitua pelo caminho do seu arquivo binário
    disassemble_binary_file(binary_file_path)
