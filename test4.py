import os
from elftools.elf.elffile import ELFFile
from keystone import *
from iced_x86 import *

# Inicialize o Keystone com a arquitetura x86_64
ks = Ks(KS_ARCH_X86, KS_MODE_64)

def disassemble_binary(binary_data):

    decoder = Decoder(64, binary_data, 0)
    formatter = FastFormatter()
    code = bytearray()

    # Monta o código de máquina a partir do arquivo binário
    for instr in decoder:
        disassembly = formatter.format(instr)
        print(disassembly)
        if disassembly != "(bad)":
            try:
                bytecode, _ = ks.asm(disassembly)
                code.extend(bytes(bytecode))
            except Exception as e:
                print(e)

def extract_edit_save_text_section(input_file_path, output_file_path, new_text_section_data):
    # Abra o arquivo binário em modo de leitura.
    with open(input_file_path, 'rb') as file:
        # Leitura do arquivo binário
        data = file.read()
        
        # Get objeto ELF do arquivo binário
        elf = ELFFile(file)
    
        # Get seção .text do ELF
        elf_section = elf.get_section_by_name(".text") 
        
        # Get binário da seção .text
        text_data = elf_section.data()
                                           
    # Encontre a posição inicial e final da seção .text
    section_start = elf_section['sh_offset'] 
    section_end   = section_start + elf_section['sh_size']
    
    # Insira instrução na seção .text
    text_data = insert_instruction_in_position(text_data, b'\x90', 5)
    #disassemble_binary(text_data)
    print(text_data)
    
    # Modificação dos dados do arquivo original
    data = data[:section_start] + text_data + data[section_end:]

    # Salve as edições de volta no arquivo binário.
    with open(output_file_path, 'wb') as file:
        file.write(data)
    
    # Defina as permissões de execução no arquivo editado.
    os.chmod(output_file_path, 0o777)  # 0o777 representa permissões rwxr-xr-x (r = read, w = write, x = execute)
    
def insert_instruction_in_position(code, inst, position):
    return code[:position] + inst + code[position:]

# Main
input_file_path = 'hello.bin'
output_file_path = 'helloM.bin'
new_text_section_data = b'\x90\x90\x90\x90'  # Substitua com os dados desejados para a seção .text
extract_edit_save_text_section(input_file_path, output_file_path, new_text_section_data)
