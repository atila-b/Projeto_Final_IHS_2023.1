import struct
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import Section

def extract_text_section(elf_filename, output_filename):
    with open(elf_filename, 'rb') as elf_file:
        elf = ELFFile(elf_file)
        text_section = None

        # Encontre a seção .text
        for section in elf.iter_sections():
            if section.name == '.text':
                text_section = section
                break

        if text_section:
            # Extraia os dados da seção .text
            text_data = text_section.data()
            
            # Escreva os dados modificados no arquivo ELF original
            elf_file.seek(text_section['sh_offset'])
            
            # Insira instrução na seção .text
            text_data = insert_instruction_in_position(text_data, b'\x90\x90\x90\x90', 0)
            
            print(text_data)
            #elf_file.write(text_data)
            #print(f'Instrução inserida na posição {hex(address)} na seção .text e salva no arquivo ELF.')
            
            # Escreva os dados em um arquivo de saída
            with open(output_filename, 'wb') as output_file:
                output_file.write(text_data)
            print(f'Seção .text extraída e salva em {output_filename}')
        else:
            print('Seção .text não encontrada no arquivo ELF.')
            
def insert_instruction_in_position(code, inst, position):
    return code[:position] + inst + code[position:]
    

if __name__ == '__main__':
    elf_filename = 'hello.bin'  # Substitua pelo nome do seu arquivo ELF
    output_filename = 'text_section.bin'  # Nome do arquivo de saída

    extract_text_section(elf_filename, output_filename)
