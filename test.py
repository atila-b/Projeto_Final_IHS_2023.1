import os
import random
from elftools.elf.elffile import ELFFile
from keystone import *
from iced_x86 import *

# Implementação do gerador de instruções aleatórias em x86_64

# Registradores
regs = ["rdi", "rsi", "rax", "rbx", "rcx", "rdx", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"]

# Random instructions
asm_instructions = [f"mov {random.choice(regs)}, {random.randint(-10000, 10000)}", 
                    f"mov {random.choice(regs)}, {random.choice(regs)}",
                    f"cmp {random.choice(regs)}, {random.choice(regs)}",
                    f"jmp {random.randint(-1000, 1000)}",
                    f"jg {random.randint(-1000, 1000)}",
                    f"jl {random.randint(-1000, 1000)}",
                    f"je {random.randint(-1000, 1000)}",
                    f"jne {random.randint(-1000, 1000)}",
                    f"add {random.choice(regs)}, {random.choice(regs)}",
                    f"sub {random.choice(regs)}, {random.choice(regs)}",
                    f"and {random.choice(regs)}, {random.choice(regs)}",
                    f"or {random.choice(regs)}, {random.choice(regs)}",
                    f"xor {random.choice(regs)}, {random.choice(regs)}",
                    f"shl {random.choice(regs)}, {random.randint(1, 64)}", 
                    f"shr {random.choice(regs)}, {random.randint(1, 64)}", 
                    ]

# Inicialize o Keystone com a arquitetura x86_64
ks = Ks(KS_ARCH_X86, KS_MODE_64)

# Retorna o código de máquina x86_64 de uma instrução 'mov rx, int' aleatória (por exemplo, "mov rbx, 42")
def random_instruction_code_x86():
    assembly_code = random.choice(asm_instructions)
    print(f"Inserindo código x86_64 da instrução: {assembly_code}")
    bytecode, _ = ks.asm(assembly_code)
    return bytes(bytecode)

class Individual:
    def __init__(self, text_section, init_inst):
        self.text_section = text_section
        self.obfuscation_insts = [init_inst]
        self.fit_value = 0

class Model:
    def __init__(self, population_size, generations):
        self.population_size = population_size
        self.generations = generations
        self.population = []
        self.top_individual = None
        
    def init_population(self):
        for i in range(self.population_size):
          # Gere um indivíduo
          text_section, init_inst = extract_edit_save_text_section(input_file_path, output_file_path)
          individual = Individual(text_section=text_section, init_inst=init_inst)
          individual.fit_value += 1
    
          # Insira o indivíduo na população
          self.population.append(individual)

# Extrai a section .text do arquivo e insere instruções nela até que a execução funcione
def extract_edit_save_text_section(input_file_path, output_file_path):
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
    
    # Insira instruções na seção .text até a execução ser bem sucedida
    while 1:
        # Instrução a ser inserida na section .text
        inst = b'\x90\x90\x90'
        position = random.randint(0, len(text_data))
        
        # Insira instrução em posição aleatória da section .text
        new_text_data = insert_instruction_in_position(text_data, inst, position)
        
        # Modificação dos dados do arquivo original
        new_data = data[:section_start] + new_text_data + data[section_end:]
    
        # Salve as edições de volta no arquivo binário.
        with open(output_file_path, 'wb') as file:
            file.write(new_data)
        
        # Defina as permissões de execução no arquivo editado.
        os.chmod(output_file_path, 0o777)  
        
        # Execute o arquivo e verifica se o retorno está correto.
        if(exec_bin() == 0):
            #print(new_text_data)
            return new_text_data, (inst, position)
            break
    
# Insere código x86_64 em uma posição específica do bytearray
def insert_instruction_in_position(code, inst, position):
    code = bytearray(code)
    code[position:position+len(inst)] = inst
    return bytes(code)

    
# Executa arquivo binário
import subprocess

def exec_bin():
    arquivo_binario = 'helloM.bin'
    
    # Comando para executar o arquivo binário.
    comando = f'./{arquivo_binario}' 
    
    # Tente executar o arquivo binário e capturar a saída.
    try:
        resultado = subprocess.run(comando, shell=True, check=True, stdout=subprocess.PIPE, text=True)
        saida = resultado.stdout
        print(f"Saída do arquivo binário:\n{saida}")
        return 0
    except subprocess.CalledProcessError as e:
        #print(f"Erro ao executar o arquivo binário: {e}")
        return -1
    except FileNotFoundError:
        #print(f"O arquivo binário '{arquivo_binario}' não foi encontrado.")
        return -1


# Main
input_file_path = 'hello.bin'
output_file_path = 'helloM.bin'
extract_edit_save_text_section(input_file_path, output_file_path)

# Algoritmo genético
model = Model(population_size=100, generations=1000)
model.init_population()
