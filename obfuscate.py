import os
import random
from elftools.elf.elffile import ELFFile
from keystone import *
from iced_x86 import *

# Implementação do gerador de instruções aleatórias em x86_64

# Registradores
regs = ["rdi", "rsi", "rax", "rbx", "rcx", "rdx", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"]
         
# Opcodes das instruções           
opcodes = ["mov int", "mov", "cmp", "jmp", "jg", "jl", "je", "jne", "add", "sub", "imul", "idiv",
           "and", "or", "xor", "shl", "shr", "test", "inc"]

# Inicialize o Keystone com a arquitetura x86_64
ks = Ks(KS_ARCH_X86, KS_MODE_64)

# Retorna o código de máquina x86_64 de uma instrução aleatória (por exemplo, "mov rax, rdx")
def random_instruction_code_x86():
    # Selecione um opcode aleatório
    opcode = random.choice(opcodes)
    
    # Monte uma instrução aleatória com o opcode
    if opcode == "mov":
        assembly_code =  f"mov {random.choice(regs)}, {random.choice(regs)}"
    elif opcode == "mov int":
        assembly_code = f"mov {random.choice(regs)}, {random.randint(-1000, 1000)}"
    elif opcode == "cmp":
        assembly_code = f"cmp {random.choice(regs)}, {random.choice(regs)}"
    elif opcode == "jmp":
        assembly_code = f"jmp {random.randint(-1000, 1000)}"
    elif opcode == "jg":
        assembly_code = f"jg {random.randint(-1000, 1000)}"
    elif opcode == "jl":
        assembly_code = f"jl {random.randint(-1000, 1000)}"
    elif opcode == "je":
        assembly_code = f"je {random.randint(-1000, 1000)}"
    elif opcode == "jne":
        assembly_code = f"jne {random.randint(-1000, 1000)}"
    elif opcode == "add":
        assembly_code = f"add {random.choice(regs)}, {random.choice(regs)}"
    elif opcode == "sub":
        assembly_code = f"sub {random.choice(regs)}, {random.choice(regs)}"
    elif opcode == "imul":
        assembly_code = f"imul {random.choice(regs)}, {random.choice(regs)}"
    elif opcode == "idiv":
        assembly_code = f"idiv {random.choice(regs)}"
    elif opcode == "and":
        assembly_code = f"and {random.choice(regs)}, {random.choice(regs)}"
    elif opcode == "or":
        assembly_code = f"or {random.choice(regs)}, {random.choice(regs)}"
    elif opcode == "xor":
        assembly_code = f"xor {random.choice(regs)}, {random.choice(regs)}"
    elif opcode == "shl":
        assembly_code = f"shl {random.choice(regs)}, {random.randint(1, 64)}"
    elif opcode == "shr":
        assembly_code = f"shr {random.choice(regs)}, {random.randint(1, 64)}"
    elif opcode == "test":
        assembly_code = f"test {random.choice(regs)}, {random.choice(regs)}"
    elif opcode == "inc":
        assembly_code = f"inc {random.choice(regs)}"

    #print(f"Inserindo código x86_64 da instrução: {assembly_code}")
    
    # Get código x86_64 da instrução e retorne
    bytecode, _ = ks.asm(assembly_code)
    return bytes(bytecode)

class Individual:
    def __init__(self, text_section, obfuscation_insts, fit_value):
        self.text_section = text_section
        self.obfuscation_insts = obfuscation_insts
        self.fit_value = fit_value

class GA:
    def __init__(self, generations):
        self.generations = generations
        self.population = []
        self.top_individual = None
        
    # Inicia uma população de indivíduos
    def init_population(self):
      # Gere um indivíduo
      text_section, init_inst = edit_save_text_section(text_data, input_file_path, output_file_path)
      individual = Individual(text_section=text_section, obfuscation_insts=[init_inst], fit_value=1)

      # Insira o indivíduo na população
      self.population.append(individual)
            
    # Sobrescreve uma instrução aleatória no indivíduo
    def mutation(self, individual):
        # Sobrescreva uma instrução aleatória na text section do indivíduo
        text_section, inst = edit_save_text_section(individual.text_section, input_file_path, output_file_path)
        
        # Atualize os atributos do filho
        individual.text_section = text_section
        individual.obfuscation_insts.append(inst)
        individual.fit_value += 1
        
    # Inicializa a população e faz o loop de gerações
    def evolution(self):
        print("Inicializando a população de indivíduos...")
        # Inicialize a população
        self.init_population()
        
        print("Evoluindo as gerações...")
        # Para cada geração, aplique a mutação
        for i in range(self.generations):
          # Printe o andamento de 100 em 100 gerações
          if (i+1)%100 == 0:
            print(f"Mutação da geração {i+1}...")
          self.mutation(self.population[0])

# Extrai a section .text do arquivo binário       
def extract_text_section(input_file_path, output_file_path):
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
        
        file.close()
                                           
    # Encontre a posição inicial e final da seção .text
    section_start = elf_section['sh_offset'] 
    section_end   = section_start + elf_section['sh_size']
    
    return data, text_data, section_start, section_end
    
# Edita a section .text do arquivo binário e sobrescreve instruções nela até que a execução funcione
def edit_save_text_section(text_data, input_file_path, output_file_path):
    # Sobrescreva instruções na seção .text até a execução ser bem sucedida
    while 1:
        # Instrução a ser inserida na section .text
        inst = random_instruction_code_x86()
        
        # Posição aleatória
        position = random.randint(0, len(text_data))
        
        # Sobrescreva uma instrução em posição aleatória da section .text
        new_text_data = insert_instruction_in_position(text_data, inst, position)
        
        # Modificação dos dados do arquivo original
        new_data = data[:section_start] + new_text_data + data[section_end:]
    
        # Salve as edições de volta no arquivo binário.
        with open(output_file_path, 'wb') as file:
            file.write(new_data)
            file.close()
        
        # Defina as permissões de execução no arquivo editado.
        os.chmod(output_file_path, 0o755)  
        
        # Execute o arquivo e verifica se o retorno está correto.
        if(exec_bin(timeout=0.05) == 0):
            #print(new_text_data)
            return new_text_data, [inst, position]
            break
    
# Sobrescreve código x86_64 em uma posição específica do bytearray
def insert_instruction_in_position(code, inst, position):
    code = bytearray(code)
    code[position:position+len(inst)] = inst
    return bytes(code)
    
# Execução de arquivos
import subprocess
import pty

# Execute e capture a saída do arquivo executável original
input_file_path = input("Insira o caminho do arquivo de entrada: ")
original_command = f'{input_file_path}'

# Crie um terminal virtual (pty)
master, sl = pty.openpty()

import fcntl

# Configure o master como não bloqueante
fcntl.fcntl(master, fcntl.F_SETFL, os.O_NONBLOCK)

# Execute o binário original
subprocess.call(original_command, stdout=sl, stderr=sl)

# Capture a saída da execução
original_stdout = os.read(master, 1024)

# Comando para executar o binário ofuscado
output_file_path = f"{input_file_path}_obfuscated"
obfuscated_command = f'{output_file_path}'

def exec_bin(timeout):
    try:
        # Execute o binário ofuscado
        subprocess.run(obfuscated_command, stdout=sl, stderr=sl, timeout=timeout)
        
        # Capture a saída da execução
        obfuscated_stdout = os.read(master, 1024)
        
        # Verifique se as saídas são iguais
        if original_stdout == obfuscated_stdout:
            return 0
        else:
            return -1
        
    except Exception as e:
        #print(f"Erro ao executar o comando '{command}': {e}")
        return -1
    return -1

# Main

# Extraia os dados e a seção .text do arquivo de entrada
data, text_data, section_start, section_end = extract_text_section(input_file_path, output_file_path)

# Execute o algoritmo genético
model = GA(generations=10000)
model.evolution()
    
top_individual = model.population[0]

# Printe os resultados
print(f"Melhor indivíduo:")
print(f"Número de instruções de ofuscação inseridas = {top_individual.fit_value}")

# Crie o arquivo de saída final com a section .text do melhor indivíduo
# Modificação dos dados do arquivo original
new_data = data[:section_start] + top_individual.text_section + data[section_end:]

# Salve as edições de volta no arquivo binário.
with open(output_file_path, 'wb') as file:
    file.write(new_data)
    file.close()

# Defina as permissões de execução no arquivo editado.
os.chmod(output_file_path, 0o777)

