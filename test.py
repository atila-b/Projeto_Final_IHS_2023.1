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
    
    # Extraia o código x86_64 da instrução e retorne
    bytecode, _ = ks.asm(assembly_code)
    return bytes(bytecode)

class Individual:
    def __init__(self, text_section):
        self.text_section = text_section
        self.obfuscation_insts = []
        self.fit_value = 0
        self.last_version = self

class GA:
    def __init__(self, generations):
        self.generations = generations
        self.population = []
        self.top_individual = None
        
    # Inicia uma população de indivíduos
    def init_population(self):
      # Gere um indivíduo
      individual = Individual(text_section=text_data)

      # Insira o indivíduo na população
      self.population.append(individual)
            
    # Sobrescreve uma instrução aleatória em uma posição aleatória do indivíduo
    def mutation(self, output_file_path, individual):
        # Sobrescreva instruções na seção .text até a execução ser bem sucedida
        while 1:
            # Instrução a ser inserida na section .text
            inst = random_instruction_code_x86()
            
            # Posição aleatória
            position = random.randint(0, len_text_data)
            
            # Sobrescreva a instrução aleatória na posição aleatória da section .text
            new_text_data = insert_instruction_in_position(individual.text_section, inst, position)
            
            # Modificação dos dados do arquivo original
            new_data = data[:section_start] + new_text_data + data[section_end:]

            # Salve as edições de volta no arquivo binário.
            with open(output_file_path, 'wb') as file:
                file.write(new_data)
                file.close()
            
            # Defina as permissões de execução no arquivo editado.
            os.chmod(output_file_path, 0o755)  
            
            ret = exec_bin(timeout=0.05)
            
            # Execute o arquivo e verifica se o retorno está correto.
            if ret == 0:
                # Atualize a última versão do indivíduo se a execução for bem sucedida
                individual.last_version = Individual(text_section = individual.text_section)
                individual.last_version.obfuscation_insts = individual.obfuscation_insts
                individual.last_version.fit_value = individual.fit_value
                
                # Atualize o indivíduo se a execução for bem sucedida
                individual.text_section = new_text_data
                individual.obfuscation_insts.append([inst, position])
                individual.fit_value += 1
                return individual
            else:
                # Se der timeout, volte para a versão anterior
                individual = individual.last_version

                    
    # Avalie o indivíduo com a porcentagem de diferença entre o bytecode original e o bytecode ofuscado
    def evaluate(self, individual):
        # Extraia os bytecodes
        bytecode1 = text_data
        bytecode2 = individual.text_section
    
        # Obtenha o número total de bytes nos bytecodes
        num_bytes = len(bytecode1)
    
        # Inicialize uma contagem de diferenças
        diff_count = sum(1 for i in range(num_bytes) if bytecode1[i] != bytecode2[i])
    
        # Calcule a porcentagem de diferença entre os bytecodes
        difference_percentage = (diff_count / num_bytes) * 100
    
        # Atualize o fit value do indivíduo
        individual.fit_value = difference_percentage
        
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
          #self.mutation(self.population[0])
          self.population[0] = self.mutation(output_file_path, self.population[0])
          
        self.evaluate(self.population[0])

# Extrai a section .text do arquivo binário       
def extract_text_section(input_file_path):
    # Abra o arquivo binário em modo de leitura.
    with open(input_file_path, 'rb') as file:
        # Leitura do arquivo binário
        data = file.read()
        
        # Extraia o  objeto ELF do arquivo binário
        elf = ELFFile(file)
    
        # Extraia a seção .text do ELF
        elf_section = elf.get_section_by_name(".text") 
        
        # Extraia o binário da seção .text
        text_data = elf_section.data()
        
        # Feche o arquivo
        file.close()
                                           
    # Encontre a posição inicial e final da seção .text
    section_start = elf_section['sh_offset'] 
    section_end   = section_start + elf_section['sh_size']
    
    return data, text_data, section_start, section_end
    
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

# Configure o master como não bloqueante
#os.set_blocking(master, False)
#os.set_blocking(sl, False)

# Execute o binário original
subprocess.run(original_command, stdout=sl, stderr=sl, check=True)

# Capture a saída da execução
original_stdout = os.read(master, 1024)

# Comando para executar o binário ofuscado
output_file_path = f"{input_file_path}_obfuscated"
obfuscated_command = f'{output_file_path}'

os.close(master)
os.close(sl)

def exec_bin(timeout):
    try:
        # Crie um terminal virtual (pty)
        master, sl = pty.openpty()
        
        # Configure o master como não bloqueante
        os.set_blocking(master, False)
        os.set_blocking(sl, False)
        
        # Limpe o terminal virtual
        #subprocess.run("clear", stdout=sl, stderr=sl, check=True)
        
        #data = os.read(master, 1024)
            
        # Execute o binário ofuscado
        ret = subprocess.run(obfuscated_command, stdout=sl, stderr=sl, check=True, timeout=timeout)
        
        # Capture a saída da execução           
        obfuscated_stdout = b''
        while True:
            try:
                data = os.read(master, 1024)
                if not data:
                    break
                obfuscated_stdout += data
            except Exception as e:
                #print(e)
                break
            
        os.close(master)
        os.close(sl)
        
        # Verifique se as saídas são iguais
        if original_stdout == obfuscated_stdout and ret.returncode == 0:
            return 0
        else:
            return -1
    except Exception as e:
        os.close(master)
        os.close(sl)
        #print(e)
        # Erro na execução
        return -1

# Main

# Extraia os dados e a seção .text do arquivo de entrada
data, text_data, section_start, section_end = extract_text_section(input_file_path)
len_text_data = len(text_data)

# Execute o algoritmo genético
model = GA(generations=10000)
model.evolution()
    
# Selecione o melhor indivíduo
top_individual = model.population[0]

# Printe os resultados
print(f"Melhor indivíduo:")
print(f"Porcentagem de ofuscação do bytecode: {round(top_individual.fit_value, 2)}%")

# Crie o arquivo de saída final com a section .text do melhor indivíduo
# Modificação dos dados do arquivo original
new_data = data[:section_start] + top_individual.text_section + data[section_end:]

# Salve as edições de volta no arquivo binário.
with open(output_file_path, 'wb') as file:
    file.write(new_data)
    file.close()

# Defina as permissões de execução no arquivo editado.
os.chmod(output_file_path, 0o755)

# Feche o terminal virtual pty
#os.close(master)
#os.close(sl)

