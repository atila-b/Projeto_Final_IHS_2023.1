import os
import random
from elftools.elf.elffile import ELFFile
from keystone import *
from iced_x86 import *

# Implementação do gerador de instruções aleatórias em x86_64

# Registradores
regs = ["rdi", "rsi", "rax", "rbx", "rcx", "rdx", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"]
         
# Opcodes das instruções           
opcodes = ["mov", "cmp", "jmp", "jg", "jl", "je", "jne", "add", "sub", "imul", "idiv",
           "and", "or", "xor", "shl", "shr"]

# Inicialize o Keystone com a arquitetura x86_64
ks = Ks(KS_ARCH_X86, KS_MODE_64)

# Retorna o código de máquina x86_64 de uma instrução 'mov rx, int' aleatória (por exemplo, "mov rbx, 42")
def random_instruction_code_x86():
    # Selecione um opcode aleatório
    opcode = random.choice(opcodes)
    
    # Monte uma instrução aleatória com o opcode
    if opcode == "mov":
        assembly_code =  f"mov {random.choice(regs)}, {random.choice(regs)}"
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
    def __init__(self, population_size, generations):
        self.population_size = population_size
        self.generations = generations
        self.population = []
        self.top_individual = None
        
    def init_population(self):
        for i in range(self.population_size):
          # Gere um indivíduo
          text_section, init_inst = edit_save_text_section(text_data, input_file_path, output_file_path)
          individual = Individual(text_section=text_section, obfuscation_insts=[init_inst], fit_value=1)
    
          # Insira o indivíduo na população
          self.population.append(individual)
          
    def crossover(self):
        for i in range(0, int(self.population_size/2), 2):
            # Escolha aleatoriamente quem será o pai 1 e o pai 2
            fathers = [self.population[i], self.population[i+1]]
            father_1 = random.choice(fathers)
            for i in range(2):
                if fathers[i] == father_1:
                    continue
                else:
                    father_2 = fathers[i]
                    
            # Fit value inicial
            fit_value = father_1.fit_value
                    
            # Get text section do pai 1
            text_section = father_1.text_section
            
            # Get obfuscation insts do pai 1
            obfuscation_insts = father_1.obfuscation_insts
            
            # Cruze com a text section do pai 2
            for j in range(len(father_2.obfuscation_insts)):
                # Get instrução e posição de cada dead code
                inst = father_2.obfuscation_insts[j][0]
                #position = father_2.obfuscation_insts[j][1]
                
                # Insira a instrução em uma posição aleatória da section .text
                new_text_data, position = insert_instruction_in_position(text_section, inst)
                
                # Modificação dos dados do arquivo original
                new_data = data[:section_start] + new_text_data + data[section_end:]
            
                # Salve as edições de volta no arquivo binário.
                with open(output_file_path, 'wb') as file:
                    file.write(new_data)
                
                # Defina as permissões de execução no arquivo editado.
                os.chmod(output_file_path, 0o777)  
                
                # Execute o arquivo e verifica se o retorno está correto.
                if(exec_bin() == 0):
                    # Se a instrução ainda não foi inserida
                    if([inst, position] not in obfuscation_insts):
                        # Incremente fit value, atualize a text section e insira a instrução de ofuscação
                        fit_value += 1
                        text_section = new_text_data
                        obfuscation_insts.append([inst, position])
                  
            # Gere novo filho  
            children = Individual(text_section=text_section, obfuscation_insts=obfuscation_insts, fit_value=fit_value)
            
            # Aplique a mutação no filho
            self.mutation(children)
            
            # Insira novo filho na população
            self.population.append(children)
            
    def mutation(self, children):
        # Insira uma instrução aleatória na text section do filho
        text_section, inst = edit_save_text_section(children.text_section, input_file_path, output_file_path)
        
        # Atualize os atributos do filho
        children.text_section = text_section
        children.obfuscation_insts.append(inst)
        children.fit_value += 1
        
    def tournament(self):
        # Sort population pelo fit value
        return sorted(self.population, key = lambda x: x.fit_value, reverse=True)
        
    def evolution(self):
        print("Inicializando a população de indivíduos...")
        # Inicialize a população
        self.init_population()
        
        print("Evoluindo as gerações...")
        # Para cada geração, aplique o crossover e evolua a população
        for i in range(self.generations):
          self.crossover()
          self.population = self.tournament()[:self.population_size]

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
                                           
    # Encontre a posição inicial e final da seção .text
    section_start = elf_section['sh_offset'] 
    section_end   = section_start + elf_section['sh_size']
    
    return data, text_data, section_start, section_end
    
# Edita a section .text do arquivo binário e insere instruções nela até que a execução funcione
def edit_save_text_section(text_data, input_file_path, output_file_path):
    # Insira instruções na seção .text até a execução ser bem sucedida
    while 1:
        # Instrução a ser inserida na section .text
        inst = random_instruction_code_x86()
        #position = random.randint(0, len(text_data))

        # Insira instrução em posição aleatória da section .text
        new_text_data, position = insert_instruction_in_position(text_data, inst)
        
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
            return new_text_data, [inst, position]
            break
        
def disassemble_bytearray(bytecode):
    # Crie um decodificador
    decoder = Decoder(64, bytearray(bytecode), ip=0x1000)

    instructions = []

    # Loop para decodificar cada instrução
    for instr in decoder:
        # Obtém o tamanho da instrução em bytes
        instr_size = instr.len

        # Obtém os bytes da instrução a partir do bytearray original
        instruction_bytes = bytecode[:instr_size]

        # Atualize o bytearray original para avançar para a próxima instrução
        bytecode = bytecode[instr_size:]

        # Adicione os bytes da instrução à lista de instruções
        instructions.append(instruction_bytes)

    return instructions
    
def assemble_bytecode(instructions):
    # Inicialize um bytearray vazio para armazenar o bytecode reconstruído
    bytecode = bytearray()
    
    # Concatene os bytes de cada instrução
    for instr_bytes in instructions:
        bytecode.extend(instr_bytes)

    return bytes(bytecode)
    
# Insere código x86_64 em uma posição específica do bytearray
def insert_instruction_in_position(code, inst):
    # Disassemble o bytecode
    instructions = disassemble_bytearray(code)
    
    # Escolha uma posição aleatória
    position = random.randint(0, len(instructions))
    
    # Insira a instrução na posição
    instructions.insert(position, inst)
    
    # Assemble o bytecode novamente e retorne
    return assemble_bytecode(instructions), position

# Executa arquivo binário
import subprocess

def exec_bin():
    # Comando para executar o arquivo binário.
    comando = f'./{output_file_path} 2>/dev/null' 
    
    # Tente executar o arquivo binário e capturar a saída.
    try:
        resultado = subprocess.run(comando, shell=True, check=True, stdout=subprocess.PIPE, text=True)
        saida = resultado.stdout
        #print(f"Saída do arquivo binário:\n{saida}")
        print("execução bem sucedida")
        return 0
    except subprocess.CalledProcessError as e:
        #print(f"Erro ao executar o arquivo binário: {e}")
        return -1
    except Exception as e:
        #print(f"Erro ao executar o arquivo binário: {e}")
        return -1
    except FileNotFoundError:
        #print(f"O arquivo binário '{arquivo_binario}' não foi encontrado.")
        return -1

# Main
# Variáveis globais
input_file_path = input("Insira o nome do arquivo de entrada: ")
output_file_path = f"obfuscated_{input_file_path}"

# Extrai dados e seção .text do arquivo de entrada
data, text_data, section_start, section_end = extract_text_section(input_file_path, output_file_path)

# Algoritmo genético
model = GA(population_size=100, generations=100)
model.evolution()

# Pegue o melhor indivíduo
top_individual = model.population[0]

# Printe os resultados
print(f"Melhor indivíduo:")
print(f"Número de instruções de ofuscação inseridas = {top_individual.fit_value}")
print(f"Instruções de ofuscação = {top_individual.obfuscation_insts}")
print(f"Bytecode final = {top_individual.text_section}")

# Crie o arquivo de saída final com a section .text do melhor indivíduo
# Modificação dos dados do arquivo original
new_data = data[:section_start] + top_individual.text_section + data[section_end:]

# Salve as edições de volta no arquivo binário.
with open(output_file_path, 'wb') as file:
    file.write(new_data)

# Defina as permissões de execução no arquivo editado.
os.chmod(output_file_path, 0o777)