import ctypes
import mmap

# Nome do arquivo binário que você deseja carregar e executar
nome_arquivo_binario = 'hello.bin'

try:
    # Abre o arquivo binário em modo leitura binária e mapeia-o em memória
    with open(nome_arquivo_binario, 'rb') as arquivo_binario:

        # Copiar o código binário para o espaço de memória executável
        binary_data = arquivo_binario.read()
        
        #print(bytearray(binary_data))
        
        exec_memory = mmap.mmap(-1, len(binary_data), mmap.MAP_PRIVATE | mmap.MAP_ANONYMOUS, mmap.PROT_READ | mmap.PROT_WRITE | mmap.PROT_EXEC)
        
        exec_memory.write(binary_data)

        # Executar o código no espaço de memória
        func = ctypes.CFUNCTYPE(None)(ctypes.addressof(ctypes.c_void_p.from_buffer(exec_memory)))
        resultado = func()

    # Fechar o espaço de memória
    exec_memory.close()

    # Imprime o resultado (você pode personalizar isso de acordo com o que sua função retorna)
    print(f"Resultado da execução: {resultado}")

except FileNotFoundError:
    print(f'O arquivo "{nome_arquivo_binario}" não foi encontrado.')

except Exception as e:
    print(f'Ocorreu um erro ao executar o arquivo binário: {str(e)}')
