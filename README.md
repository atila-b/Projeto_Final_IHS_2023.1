#  Ofuscação de Código com Algoritmo Genético

Este é um código Python que realiza a ofuscação de código em arquivos binários usando o algoritmo genético. Ele é projetado para tornar o código de um programa mais difícil de entender, prevenindo a engenharia reversa. A ofuscação de código é muito importante para garantir a segurança e autenticidade dos softwares, pois esconde o comportamento real do código, dificultando que pessoas mal intencionadas copiem o código sem autorização ou achem vulnerabilidades para ataques.

## Requisitos

Antes de começar, certifique-se de ter os seguintes requisitos instalados:

- Python: Você precisa ter o Python instalado no seu sistema. Se ainda não o tiver, você pode baixá-lo em [python.org](https://www.python.org/).

- keystone-engine: Esta biblioteca é usada para montar o código de máquina de instruções x86_64.
```
pip3 install keystone
```
- pyelftools: Esta biblioteca é usada para trabalhar com arquivos ELF.
```
pip3 install pyelftools
```
- iced-x86: Esta biblioteca é usada para disassemblar e assemblar binários.
```
pip3 install iced-x86
```
Agora, com todas as bibliotecas instaladas, você pode seguir as instruções fornecidas abaixo para ofuscar o código do arquivo binário. Certifique-se de que todas as dependências estejam satisfeitas antes de executar o código de ofuscação.

## Uso Básico

Siga estas etapas para ofuscar um arquivo binário com o código fornecido:

- Clone o Repositório: Clone o repositório Git que contém o código de ofuscação.
```
git clone https://github.com/atila-b/Projeto_Final_IHS_2023.1/
```

- Navegue até o Diretório: Acesse o diretório onde o código de ofuscação binário está localizado.
```
cd seu-repositorio
```
- Execute o Código: Execute o código Python fornecido com o caminho para o arquivo binário que deseja ofuscar.
```
python obfuscate.py
```
- Siga as Instruções: O código solicitará o caminho do arquivo binário de entrada. Forneça o caminho completo do arquivo binário que você deseja ofuscar.

- Resultados: Após a conclusão, o código mostrará informações sobre o melhor indivíduo encontrado, incluindo o número de instruções de ofuscação inseridas.

- Arquivo de Saída: O arquivo binário ofuscado será criado no mesmo diretório com um sufixo _obfuscated. Este é o arquivo de saída final com o código ofuscado.

## Notas Adicionais

- O programa usa o código de máquina de instruções aleatórias em x86_64 para ofuscar o código original.

- O nível de ofuscação pode variar dependendo dos parâmetros do algoritmo genético. Quanto maior o tamanho da população e o número de gerações, maior será a ofuscação.

- Lembre-se de que a eficácia da ofuscação pode depender do tamanho e da complexidade do código original.

- Para verificar as diferenças entre o código original e o código ofuscado, você pode disassemblar os códigos com o comando *objdump* e em seguida usar o comando *vimdiff* para visualizar as ofuscações.

- Espero que este código seja útil para você e sua equipe. Se você tiver alguma dúvida ou precisar de suporte, não hesite em entrar em contato.
