#  Ofuscação de Código com Algoritmo Genético

Este é um código Python que realiza a ofuscação de código em arquivos binários usando o algoritmo genético. Ele é projetado para tornar o código de um programa mais difícil de entender, prevenindo a engenharia reversa. A ofuscação de código é muito importante para garantir a segurança e autenticidade dos softwares, pois esconde o comportamento real do código, dificultando que pessoas mal intencionadas copiem o código sem autorização ou achem vulnerabilidades para ataques.

## Funcionamento

O projeto funciona da seguinte forma:

- **Inicialização da População**: O algoritmo genético começa criando uma população inicial de indivíduos. Cada indivíduo contém uma versão ofuscada do código original.

- **Mutação**: Em cada geração, o algoritmo seleciona o melhor indivíduo da população atual e realiza uma mutação nele. Isso envolve a substituição de uma parte do bytecode pelo código de máquina x86_64 de uma instrução aleatória em uma posição aleatória da seção `.text` do arquivo binário.

- **Avaliação**: Após cada mutação, o algoritmo executa o arquivo binário ofuscado e verifica se ele produz a mesma saída que o código original. Se a saída for a mesma, a mutação é bem-sucedida.

- **Evolução**: O algoritmo continua a mutação e evolução por um número específico de gerações.

- **Resultado Final**: O código-fonte do melhor indivíduo é salvo em um arquivo binário, produzindo uma versão ofuscada do código original.


## Requisitos

Antes de começar, certifique-se de ter os seguintes requisitos instalados:

- **Python**: Você precisa ter o Python instalado no seu sistema. Se ainda não o tiver, você pode baixá-lo em [python.org](https://www.python.org/).

- **Linux**: O código utiliza módulos específicos do Linux, portanto esta plataforma é um requisito.

- **keystone-engine**: Esta biblioteca é usada para montar o código de máquina de instruções x86_64.
```
pip install keystone-engine
```
- **pyelftools**: Esta biblioteca é usada para trabalhar com arquivos ELF.
```
pip install pyelftools
```
- **iced-x86**: Esta biblioteca é usada para disassemblar e assemblar binários.
```
pip install iced-x86
```
Agora, com todas as bibliotecas instaladas, você pode seguir as instruções fornecidas abaixo para ofuscar o código do arquivo binário. Certifique-se de que todas as dependências estejam satisfeitas antes de executar o código de ofuscação.

## Uso Básico

Siga estas etapas para ofuscar um arquivo binário com o código fornecido:

- **Clone o Repositório**: Clone o repositório Git que contém o código de ofuscação.
```
git clone https://github.com/atila-b/Projeto_Final_IHS_2023.1/
```

- **Navegue até o diretório**: Acesse o diretório onde o código de ofuscação binário está localizado.
```
cd seu-repositorio
```
- **Execute o Código**: Execute o código Python fornecido com o caminho para o arquivo binário que deseja ofuscar.
```
python obfuscate.py
```
- **Siga as Instruções**: O código solicitará o caminho do arquivo binário de entrada. Forneça o caminho completo do arquivo binário que você deseja ofuscar.

- **Resultados**: Após a conclusão, o código mostrará informações sobre o melhor indivíduo encontrado, incluindo o número de instruções de ofuscação inseridas.

- **Arquivo de Saída**: O arquivo binário ofuscado será criado no mesmo diretório com um sufixo _obfuscated. Este é o arquivo de saída final com o código ofuscado.

## Resultados

Nesta seção se econtram os resultados obtidos nas ofuscações de comandos *Linux*. Para cada binário ofuscado, é apresentada a porcentagem de diferença dos seus disassembles, seguido do número de gerações utilizado e o respectivo tempo de execução.

- **ls**: 84,28% de ofuscação (10.000 gerações, X minutos e X segundos de execução)

- **pwd**: 82,15% de ofuscação (10.000 gerações, X minutos e X segundos de execução)
 
- **whoami**: 82,16% de ofuscação (10.000 gerações, X minutos e X segundos de execução)

## Notas Adicionais

- O programa usa o código de máquina de instruções aleatórias em x86_64 para ofuscar o código original.

- O programa sobrescreve os bytes da seção `.text` do arquivo original, mantendo o tamanho original do código.

- O nível de ofuscação pode variar dependendo dos parâmetros do algoritmo genético. Quanto maior o número de gerações, maior será a ofuscação.

- É importante ajustar o parâmetro *timeout* da função *exec_bin()*, que irá limitar o tempo de execução do arquivo ofuscado. O *timeout* deve ser calculado de forma coerente com o tempo de execução original, caso contrário, o algoritmo genético pode não achar soluções. Esse parâmetro foi necessário devido a algumas ofuscações aumentarem drasticamente o tempo de execução. Com o *timeout* definido, essas ofuscações serão descartadas.

- O programa verifica a corretude do código ofuscado através do sucesso da sua execução e da sua saída no terminal. Portanto, é necessário que, caso haja uma saída, ela esteja no terminal. Isso acontece porque alguns executáveis, por exemplo o *ls*, funcionam de forma diferente quando o *stdout* é redirecionado, levando a comportamentos inconsistentes quando executados no terminal. Porém, o código pode ser facilmente adaptado para verificar a saída em arquivos.

- Lembre-se de que a eficácia da ofuscação pode depender do tamanho e da complexidade do código original.

- A pasta /bin/ contém os arquivos executáveis originais e ofuscados de comandos *Linux* que foram usados como exemplo.

- A pasta /disassemble/ contém o disassemble dos códigos originais e ofuscados.

- Para verificar as diferenças entre o código original e o código ofuscado, você pode disassemblar a seção `.text` dos códigos com o comando *objdump* e em seguida usar comandos como *vimdiff* ou *cmp* para examinar as ofuscações. O arquivo *compare_bins.txt* contém exemplos de códigos *bash* que calculam a porcentagem de diferença entre o disassemble dos arquivos originais e ofuscados.

- Espero que este código seja útil para você e sua equipe. Se você tiver alguma dúvida ou precisar de suporte, não hesite em entrar em contato.
