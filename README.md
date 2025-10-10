Analisador de Vulnerabilidades com Nmap em Python
Este é um script em Python que automatiza a varredura de vulnerabilidades em um alvo (IP ou domínio) utilizando a poderosa ferramenta Nmap. O script foi desenvolvido com uma estrutura de classes (Programação Orientada a Objetos) para organizar o código, tornando-o mais limpo e reutilizável.

Ele processa os resultados da varredura e os exibe de forma organizada, destacando as portas abertas, os serviços em execução e as possíveis vulnerabilidades identificadas pelos scripts do Nmap.

✨ Funcionalidades
Interface Simples: Solicita um alvo via linha de comando.

Varredura Detalhada: Executa o Nmap com detecção de versão de serviço (-sV) e scripts de vulnerabilidade (--script vuln).

Estrutura Organizada: Utiliza uma classe NmapScanner para encapsular a lógica da varredura e da exibição dos resultados.

Saída Legível: Apresenta as informações de forma clara, separando por host, protocolo e porta.

Tratamento de Erros: Inclui verificação básica para o caso de o Nmap não estar instalado ou o alvo não ser encontrado.
