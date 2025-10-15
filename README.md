Este projeto foi criado para simplificar e agilizar a fase inicial de uma auditoria de segurança ou pentest. Ao fornecer um endereço IP, o script executa um escaneamento detalhado e apresenta um relatório claro e organizado, destacando as portas abertas e as possíveis falhas de segurança encontradas, facilitando a análise e a tomada de decisões.

Entrada de Alvo Interativa: Solicita ao usuário o endereço IP do alvo.

Detecção de Serviços e Versões: Utiliza o argumento -sV do Nmap para identificar qual software e versão estão rodando em cada porta.

Escaneamento de Vulnerabilidades: Executa todos os scripts da categoria vuln do Nmap (--script vuln) para encontrar falhas de segurança conhecidas.

Relatório Organizado: Exibe os resultados de forma estruturada, mostrando cada porta aberta, o serviço correspondente e os detalhes das vulnerabilidades encontradas.

Tratamento de Erros: Verifica se o Nmap está instalado e informa caso o host alvo esteja offline.

