import nmap
import sys

def scan_vulnerabilities(target_ip):
    print(f"\n[*] Iniciando escaneamento de vulnerabilidades em: {target_ip}")
    print("[*] Isso pode levar vários minutos, por favor aguarde...")
    
    try:
        # Inicializa o PortScanner do Nmap
        scanner = nmap.PortScanner()
    except nmap.PortScannerError:
        print("[!] Erro: Nmap não encontrado no seu sistema.")
        print("[!] Por favor, instale o Nmap e tente novamente.")
        sys.exit(1)

    # Argumentos do Nmap:
    # -sV: Tenta determinar a versão do serviço rodando na porta
    # --script vuln: Executa todos os scripts da categoria 'vuln' para checar vulnerabilidades
    arguments = '-sV --script vuln'
    
    try:
        # Executa o escaneamento no alvo e nas portas mais comuns
        scanner.scan(hosts=target_ip, arguments=arguments)
    except Exception as e:
        print(f"[!] Ocorreu um erro durante o escaneamento: {e}")
        return

    # Processa e exibe os resultados
    if not scanner.all_hosts():
        print(f"\n[!] Nenhum host encontrado no endereço {target_ip}. Verifique se o IP está correto e o host está online.")
        return
        
    for host in scanner.all_hosts():
        if scanner[host].state() == 'down':
            print(f"\n[!] Host: {host} parece estar offline.")
            continue

        print(f"\n{'='*20} Resultados para o Host: {host} ({scanner[host].hostname()}) {'='*20}")
        print(f"Estado: {scanner[host].state()}")

        open_ports_found = False
        # Itera sobre todos os protocolos escaneados (tcp, udp)
        for proto in scanner[host].all_protocols():
            print(f"\nProtocolo: {proto.upper()}")

            ports = scanner[host][proto].keys()
            for port in sorted(ports):
                port_info = scanner[host][proto][port]
                if port_info['state'] == 'open':
                    open_ports_found = True
                    product = port_info.get('product', 'N/A')
                    version = port_info.get('version', 'N/A')
                    name = port_info.get('name', 'N/A')
                    
                    print(f"\n  [+] Porta Aberta: {port}/{proto}")
                    print(f"  -> Serviço: {name}")
                    print(f"  -> Produto: {product}")
                    print(f"  -> Versão: {version}")

                    # Verifica se há resultados dos scripts de vulnerabilidade
                    if 'script' in port_info and port_info['script']:
                        print("  -> Vulnerabilidades Encontradas:")
                        for script_name, output in port_info['script'].items():
                            print(f"    - Script '{script_name}':")
                            # Formata a saída do script para melhor legibilidade
                            for line in output.split('\n'):
                                if line.strip(): # Ignora linhas vazias
                                    print(f"      {line.strip()}")
                    else:
                        print("  -> Nenhuma vulnerabilidade detectada pelos scripts do Nmap.")

        if not open_ports_found:
            print("\nNenhuma porta aberta foi encontrada neste host.")
    
    print(f"\n{'='*25} Escaneamento Concluído {'='*25}")


if __name__ == "__main__":
    target = input("Digite o endereço IP do alvo: ")
    
    # Validação simples do IP (pode ser melhorada com regex ou bibliotecas)
    if not target:
        print("[!] Erro: Nenhum endereço IP foi fornecido.")
    else:
        scan_vulnerabilities(target)