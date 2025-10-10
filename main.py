import nmap
import sys

def scan_network(target):
    try:
        nm = nmap.PortScanner()
        print(f"\n [*] Iniciando varredura de rede em {target}...")
        print(" [*] Isso pode levar algum tempo, por favor aguarde...\n")

        #Executa a varredura`
        # Argumentos: -sS (varredura TCP SYN), -O (detecção de SO), -sV (detecção de versão)
        # --script vuln (executa scripts de vulnerabilidade)
        # --open (mostra apenas portas abertas)
        nm.scan(target, arguments='-sS -O -sV --script vuln --open')
    
    except nmap.PortScannerError:
        print(" [!] Erro: Nmap não está instalado ou não foi encontrado.")
        sys.exit(1)
    except Exception as e:
        print(f" [!] Erro: {e}")
        sys.exit(1)
    

    #verifica se algum host foi encontrado
    if not nm.all_hosts():
        print(" [!] Nenhum host encontrado. Verifique o alvo e tente novamente.")
        return
    
    # Itera sobre todos os hosts encontrados
    for host in nm.all_hosts():
        print("\n" + "="*50)
        print(f"Host: {host} ({nm[host].hostname()})")
        print(f"Estado: {nm[host].state()}")
        print("="*50)

        #itera sobre todos os protocolos (tcp, udp, etc.)
        for proto in nm[host].all_protocols():
            print(f"\nProtocolo: {proto}")

            #obtém todas as portas do protocolo
            list_ports = nm[host][proto].keys()
            sorted_ports = sorted(list_ports)


            for port in sorted_ports:
                port_info = nm[host][proto][port]
                print(f"\n  [+] Porta {port}/{proto}")
                print(f"    - Estado: {port_info['state']}")
                print(f"    - Serviço: {port_info['name']}")
                if 'product' in port_info and port_info['product']:
                    print(f"    - Produto: {port_info['product']}")
                if 'version' in port_info and port_info['version']:
                    print(f"    - Versão: {port_info['version']}")
                
                #Verifica se há scripts de vulnerabilidade
                if 'script' in port_info:
                    print("    - Vulnerabilidades:")
                    for script_name, output in port_info['script'].items():
                        print(f"      * {script_name}: {output}")
                        
                        for line in output.split('\n'):
                            if line.strip(): #ignora linhas em branco
                                print(f"        {line.strip()}")
                else:
                    print("    - Nenhuma vulnerabilidade encontrada.")
        #Verifica o sistema operacional
        if 'osmatch' in nm[host]:
            print("\nSistema Operacional:")
            for os in nm[host]['osmatch']:
                print(f"  - {os['name']} (Precisão: {os['accuracy']}%)")
                for os_class in os['osclass']:
                    print(f"    * Tipo: {os_class['type']}, Plataforma: {os_class['platform']}, Versão: {os_class.get('version', 'N/A')}")
                    print(f"      CPE: {', '.join(os_class.get('cpe', []))}")
        else:
            print("\nSistema Operacional: Não detectado")

if __name__ == "__main__":
    try:
        target_host = input("Digite o alvo (IP ou Dominio) para escanear:")
        if not target_host:
            print(" [!] Alvo inválido. Por favor, insira um IP ou domínio válido.")
        else:
            scan_network(target_host)
    except KeyboardInterrupt:
        print("\n [*] Varredura interrompida pelo usuário.")
        sys.exit(0)