import nmap
import subprocess
import time
import sys

# --- CONFIGURAÇÕES ---
# O endereço IP do alvo que você tem permissão para escanear.
# NUNCA use em um alvo sem permissão. Use o IP do seu Metasploitable.
TARGET_IP = '192.168.1.10' # MUDE PARA O IP DO SEU ALVO

def run_nmap_scan(target):
    """
    Executa um scan detalhado do Nmap e retorna o resultado.
    """
    print(f"[*] Iniciando scan Nmap em {target}... Por favor, aguarde.")
    nm = nmap.PortScanner()
    # -sV: Detecta a versão dos serviços
    # -sC: Usa scripts padrão para obter mais informações
    # -T4: Acelera o scan (use com cuidado)
    try:
        nm.scan(target, arguments='-sV -sC -T4')
        return nm
    except nmap.PortScannerError:
        print(f"[!] Erro: Nmap não encontrado. Verifique se está instalado e no PATH do sistema.")
        sys.exit(1)
    except Exception as e:
        print(f"[!] Um erro inesperado ocorreu com o Nmap: {e}")
        sys.exit(1)


def search_metasploit(query):
    """
    Usa o msfconsole para pesquisar por módulos relacionados a uma query.
    """
    print(f"    -> Pesquisando no Metasploit por: '{query}'")
    if not query:
        return "Nenhuma query válida fornecida."

    # Comando que será executado no shell
    # Inicia o msfconsole, espera, busca e sai.
    command = f"msfconsole -q -x 'search {query}; exit'"
    
    try:
        # Usamos o subprocess para rodar o comando e capturar a saída
        result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=120)
        if result.returncode != 0:
            return f"    [!] Erro ao executar msfconsole. Verifique se o Metasploit está instalado corretamente.\n{result.stderr}"
            
        return result.stdout
    except subprocess.TimeoutExpired:
        return "    [!] A pesquisa no Metasploit demorou demais (timeout)."
    except Exception as e:
        return f"    [!] Um erro inesperado ocorreu ao chamar o msfconsole: {e}"

def main():
    """
    Função principal que orquestra o scan e a pesquisa.
    """
    scan_results = run_nmap_scan(TARGET_IP)

    if not scan_results.all_hosts():
        print(f"[!] Nenhum host encontrado em {TARGET_IP}. O host está ativo?")
        return

    for host in scan_results.all_hosts():
        print("-" * 50)
        print(f"Host: {host} ({scan_results[host].hostname()})")
        print(f"Estado: {scan_results[host].state()}")
        print("-" * 50)

        for proto in scan_results[host].all_protocols():
            print(f"\nProtocolo: {proto.upper()}")
            ports = scan_results[host][proto].keys()
            sorted_ports = sorted(ports)

            for port in sorted_ports:
                service_info = scan_results[host][proto][port]
                product = service_info.get('product', '')
                version = service_info.get('version', '')
                name = service_info.get('name', '')
                
                print(f"\n[+] Porta {port}:")
                print(f"  - Estado: {service_info['state']}")
                print(f"  - Serviço: {name}")
                print(f"  - Produto: {product}")
                print(f"  - Versão: {version}")

                # Criamos uma query de pesquisa para o Metasploit
                # A pesquisa é mais eficaz com o nome do produto
                search_query = product if product else name
                if search_query:
                    metasploit_results = search_metasploit(search_query.strip())
                    print("\n    --- Resultados do Metasploit ---")
                    print(metasploit_results)
                    print("    ----------------------------------")
                    # Pequena pausa para não sobrecarregar
                    time.sleep(2)

if __name__ == "__main__":
    if TARGET_IP == '192.168.1.10': # Lembrete para o usuário
        print("[!] ATENÇÃO: O IP do alvo está configurado como '192.168.1.10'.")
        print("[!] Por favor, altere a variável 'TARGET_IP' no script para o IP do seu alvo autorizado.")
    else:
        main()