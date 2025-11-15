import argparse
import json
import importlib
import configparser
import os
import re
from datetime import datetime
import concurrent.futures

def load_config():
    """Carga el archivo de configuración."""
    config = configparser.ConfigParser()
    config.read('config.ini')
    return config

def save_results(results, target, chain_suffix=""):
    """Guarda los resultados en un archivo JSON."""
    if not os.path.exists('results'):
        os.makedirs('results')
    
    safe_target = target.replace('.', '_').replace('@', '_').replace('/', '_')
    timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
    filename = f"results/{safe_target}_{timestamp}{chain_suffix}.json"
    
    with open(filename, 'w') as f:
        json.dump(results, f, indent=4)
    
    print(f"[+] Resultados guardados en: {filename}")

def run_module(module_name, target, config):
    """Carga y ejecuta dinámicamente un módulo."""
    try:
        module = importlib.import_module(f"modules.{module_name}")
        if hasattr(module, 'run'):
            results = module.run(target, config)
            return results
        else:
            print(f"[!] Error: El módulo '{module_name}' no tiene una función 'run'.")
            return None
    except ImportError:
        print(f"[!] Error: El módulo '{module_name}' no se encontró.")
        return None

# --- NUEVA FUNCIÓN PARA EJECUTAR CADENAS ---
def run_chain(module_chain, initial_target, config):
    """
    Ejecuta una cadena de módulos, donde la salida de uno alimenta al siguiente.
    """
    if not module_chain:
        return

    current_module = module_chain[0]
    remaining_chain = module_chain[1:]
    
    print(f"\n{'='*20} INICIANDO MÓDULO: {current_module.upper()} PARA EL OBJETIVO: {initial_target} {'='*20}")
    
    results = run_module(current_module, initial_target, config)
    
    if results:
        save_results(results, initial_target, f"_chain_{current_module}")
        
        # Buscamos nuevos objetivos en los resultados para continuar la cadena
        new_targets = []
        for finding in results.get('findings', []):
            if finding['type'] == 'whois' and 'emails' in finding.get('data', {}):
                new_targets.extend(finding['data']['emails'])
            if finding['type'] == 'subdomain_enumeration':
                new_targets.extend(finding['data']['subdomains'])
            if finding['type'] == 'reverse_dns':
                new_targets.append(finding['data']['hostname'])
            if finding['type'] == 'shodan_host_info' and 'ip_str' in finding.get('data', {}):
                 new_targets.append(finding['data']['ip_str'])

        if new_targets and remaining_chain:
            print(f"\n[*] Se encontraron {len(new_targets)} nuevos objetivos para continuar la cadena: {new_targets}")
            # Para cada nuevo objetivo, ejecutamos el resto de la cadena
            for new_target in new_targets:
                run_chain(remaining_chain, new_target, config)
        elif remaining_chain:
            print("\n[-] No se encontraron nuevos objetivos para continuar la cadena.")

def main():
    """Función principal del framework."""
    parser = argparse.ArgumentParser(description="Un framework simple y modular para OSINT con soporte para cadenas.")
    parser.add_argument('-t', '--target', required=True, help="El objetivo inicial (ej: ejemplo.com, user@email.com) o un archivo de texto con una lista de objetivos.")
    parser.add_argument('-m', '--module', required=True, help="El módulo o una cadena de módulos separados por comas (ej: 'domain_recon' o 'domain_recon,ip_recon,username_recon').")
    
    args = parser.parse_args()
    
    config = load_config()
    
    # Procesamos la cadena de módulos
    module_chain = [m.strip() for m in args.module.split(',')]

    if os.path.isfile(args.target):
        print(f"[*] Detectado archivo de objetivos: {args.target}")
        try:
            with open(args.target, 'r') as f:
                targets = [line.strip() for line in f if line.strip()]
            
            print(f"[*] Se encontraron {len(targets)} objetivos. Iniciando investigación en cadena para cada uno...\n")
            
            for target in targets:
                run_chain(module_chain, target, config)

        except FileNotFoundError:
            print(f"[!] Error: El archivo '{args.target}' no se pudo encontrar.")
        except Exception as e:
            print(f"[!] Ocurrió un error al leer el archivo: {e}")
    else:
        run_chain(module_chain, args.target, config)

if __name__ == "__main__":
    main()
