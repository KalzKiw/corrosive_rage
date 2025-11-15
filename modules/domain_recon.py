import shodan
import whois
import configparser
import json
import re
import requests

def run(target, config):
    """
    Función principal del módulo de reconocimiento de dominios.
    """
    print(f"[*] Iniciando reconocimiento de dominio para: {target}")
    results = {'target': target, 'module': 'domain_recon', 'findings': []}

    # 1. Consulta WHOIS
    try:
        domain_info = whois.whois(target)
        registrar = domain_info.registrar
        creation_date = domain_info.creation_date
        expiration_date = domain_info.expiration_date
        
        # Buscamos emails en los datos del WHOIS
        emails_found = set()
        whois_text = str(domain_info)
        email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
        emails_found.update(re.findall(email_pattern, whois_text))

        results['findings'].append({
            'type': 'whois',
            'data': {
                'registrar': registrar[0] if isinstance(registrar, list) else registrar,
                'creation_date': str(creation_date[0]) if isinstance(creation_date, list) else str(creation_date),
                'expiration_date': str(expiration_date[0]) if isinstance(expiration_date, list) else str(expiration_date),
                'emails': list(emails_found) # <-- ¡Añadimos los emails para la cadena!
            }
        })
        print("[+] Informacion WHOIS encontrada.")
    except Exception as e:
        print(f"[!] Error en la consulta WHOIS: {e}")

    # 2. Enumeración de Subdominios (versión definitiva)
    try:
        print(f"[*] Buscando subdominios para {target}...")
        url = f"https://crt.sh/?q=%25.{target}&output=json"
        response = requests.get(url, timeout=10)
        
        subdomains = []
        if response.status_code == 200:
            certs = response.json()
            for cert in certs:
                name_value = cert.get('name_value', '')
                for name in name_value.split('\n'):
                    if name and name not in subdomains:
                        subdomains.append(name)
        
        unique_subdomains = sorted(list(set(sub for sub in subdomains if sub and sub != target and not sub.startswith('*.'))))

        if unique_subdomains:
            results['findings'].append({
                'type': 'subdomain_enumeration',
                'data': {'subdomains': unique_subdomains, 'count': len(unique_subdomains)}
            })
            print(f"[+] Se encontraron {len(unique_subdomains)} subdominios unicos.")
        else:
            print(f"[-] No se encontraron subdominios para {target}.")
            
    except Exception as e:
        print(f"[!] Error en la enumeracion de subdominios: {e}")

    # 3. Búsqueda en Shodan (si hay API key)
    try:
        shodan_api_key = config.get('APIs', 'shodan_api_key')
        if shodan_api_key and shodan_api_key != 'TU_CLAVE_DE_API_DE_SHODAN_AQUI':
            api = shodan.Shodan(shodan_api_key)
            host = api.host(target, history=False)
            results['findings'].append({
                'type': 'shodan_host_info',
                'data': {
                    'country': host.get('country_name'),
                    'city': host.get('city'),
                    'org': host.get('org'),
                    'ports': host.get('ports'),
                    'vulns': list(host.get('vulns', []))[:5],
                    'ip_str': host.get('ip_str') # <-- ¡Añadimos la IP para la cadena!
                }
            })
            print("[+] Informacion de Shodan encontrada.")
        else:
            print("[!] Clave de API de Shodan no configurada. Omitiendo busqueda en Shodan.")
    except (configparser.NoSectionError, shodan.APIError) as e:
        print(f"[!] Error al consultar Shodan: {e}")
    except Exception as e:
        print(f"[!] Error al conectar con Shodan: {e}")

    return results