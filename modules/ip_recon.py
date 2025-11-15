import requests
import socket
import shodan
import configparser

def run(target, config):
    """
    Función principal del módulo de investigación de IPs.
    """
    print(f"[*] Iniciando investigación de IP para: {target}")
    results = {'target': target, 'module': 'ip_recon', 'findings': []}

    # 1. Geolocalización con ip-api.com (no requiere API key)
    try:
        ip_info_url = f"http://ip-api.com/json/{target}"
        response = requests.get(ip_info_url, timeout=5)
        if response.status_code == 200:
            data = response.json()
            if data.get('status') == 'success':
                results['findings'].append({
                    'type': 'geolocation',
                    'data': {
                        'country': data.get('country'),
                        'region': data.get('regionName'),
                        'city': data.get('city'),
                        'isp': data.get('isp'),
                        'org': data.get('org'),
                        'query': data.get('query')
                    }
                })
                print("[+] Información de geolocalización encontrada.")
    except Exception as e:
        print(f"[!] Error en la consulta de geolocalización: {e}")

    # 2. DNS Inverso
    try:
        hostname, _, _ = socket.gethostbyaddr(target)
        results['findings'].append({
            'type': 'reverse_dns',
            'data': {'hostname': hostname}
        })
        print(f"[+] DNS inverso encontrado: {hostname}")
    except socket.herror:
        print("[-] No se encontró DNS inverso para esta IP.")
    except Exception as e:
        print(f"[!] Error en la consulta de DNS inverso: {e}")

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
                    'vulns': list(host.get('vulns', []))[:5]
                }
            })
            print("[+] Información de Shodan encontrada.")
        else:
            print("[!] Clave de API de Shodan no configurada o es invalida en config.ini. Omitiendo busqueda en Shodan.")
    except (configparser.NoSectionError, shodan.APIError) as e:
        print(f"[!] Error al consultar Shodan: {e}")
    except Exception as e:
        print(f"[!] Error al conectar con Shodan: {e}")

    return results