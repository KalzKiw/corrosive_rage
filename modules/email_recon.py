import requests
import hashlib
import json

def run(target, config):
    """
    Función principal del módulo de investigación de emails.
    """
    print(f"[*] Iniciando investigacion de email para: {target}")
    results = {'target': target, 'module': 'email_recon', 'findings': []}

    # 1. Comprobación de Gravatar
    try:
        email_hash = hashlib.md5(target.lower().strip().encode()).hexdigest()
        gravatar_url = f"https://www.gravatar.com/avatar/{email_hash}?d=404&s=80"
        response = requests.head(gravatar_url, timeout=5)
        if response.status_code == 200:
            results['findings'].append({
                'type': 'gravatar_profile',
                'data': {'profile_url': f"https://www.gravatar.com/{email_hash}"}
            })
            print("[+] Perfil de Gravatar encontrado.")
    except Exception as e:
        print(f"[!] Error al comprobar Gravatar: {e}")

    # 2. Generación de Enlaces para Investigación Manual (NUEVA FUNCIONALIDAD)
    # Codificamos el email para que sea seguro en una URL
    encoded_email = requests.utils.quote(target)
    
    search_links = [
        {'name': 'Google', 'url': f"https://www.google.com/search?q=\"{encoded_email}\""},
        {'name': 'Bing', 'url': f"https://www.bing.com/search?q=\"{encoded_email}\""},
        {'name': 'DuckDuckGo', 'url': f"https://duckduckgo.com/?q=\"{encoded_email}\""},
        {'name': 'Facebook', 'url': f"https://www.facebook.com/search/people/?q={encoded_email}"},
        {'name': 'Twitter', 'url': f"https://twitter.com/search?q=\"{encoded_email}\"&f=user"}
    ]

    results['findings'].append({
        'type': 'search_engine_links',
        'data': search_links
    })
    print("[+] Enlaces de busqueda generados para investigación manual.")

    # 3. Generar enlace para Have I Been Pwned
    results['findings'].append({
        'type': 'have_i_been_pwned_link',
        'data': {'search_url': f"https://haveibeenpwned.com/Account/{target}"}
    })
    print("[+] Enlace para Have I Been Pwned generado.")

    return results