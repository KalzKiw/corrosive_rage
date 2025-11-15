import requests
import concurrent.futures
import json

# Lista de sitios para buscar. Se puede expandir fácilmente.
# 'url_check' es la URL que verificaremos. El '{}' será reemplazado por el nombre de usuario.
# 'url_profile' es el enlace directo al perfil encontrado.
SITES = [
    {'name': 'Twitter', 'url_check': 'https://twitter.com/{}', 'url_profile': 'https://twitter.com/{}'},
    {'name': 'Instagram', 'url_check': 'https://www.instagram.com/{}/', 'url_profile': 'https://www.instagram.com/{}/'},
    {'name': 'GitHub', 'url_check': 'https://github.com/{}', 'url_profile': 'https://github.com/{}'},
    {'name': 'TikTok', 'url_check': 'https://www.tiktok.com/@{}', 'url_profile': 'https://www.tiktok.com/@{}'},
    {'name': 'YouTube', 'url_check': 'https://www.youtube.com/{}', 'url_profile': 'https://www.youtube.com/{}'},
    {'name': 'Reddit', 'url_check': 'https://www.reddit.com/user/{}', 'url_profile': 'https://www.reddit.com/user/{}'},
    {'name': 'LinkedIn', 'url_check': 'https://www.linkedin.com/in/{}', 'url_profile': 'https://www.linkedin.com/in/{}'},
    {'name': 'Facebook', 'url_check': 'https://www.facebook.com/{}', 'url_profile': 'https://www.facebook.com/{}'},
]

def check_username(username, site):
    """
    Verifica si un nombre de usuario existe en un sitio específico.
    """
    url = site['url_check'].format(username)
    try:
        # Usamos HEAD para que sea más rápido, solo nos interesa el código de estado.
        response = requests.head(url, timeout=5, allow_redirects=True)
        
        # Consideramos que el perfil existe si la página devuelve un 200 (OK).
        # NOTA: Algunos sitios pueden devolver 200 incluso para usuarios no existentes.
        # Esta es una simplificación, pero un buen punto de partida.
        if response.status_code == 200:
            return {'site': site['name'], 'url': site['url_profile'].format(username)}
    except requests.RequestException:
        # Ignoramos errores de conexión, timeout, etc.
        pass
    return None

def run(target, config):
    """
    Función principal del módulo de investigación de nombres de usuario.
    """
    print(f"[*] Iniciando busqueda de nombre de usuario para: {target}")
    results = {'target': target, 'module': 'username_recon', 'findings': []}

    found_profiles = []
    # Usamos ThreadPoolExecutor para hacer las peticiones en paralelo, ¡mucho más rápido!
    with concurrent.futures.ThreadPoolExecutor() as executor:
        futures = [executor.submit(check_username, target, site) for site in SITES]
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                found_profiles.append(result)
    
    if found_profiles:
        results['findings'].append({
            'type': 'user_profiles',
            'data': found_profiles
        })
        print(f"[+] Se encontraron {len(found_profiles)} perfiles para el usuario '{target}'.")
    else:
        print(f"[-] No se encontraron perfiles publicos para el usuario '{target}'.")

    return results