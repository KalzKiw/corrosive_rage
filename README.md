# 🕵️ Corrosive's Rage
Framework modular de reconocimiento digital (OSINT) con CLI y GUI. Permite realizar recon de dominios, emails, direcciones IP y usernames mediante módulos independientes.

![Python](https://img.shields.io/badge/Python-3.10+-blue)
![OSINT](https://img.shields.io/badge/Category-OSINT-red)
![License](https://img.shields.io/badge/License-MIT-lightgrey)

## ⚠️ Uso legal
Esta herramienta es únicamente para auditorías autorizadas, prácticas educativas y análisis sobre sistemas propios. El uso sin permiso en sistemas ajenos puede ser ilegal.

## 📌 Funcionamiento
El programa funciona exclusivamente con DOS parámetros:

- `-m` → módulo a usar  
- `-t` → target (objetivo o archivo de targets)

Ejemplo general:
```
python corrosive_rage.py -m <modulo> -t <objetivo>
```

## 🚀 Ejemplos CLI

### Recon de dominio
```
python corrosive_rage.py -m domain_recon -t example.com
```

### Recon de email
```
python corrosive_rage.py -m email_recon -t persona@example.com
```

### Recon de IP
```
python corrosive_rage.py -m ip_recon -t 8.8.8.8
```

### Recon de username
```
python corrosive_rage.py -m username_recon -t johndoe
```

## 🔄 Modo batch (targets.txt)
El archivo `targets.txt` puede contener múltiples objetivos:

```
example.com
otrodominio.net
johndoe
8.8.8.8
```

Ejecutar:
```
python corrosive_rage.py -m domain_recon -t targets.txt
```

El programa detectará automáticamente que `-t` es un archivo y procesará cada línea.

## 🖥 GUI
Para lanzar la interfaz gráfica:
```
python gui.py
```

La GUI permite:
- Seleccionar un módulo OSINT
- Introducir el target
- Ejecutar sin usar terminal
- Ver resultados rápidamente

## 📂 Estructura del proyecto
```
osint_toolkit/
│
├── modules/
│   ├── domain_recon.py
│   ├── email_recon.py
│   ├── ip_recon.py
│   ├── username_recon.py
│   └── __init__.py
│
├── osint_toolkit.py      # CLI principal (-m y -t)
├── gui.py                # Interfaz gráfica
├── config.ini            # Configuración y claves API
├── targets.txt           # Lista de objetivos
├── requirements.txt
├── README.md
└── results/              # Archivos generados automáticamente
```

## 📁 Resultados
Cada ejecución crea un archivo nuevo en `results/`, por ejemplo:
```
results/domain_example.com_2025-11-15.json
```

## 🧰 Módulos OSINT

### domain_recon.py
- WHOIS  
- DNS  
- APIs externas si están configuradas  

### email_recon.py
- Validación  
- Consultas a APIs  
- Registro MX  

### ip_recon.py
- GeoIP  
- ASN  
- ISP  
- APIs externas  

### username_recon.py
- Búsquedas HTTP  
- Coincidencias en plataformas  
- Presencia estimada

## 🛠 Instalación
```
git clone https://github.com/joseglezherrera/corrosive_rage
cd corrosive_rage
python -m venv venv
source venv/bin/activate     # Linux/Mac
venv\Scripts\activate        # Windows
pip install -r requirements.txt
```

Configura tus claves API en:
```
config.ini
```

## 🧬 Características
✔ Modular  
✔ CLI simple (`-m` y `-t`)  
✔ Soporta batch  
✔ GUI incluida  
✔ Resultados automáticos  
✔ Fácil de extender añadiendo módulos en /modules  

## 📝 Licencia
MIT License.

## 👨‍💻 Autor 
https://github.com/joseglezherrera
