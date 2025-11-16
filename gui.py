import logging
import json
from datetime import datetime
import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox, font
import subprocess
import os
import glob
import webbrowser
import threading
import sys
import ast
try:
    from ttkbootstrap import Style as TtkStyle
    TTKBOOTSTRAP_AVAILABLE = True
except Exception:
    TTKBOOTSTRAP_AVAILABLE = False

class OsintGui:
    def __init__(self, root):
        self.root = root
        self.root.title("Corrosive's Rage - OSINT Toolkit")
        # abrir en un tamaño mayor para que todos los componentes sean visibles
        self.root.geometry("1000x700")
        self.root.minsize(900, 600)
        # Variables
        self.target_var = tk.StringVar()
        self.module_var = tk.StringVar()
        self.process = None
        self._stop_requested = False
        
        # configurar logging básico
        logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')
        self.logger = logging.getLogger('corrosive_rage.gui')

        # Estilo ttk y fuente
        # Prefer ttkbootstrap style if available
        if TTKBOOTSTRAP_AVAILABLE:
            try:
                # apply a dark 'hacker' leaning theme
                self.style = TtkStyle(theme='cyborg')
            except Exception:
                self.style = ttk.Style(self.root)
        else:
            style = ttk.Style(self.root)
            try:
                style.theme_use('clam')
            except Exception:
                pass
        self.base_font = font.nametofont('TkDefaultFont').copy()
        self.mono_font = ('Consolas', 10) if sys.platform == 'win32' else ('DejaVu Sans Mono', 11)
        self.base_font.configure(size=10)
        self.dark_mode = True
        self.apply_theme()

        self.create_widgets()

    def create_widgets(self):
        # Menú
        menubar = tk.Menu(self.root)
        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="Salir", command=self.root.quit)
        menubar.add_cascade(label="Archivo", menu=file_menu)

        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label="Acerca de", command=self.show_about)
        menubar.add_cascade(label="Ayuda", menu=help_menu)

        self.root.config(menu=menubar)

        # Header ASCII art (top) - mostrar el ASCII original en un widget con scrollbar horizontal
        header_txt = r'''_________                                  .__           /\         __________                        
\_   ___ \  __________________  ____  _____|__|__  __ ___)/  ______ \______   \_____     ____   ____  
/    \  \/ /  _ \_  __ \_  __ \/  _ \/  ___/  \  \/ // __ \ /  ___/  |       _/\__  \   / ___\_/ __ \ 
\     \___(  <_> )  | \/|  | \(  <_> )___ \|  |\   /\  ___/ \___ \   |    |   \ / __ \_/ /_/  >  ___/ 
 \______  /\____/|__|   |__|   \____/____  >__| \_/  \___  >____  >  |____|_  /(____  /\___  / \___  >
        \/                               \/              \/     \/          \/      \//_____/      \/'''
        # Mostrar el ASCII integrado (etiqueta monoespaciada) para que forme parte del layout
        header_label = tk.Label(self.root, text=header_txt, font=self.mono_font,
                                justify=tk.LEFT, anchor=tk.W, fg='#00FF41', bg='#0b0b0b')
        header_label.grid(row=0, column=0, sticky=(tk.W), padx=8, pady=(8,0))

        # Form row: target entry + spinner + badge + run/controls (single-column layout)
        form_frame = ttk.Frame(self.root, padding=8)
        form_frame.grid(row=1, column=0, sticky=(tk.W, tk.E), padx=8)

        ttk.Label(form_frame, text="Objetivo:").grid(row=0, column=0, sticky=tk.W)
        target_entry = ttk.Entry(form_frame, textvariable=self.target_var, width=50)
        target_entry.grid(row=0, column=1, sticky=(tk.W, tk.E), padx=(6,8))

        # spinner for module alias selection
        self.modules_info = self.scan_modules_metadata()
        translations = {
            'domain_recon': 'Rastrear Dominios',
            'email_recon': 'Analizar Emails',
            'ip_recon': 'Investigación IP',
            'username_recon': 'Buscar Usuarios'
        }
        alias_list = [translations.get(m['name'], m.get('alias', m['name'])) for m in self.modules_info]
        self.alias_to_name = { (translations.get(m['name'], m.get('alias', m['name']))): m['name'] for m in self.modules_info }
        # map name -> alias to programmatically set combobox when autoselecting
        self.name_to_alias = { m['name']: translations.get(m['name'], m.get('alias', m['name'])) for m in self.modules_info }
        # flags to control user override vs programmatic changes
        self.user_overrode_module = False
        self._suppress_module_change = False
        self.module_spinner = ttk.Combobox(form_frame, values=alias_list, state='readonly', width=24)
        self.module_spinner.grid(row=0, column=2, sticky=(tk.W), padx=(0,8))
        if alias_list:
            self.module_spinner.current(0)
            self.selected_modules = [self.alias_to_name[alias_list[0]]]

        # badge
        self.badge_label = tk.Label(form_frame, text='MOD', anchor=tk.CENTER, width=6, relief=tk.RIDGE, bg='#333', fg='#fff')
        self.badge_label.grid(row=0, column=3, padx=(0,8))

        # action buttons
        self.run_button = ttk.Button(form_frame, text="¡Investigar!", command=self.start_investigation)
        self.run_button.grid(row=0, column=4, padx=4)
        self.clear_button = ttk.Button(form_frame, text="Limpiar", command=self.clear_output)
        self.clear_button.grid(row=0, column=6, padx=4)

        # no mostramos una etiqueta duplicada del módulo seleccionado (la combobox ya indica la selección)

        # bind spinner
        def on_spinner_change(evt):
            # si estamos programáticamente actualizando el spinner, no marcar override
            if getattr(self, '_suppress_module_change', False):
                self._suppress_module_change = False
                return
            alias = self.module_spinner.get()
            name = self.alias_to_name.get(alias, alias)
            self.selected_modules = [name]
            # combobox muestra la selección; no mostramos etiqueta duplicada
            # usuario cambió manualmente
            self.user_overrode_module = True
            if 'domain' in name:
                self.badge_label.config(text='DOM', bg='#1f8ef1')
            elif 'email' in name:
                self.badge_label.config(text='MAIL', bg='#f39c12')
            elif 'ip' in name:
                self.badge_label.config(text='IP', bg='#2ecc71')
            elif 'username' in name or 'user' in name:
                self.badge_label.config(text='USR', bg='#9b59b6')
            else:
                self.badge_label.config(text='MOD', bg='#bdc3c7')

        self.module_spinner.bind('<<ComboboxSelected>>', on_spinner_change)

        # cambiar módulo automáticamente según lo que escriba el usuario, salvo override manual
        def on_target_change(event=None):
            try:
                if getattr(self, 'user_overrode_module', False):
                    return
                t = self.target_var.get().strip()
                if not t:
                    return
                import re
                module_name = None
                # split on commas/semicolons/newlines to detect multiple tokens
                tokens = [s.strip() for s in re.split(r'[,;\n]+', t) if s.strip()]
                has_email = False
                has_ip = False
                has_domain = False
                has_user = False
                provider_keywords = ('gmail', 'hotmail', 'yahoo', 'outlook', 'proton', 'icloud', 'yandex', 'mail')
                for tok in tokens:
                    lower = tok.lower()
                    if tok.startswith('@'):
                        # @gmail, @hotmail short form implies email search
                        has_email = True
                        continue
                    if '@' in tok:
                        # something@domain.tld
                        has_email = True
                        continue
                    # plain provider like 'gmail' or '@gmail.com' or 'gmail.com'
                    if any(pk in lower for pk in provider_keywords):
                        has_email = True
                        continue
                    # IPv4 simple
                    if re.match(r'^\d{1,3}(?:\.\d{1,3}){3}$', tok):
                        has_ip = True
                        continue
                    # URL with scheme
                    if lower.startswith('http://') or lower.startswith('https://'):
                        host = re.sub(r'^https?://', '', lower)
                        host = host.split('/')[0]
                        if '.' in host:
                            has_domain = True
                            continue
                    # domain-like token
                    if '.' in tok and ' ' not in tok:
                        has_domain = True
                        continue
                    # simple username-like token
                    if re.match(r'^[A-Za-z0-9_\-]{2,30}$', tok):
                        has_user = True

                # priority: email > ip > domain > username
                if has_email:
                    module_name = 'email_recon'
                elif has_ip and not has_email:
                    module_name = 'ip_recon'
                elif has_domain and not has_email:
                    module_name = 'domain_recon'
                elif has_user and not any((has_email, has_ip, has_domain)):
                    module_name = 'username_recon'

                if module_name and module_name in self.name_to_alias:
                    alias = self.name_to_alias[module_name]
                    # programmatic set without tripping user override
                    self._suppress_module_change = True
                    try:
                        self.module_spinner.set(alias)
                    except Exception:
                        try:
                            idx = alias_list.index(alias)
                            self.module_spinner.current(idx)
                        except Exception:
                            pass
                    self.selected_modules = [module_name]
                    # combobox shows selection; keep UI minimal
                    # actualizar badge
                    if 'domain' in module_name:
                        self.badge_label.config(text='DOM', bg='#1f8ef1')
                    elif 'email' in module_name:
                        self.badge_label.config(text='MAIL', bg='#f39c12')
                    elif 'ip' in module_name:
                        self.badge_label.config(text='IP', bg='#2ecc71')
                    elif 'username' in module_name or 'user' in module_name:
                        self.badge_label.config(text='USR', bg='#9b59b6')
            except Exception:
                pass

        target_entry.bind('<KeyRelease>', on_target_change)

        # Screen: output area below form
        screen_frame = ttk.Frame(self.root, padding=8)
        screen_frame.grid(row=2, column=0, sticky=(tk.N, tk.S, tk.E, tk.W), padx=8, pady=(4,8))

        ttk.Label(screen_frame, text="Pantalla: Resultados").grid(row=0, column=0, sticky=tk.W)
        self.output_text = scrolledtext.ScrolledText(screen_frame, wrap=tk.WORD, width=120, height=28, state='disabled')
        self.output_text.grid(row=1, column=0, sticky=(tk.N, tk.S, tk.E, tk.W))
        try:
            self.output_text.config(font=self.mono_font, background='#020202', foreground='#00FF41', insertbackground='#00FF41')
        except Exception:
            pass

        # small preview below
        self.results_preview = scrolledtext.ScrolledText(screen_frame, wrap=tk.WORD, width=120, height=8, state='disabled', background='#0b0b0b')
        self.results_preview.grid(row=2, column=0, sticky=(tk.W, tk.E), pady=(6,0))
        try:
            self.results_preview.config(font=self.mono_font, background='#020202', foreground='#9bff9b')
        except Exception:
            pass

        # progressbar under screen
        self.progress = ttk.Progressbar(self.root, mode='indeterminate', length=400)
        self.progress.grid(row=3, column=0, sticky=(tk.W), padx=8, pady=(2,6))

        # Configurar el grid para que la 'pantalla' (row=2) sea expandible
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(2, weight=1)

        # Status bar
        self.status_var = tk.StringVar(value='Listo')
        status_bar = ttk.Label(self.root, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        status_bar.grid(row=4, column=0, sticky=(tk.W, tk.E))

        # Bindings (atajos)
        self.root.bind('<Control-r>', lambda e: self.start_investigation())
        self.root.bind('<Control-R>', lambda e: self.start_investigation())
        self.root.bind('<Control-c>', lambda e: self.request_cancel())
        self.root.bind('<Control-l>', lambda e: self.clear_output())

        # Nota: el botón de generar JSON de prueba ha sido eliminado (logic moved)

    def scan_modules_metadata(self):
        """Escanea la carpeta `modules/` y devuelve una lista de dicts con keys: name, alias, desc.
        Usa parsing estático (AST) para no importar módulos.
        """
        modules = []
        base_dir = os.path.dirname(__file__)
        mods_dir = os.path.join(base_dir, 'modules')
        try:
            for path in glob.glob(os.path.join(mods_dir, '*.py')):
                name = os.path.splitext(os.path.basename(path))[0]
                # ignorar archivos privados o de paquete
                if name == '__init__' or name.startswith('_'):
                    continue
                alias = name
                desc = ''
                try:
                    with open(path, 'r', encoding='utf-8') as f:
                        src = f.read()
                    tree = ast.parse(src)
                    # buscar asignación a META
                    for node in tree.body:
                        if isinstance(node, ast.Assign):
                            for target in node.targets:
                                if getattr(target, 'id', None) == 'META':
                                    try:
                                        value = ast.literal_eval(node.value)
                                        alias = value.get('alias', alias)
                                        desc = value.get('description', desc)
                                    except Exception:
                                        pass
                        # extraer docstring si existe
                    module_doc = ast.get_docstring(tree)
                    if module_doc and not desc:
                        desc = module_doc.strip().split('\n')[0]
                except Exception:
                    pass
                modules.append({'name': name, 'alias': alias, 'desc': desc})
        except Exception:
            modules = [{'name': 'domain_recon', 'alias': 'Domain Recon', 'desc': ''},
                       {'name': 'email_recon', 'alias': 'Email Recon', 'desc': ''}]
        return modules

    def open_module_selector(self):
        """Muestra un diálogo con checkbuttons para seleccionar módulos por alias."""
        dlg = tk.Toplevel(self.root)
        dlg.title('Seleccionar módulos')
        dlg.geometry('400x400')
        dlg.transient(self.root)
        vars = {}

        frame = ttk.Frame(dlg, padding=8)
        frame.pack(fill=tk.BOTH, expand=True)

        lbl = ttk.Label(frame, text='Marca los módulos a ejecutar:')
        lbl.pack(anchor=tk.W)

        canvas = tk.Canvas(frame)
        scrollbar = ttk.Scrollbar(frame, orient='vertical', command=canvas.yview)
        scroll_frame = ttk.Frame(canvas)
        scroll_frame.bind('<Configure>', lambda e: canvas.configure(scrollregion=canvas.bbox('all')))
        canvas.create_window((0,0), window=scroll_frame, anchor='nw')
        canvas.configure(yscrollcommand=scrollbar.set)
        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        desc_box = scrolledtext.ScrolledText(dlg, height=6, state='disabled')
        desc_box.pack(fill=tk.X, padx=8, pady=8)

        def on_check(name):
            # mostrar la descripción del módulo seleccionado (primero que aparezca)
            for m in self.modules_info:
                if m['name'] == name:
                    desc = m.get('desc', '')
                    desc_box.config(state='normal')
                    desc_box.delete(1.0, tk.END)
                    desc_box.insert(tk.END, f"{m.get('alias','')}:\n{desc}")
                    desc_box.config(state='disabled')
                    break

        for m in self.modules_info:
            var = tk.BooleanVar(value=(m['name'] in self.selected_modules))
            cb = ttk.Checkbutton(scroll_frame, text=f"{m.get('alias','')}  ({m.get('name')})", variable=var,
                                 command=lambda n=m['name']: on_check(n))
            cb.pack(anchor=tk.W, pady=2, padx=4)
            vars[m['name']] = var

        btn_frame = ttk.Frame(dlg)
        btn_frame.pack(fill=tk.X, padx=8, pady=6)

        def apply_selection():
            sel = [name for name, v in vars.items() if v.get()]
            self.selected_modules = sel
            dlg.destroy()

        ttk.Button(btn_frame, text='Aceptar', command=apply_selection).pack(side=tk.RIGHT, padx=4)
        ttk.Button(btn_frame, text='Cancelar', command=dlg.destroy).pack(side=tk.RIGHT)

        # Bindings (atajos)
        self.root.bind('<Control-r>', lambda e: self.start_investigation())
        self.root.bind('<Control-R>', lambda e: self.start_investigation())
        self.root.bind('<Control-c>', lambda e: self.request_cancel())
        self.root.bind('<Control-l>', lambda e: self.clear_output())

    def start_investigation(self):
        target = self.target_var.get()
        # obtener módulos seleccionados
        module = ','.join(self.selected_modules) if self.selected_modules else ''

        if not target:
            messagebox.showerror("Error", "Por favor, introduce un objetivo.")
            return

        self.run_button.config(state='disabled')
        self.output_text.config(state='normal')
        self.output_text.delete(1.0, tk.END)
        self.output_text.insert(tk.END, f"Iniciando investigacion para '{target}' con el modulo '{module}'...\n\n")
        self.output_text.config(state='disabled')
        self.root.update_idletasks()

        self.thread = threading.Thread(target=self.run_command, args=(target, module))
        self.thread.start()
        # iniciar progress
        self.progress.start(10)
        self.status_var.set('Ejecutando...')

    def run_command(self, target, module):
        # --- MANTENEMOS LAS CORRECCIONES CLAVE ---
        self.logger.info(f"Usando el intérprete de Python en: {sys.executable}")

        # Determinar la ruta al CLI principal (corrosive_rage.py)
        base_dir = os.path.dirname(__file__)
        cli_path = os.path.join(base_dir, 'corrosive_rage.py')
        if not os.path.exists(cli_path):
            # Fallback: buscar en el cwd
            cli_path = os.path.join(os.getcwd(), 'corrosive_rage.py')

        if not os.path.exists(cli_path):
            self.update_output(f"\n[!] ERROR: No se encontró el archivo CLI 'corrosive_rage.py'. Ruta intentada: {cli_path}\n")
            messagebox.showerror("Error", "No se encontró el archivo 'corrosive_rage.py' junto a la GUI. Asegúrate de ejecutar desde el directorio del proyecto.")
            self.run_button.config(state='normal')
            return

        # Construir comando usando el intérprete actual
        interpreter = sys.executable or 'py'
        command = [interpreter, cli_path, '-t', target, '-m', module]

        env = os.environ.copy()
        # Ejecutar el CLI desde el directorio del paquete para rutas relativas coherentes
        env['PYTHONPATH'] = base_dir

        try:
            self.process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                cwd=base_dir,
                env=env
            )

            for line in iter(self.process.stdout.readline, ''):
                if self._stop_requested:
                    # intento de terminación del proceso
                    try:
                        self.process.terminate()
                        self.update_output("\n[!] Cancelado por el usuario.\n")
                    except Exception:
                        pass
                    break
                if line:
                    self.update_output(line)

            try:
                self.process.stdout.close()
            except Exception:
                pass

            return_code = self.process.wait()

            self.update_output(f"\nInvestigacion finalizada con codigo de salida: {return_code}\n")
            self.status_var.set('Listo')
            # intentar cargar el último resultado y mostrar en preview
            try:
                base_dir = os.path.dirname(__file__)
                results_dir = os.path.join(base_dir, 'results')
                list_of_files = glob.glob(os.path.join(results_dir, '*.json'))
                if list_of_files:
                    latest_file = max(list_of_files, key=os.path.getctime)
                    with open(latest_file, 'r', encoding='utf-8') as f:
                        j = json.load(f)
                    self.results_preview.config(state='normal')
                    self.results_preview.delete(1.0, tk.END)
                    self.results_preview.insert(tk.END, json.dumps(j, indent=2, ensure_ascii=False))
                    self.results_preview.config(state='disabled')
                    # además mostrar un resumen legible en la pantalla principal
                    try:
                        pretty = self.pretty_print_results(j)
                        self.update_output('\n--- RESULTADO (resumen) ---\n')
                        self.update_output(pretty + '\n')
                    except Exception:
                        pass
            except Exception:
                pass

        except Exception as e:
            self.update_output(f"\n[!] ERROR: No se pudo ejecutar el comando. ¿Esta en el directorio correcto?\n{e}\n")
        finally:
            self.run_button.config(state='normal')
            self.progress.stop()
            self._stop_requested = False

    def update_output(self, text):
        self.output_text.config(state='normal')
        self.output_text.insert(tk.END, text)
        self.output_text.see(tk.END)
        self.output_text.config(state='disabled')
        self.root.update_idletasks()

    def select_targets_file(self):
        """Abrir diálogo para seleccionar un archivo de targets y colocarlo en la entrada."""
        try:
            filepath = filedialog.askopenfilename(title="Seleccionar archivo de targets", filetypes=[("Text files", "*.txt"), ("All files", "*")])
            if filepath:
                self.target_var.set(filepath)
        except Exception as e:
            messagebox.showerror("Error", f"No se pudo seleccionar el archivo: {e}")

    def pretty_print_results(self, j: dict) -> str:
        """Crear un resumen legible del JSON de resultados para mostrar en la pantalla.
        Es defensivo: no asume una estructura fija.
        """
        lines = []
        try:
            target = j.get('target') if isinstance(j, dict) else None
            module = j.get('module') if isinstance(j, dict) else None
            lines.append(f"Target: {target}")
            lines.append(f"Módulo(s): {module}")
            findings = j.get('findings') if isinstance(j, dict) else None
            if findings and isinstance(findings, list):
                lines.append('\nFindings:')
                for f in findings:
                    try:
                        ftype = f.get('type', 'item')
                        data = f.get('data', f)
                        lines.append(f" - {ftype}:")
                        # si data es lista, mostrar primeros 8
                        if isinstance(data, list):
                            for v in data[:8]:
                                lines.append(f"    • {v}")
                            if len(data) > 8:
                                lines.append(f"    ... +{len(data)-8} más")
                        elif isinstance(data, dict):
                            for k, v in list(data.items())[:8]:
                                lines.append(f"    • {k}: {v}")
                        else:
                            lines.append(f"    {data}")
                    except Exception:
                        lines.append(f"    {repr(f)}")
            else:
                # si no hay findings, intentar mostrar keys del JSON
                if isinstance(j, dict):
                    lines.append('\nDatos:')
                    for k, v in list(j.items())[:12]:
                        lines.append(f" - {k}: {type(v).__name__}")
        except Exception:
            return json.dumps(j, indent=2, ensure_ascii=False)
        return '\n'.join(lines)

    # generate_sample_json removed; sample generation deprecated in favor of real CLI output
    def request_cancel(self):
        """Solicitar cancelación de la ejecución en curso."""
        if self.process and self.process.poll() is None:
            self._stop_requested = True
            self.status_var.set('Cancelando...')

    def show_about(self):
        messagebox.showinfo("Acerca de", "Corrosive's Rage - OSINT Toolkit\nInterfaz mejorada.")

    def apply_theme(self):
        """Aplicar un tema oscuro estilo 'hacker' a widgets principales."""
        if self.dark_mode:
            bg = '#0b0b0b'
            fg = '#00FF41'
            entry_bg = '#101010'
            btn_bg = '#1a1a1a'
        else:
            bg = None
            fg = None
            entry_bg = None
            btn_bg = None

        try:
            self.root.configure(bg=bg if bg else None)
        except Exception:
            pass

        # Aplicar estilo simple a scrolledtext cuando aún no existe
        self.default_text_bg = entry_bg
        self.default_text_fg = fg

    def clear_output(self):
        try:
            self.output_text.config(state='normal')
            self.output_text.delete(1.0, tk.END)
            self.output_text.config(state='disabled')
            self.results_preview.config(state='normal')
            self.results_preview.delete(1.0, tk.END)
            self.results_preview.config(state='disabled')
            self.status_var.set('Listo')
        except Exception:
            pass

    def open_selected_report(self):
        """Permite seleccionar un informe JSON y abrirlo en el explorador o mostrar su contenido."""
        try:
            base_dir = os.path.dirname(__file__)
            results_dir = os.path.join(base_dir, 'results')
            if not os.path.isdir(results_dir):
                messagebox.showinfo('Informacion', "No se encontró la carpeta 'results'.")
                return
            filepath = filedialog.askopenfilename(title="Seleccionar informe JSON", initialdir=results_dir, filetypes=[('JSON','*.json')])
            if not filepath:
                return
            # abrir con el navegador para visualización cómoda
            webbrowser.open(f'file://{os.path.realpath(filepath)}')
        except Exception as e:
            messagebox.showerror('Error', f'No se pudo abrir el informe: {e}')

    def view_last_report(self):
        # Buscar resultados en la carpeta 'results' al lado del paquete
        base_dir = os.path.dirname(__file__)
        results_dir = os.path.join(base_dir, 'results')
        list_of_files = glob.glob(os.path.join(results_dir, '*.json'))
        if not list_of_files:
            messagebox.showinfo("Informacion", "No se encontraron informes en la carpeta 'results'.")
            return
        latest_file = max(list_of_files, key=os.path.getctime)
        
        try:
            webbrowser.open(f'file://{os.path.realpath(latest_file)}')
        except Exception as e:
            messagebox.showerror("Error", f"No se pudo abrir el informe: {e}")

if __name__ == "__main__":
    root = tk.Tk()
    app = OsintGui(root)
    root.mainloop()
