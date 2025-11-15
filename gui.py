import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
import subprocess
import os
import glob
import webbrowser
import threading
import sys

class OsintGui:
    def __init__(self, root):
        self.root = root
        self.root.title("Corrosive's Rage - OSINT Toolkit")
        self.root.geometry("800x600")

        self.target_var = tk.StringVar()
        self.module_var = tk.StringVar()
        self.process = None
        self.create_widgets()

    def create_widgets(self):
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        # --- Sección de Entrada ---
        ttk.Label(main_frame, text="Objetivo (dominio, email, IP, usuario o archivo .txt):").grid(row=0, column=0, sticky=tk.W, pady=5)
        target_entry = ttk.Entry(main_frame, textvariable=self.target_var, width=60)
        target_entry.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=5)

        ttk.Label(main_frame, text="Modulo de Investigación:").grid(row=2, column=0, sticky=tk.W, pady=5)
        # VOLVEMOS A MODO 'readonly' para solo permitir selección
        module_combo = ttk.Combobox(main_frame, textvariable=self.module_var, state="readonly")
        module_combo['values'] = ('domain_recon', 'email_recon', 'username_recon', 'ip_recon')
        module_combo.grid(row=3, column=0, sticky=(tk.W, tk.E), pady=5)
        module_combo.current(0)

        # --- Sección de Botones ---
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=4, column=0, columnspan=2, pady=10)
        
        self.run_button = ttk.Button(button_frame, text="¡Investigar!", command=self.start_investigation)
        self.run_button.pack(side=tk.LEFT, padx=5)

        self.view_report_button = ttk.Button(button_frame, text="Ver Último Informe", command=self.view_last_report)
        self.view_report_button.pack(side=tk.LEFT, padx=5)

        # --- Sección de Salida ---
        ttk.Label(main_frame, text="Salida de la Investigación:").grid(row=5, column=0, sticky=(tk.W, tk.N), pady=(10, 5))
        self.output_text = scrolledtext.ScrolledText(main_frame, wrap=tk.WORD, width=80, height=20, state='disabled')
        self.output_text.grid(row=6, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S), pady=5)

        # Configurar el grid para que se expanda
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(0, weight=1)
        main_frame.rowconfigure(6, weight=1)

    def start_investigation(self):
        target = self.target_var.get()
        module = self.module_var.get()

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

    def run_command(self, target, module):
        # --- MANTENEMOS LAS CORRECCIONES CLAVE ---
        print(f"[*] DEBUG: Usando el intérprete de Python en: {sys.executable}")
        command = [sys.executable, "osint_toolkit.py", "-t", target, "-m", module]
        
        env = os.environ.copy()
        env['PYTHONPATH'] = os.getcwd()
        
        try:
            self.process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding='utf-8',
                errors='replace',
                bufsize=1,
                universal_newlines=True,
                cwd=os.getcwd(),
                env=env
            )

            for line in iter(self.process.stdout.readline, ''):
                self.update_output(line)
            
            self.process.stdout.close()
            return_code = self.process.wait()
            
            self.update_output(f"\n¡Investigacion finalizada con codigo de salida: {return_code}\n")

        except Exception as e:
            self.update_output(f"\n[!] ERROR: No se pudo ejecutar el comando. ¿Esta en el directorio correcto?\n{e}\n")
        finally:
            self.run_button.config(state='normal')

    def update_output(self, text):
        self.output_text.config(state='normal')
        self.output_text.insert(tk.END, text)
        self.output_text.see(tk.END)
        self.output_text.config(state='disabled')
        self.root.update_idletasks()

    def view_last_report(self):
        list_of_files = glob.glob('results/*.json')
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