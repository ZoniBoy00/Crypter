import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import base64
import secrets
import pyperclip
import string
import os
import re
import sys

def resource_path(relative_path):
    """ Get absolute path to resource, works for dev and for PyInstaller """
    try:
        # PyInstaller creates a temp folder and stores path in _MEIPASS
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")

    return os.path.join(base_path, relative_path)

class CryptoApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure Crypter App")
        self.root.geometry("800x600")
        
        # Käytä tätä funktiota ikonin asettamiseen
        icon_path = resource_path("Crypter.ico")
        if os.path.exists(icon_path):
            self.root.iconbitmap(icon_path)
        else:
            print(f"Warning: Icon file not found at {icon_path}")
        
        self.setup_theme()
        self.create_notebook()
        self.create_tabs()

    def setup_theme(self):
        self.style = ttk.Style()
        self.style.theme_create("HackerTheme", parent="alt", settings={
            "TNotebook": {"configure": {"background": "#0F0F0F", "tabmargins": [2, 5, 2, 0]}},
            "TNotebook.Tab": {"configure": {"padding": [5, 1], "background": "#1F1F1F", "foreground": "#00FF00"},
                              "map": {"background": [("selected", "#2F2F2F")],
                                      "expand": [("selected", [1, 1, 1, 0])]}},
            "TFrame": {"configure": {"background": "#0F0F0F"}},
            "TButton": {"configure": {"background": "#1F1F1F", "foreground": "#00FF00", "font": ("Courier", 10)}},
            "TLabel": {"configure": {"background": "#0F0F0F", "foreground": "#00FF00", "font": ("Courier", 10)}},
            "TEntry": {"configure": {"fieldbackground": "#1F1F1F", "foreground": "#00FF00", "insertcolor": "#00FF00", "font": ("Courier", 10)}},
            "TCheckbutton": {"configure": {"background": "#0F0F0F", "foreground": "#00FF00", "font": ("Courier", 10)}},
            "Vertical.TScrollbar": {"configure": {"background": "#1F1F1F", "troughcolor": "#0F0F0F"}},
        })
        self.style.theme_use("HackerTheme")
        self.root.configure(bg="#0F0F0F")

    def create_notebook(self):
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(expand=True, fill="both", padx=10, pady=10)

    def create_tabs(self):
        tabs = [
            ("Encrypt", self.create_encrypt_tab),
            ("Decrypt", self.create_decrypt_tab),
            ("Obfuscate", self.create_obfuscate_tab),
            ("Deobfuscate", self.create_deobfuscate_tab),
            ("Hash", self.create_hash_tab),
            ("Password", self.create_password_tab)
        ]
        for tab_name, tab_function in tabs:
            frame = ttk.Frame(self.notebook)
            self.notebook.add(frame, text=tab_name)
            tab_function(frame)

    def create_text_widget(self, parent, height=5):
        text_widget = tk.Text(parent, height=height, bg="#1F1F1F", fg="#00FF00", insertbackground="#00FF00", font=("Courier", 10))
        text_widget.pack(pady=5, padx=10, fill="both", expand=True)
        scrollbar = ttk.Scrollbar(parent, orient="vertical", command=text_widget.yview)
        scrollbar.pack(side="right", fill="y")
        text_widget.configure(yscrollcommand=scrollbar.set)
        return text_widget

    def create_encrypt_tab(self, parent):
        ttk.Label(parent, text="Enter text to encrypt:").pack(pady=10)
        self.encrypt_input = self.create_text_widget(parent)

        ttk.Label(parent, text="Enter encryption key (32 characters recommended):").pack(pady=5)
        self.encrypt_key_entry = ttk.Entry(parent, show="*")
        self.encrypt_key_entry.pack(pady=5, padx=10, fill="x")

        self.show_key_var = tk.BooleanVar()
        ttk.Checkbutton(parent, text="Show Key", variable=self.show_key_var, command=lambda: self.toggle_key_visibility(self.encrypt_key_entry, self.show_key_var)).pack(pady=5)

        button_frame = ttk.Frame(parent)
        button_frame.pack(pady=10)
        ttk.Button(button_frame, text="Encrypt", command=self.encrypt).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Load File", command=lambda: self.load_file(self.encrypt_input)).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Generate Key", command=self.generate_key).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Copy Key", command=lambda: self.copy_to_clipboard(self.encrypt_key_entry.get())).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Help", command=lambda: self.show_help("Encrypt")).pack(side=tk.LEFT, padx=5)

        self.encrypt_output = self.create_text_widget(parent)
        ttk.Button(parent, text="Copy Encrypted Text", command=lambda: self.copy_to_clipboard(self.encrypt_output.get("1.0", "end-1c"))).pack(pady=5)
        
    def create_decrypt_tab(self, parent):
        ttk.Label(parent, text="Enter encrypted text:").pack(pady=10)
        self.decrypt_input = self.create_text_widget(parent)

        ttk.Label(parent, text="Enter decryption key:").pack(pady=5)
        self.decrypt_key_entry = ttk.Entry(parent, show="*")
        self.decrypt_key_entry.pack(pady=5, padx=10, fill="x")

        self.show_decrypt_key_var = tk.BooleanVar()
        ttk.Checkbutton(parent, text="Show Key", variable=self.show_decrypt_key_var, command=lambda: self.toggle_key_visibility(self.decrypt_key_entry, self.show_decrypt_key_var)).pack(pady=5)

        button_frame = ttk.Frame(parent)
        button_frame.pack(pady=10)
        ttk.Button(button_frame, text="Decrypt", command=self.decrypt).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Load File", command=lambda: self.load_file(self.decrypt_input)).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Copy Key", command=lambda: self.copy_to_clipboard(self.decrypt_key_entry.get())).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Help", command=lambda: self.show_help("Decrypt")).pack(side=tk.LEFT, padx=5)

        self.decrypt_output = self.create_text_widget(parent)
        ttk.Button(parent, text="Copy Decrypted Text", command=lambda: self.copy_to_clipboard(self.decrypt_output.get("1.0", "end-1c"))).pack(pady=5)

    def create_obfuscate_tab(self, parent):
        ttk.Label(parent, text="Enter text to obfuscate:").pack(pady=10)
        self.obfuscate_input = self.create_text_widget(parent)

        button_frame = ttk.Frame(parent)
        button_frame.pack(pady=10)
        ttk.Button(button_frame, text="Obfuscate", command=self.obfuscate).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Load File", command=lambda: self.load_file(self.obfuscate_input)).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Help", command=lambda: self.show_help("Obfuscate")).pack(side=tk.LEFT, padx=5)

        self.obfuscate_output = self.create_text_widget(parent)
        ttk.Button(parent, text="Copy Obfuscated Text", command=lambda: self.copy_to_clipboard(self.obfuscate_output.get("1.0", "end-1c"))).pack(pady=5)

    def create_deobfuscate_tab(self, parent):
        ttk.Label(parent, text="Enter text to deobfuscate:").pack(pady=10)
        self.deobfuscate_input = self.create_text_widget(parent)

        button_frame = ttk.Frame(parent)
        button_frame.pack(pady=10)
        ttk.Button(button_frame, text="Deobfuscate", command=self.deobfuscate).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Load File", command=lambda: self.load_file(self.deobfuscate_input)).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Help", command=lambda: self.show_help("Deobfuscate")).pack(side=tk.LEFT, padx=5)

        self.deobfuscate_output = self.create_text_widget(parent)
        ttk.Button(parent, text="Copy Deobfuscated Text", command=lambda: self.copy_to_clipboard(self.deobfuscate_output.get("1.0", "end-1c"))).pack(pady=5)

    def create_hash_tab(self, parent):
        ttk.Label(parent, text="Enter text to hash:").pack(pady=10)
        self.hash_input = self.create_text_widget(parent)

        self.hash_algorithm = tk.StringVar(value="SHA256")
        ttk.Label(parent, text="Select hash algorithm:").pack(pady=5)
        algorithms = ["MD5", "SHA1", "SHA256", "SHA512"]
        ttk.Combobox(parent, textvariable=self.hash_algorithm, values=algorithms, state="readonly").pack(pady=5)

        button_frame = ttk.Frame(parent)
        button_frame.pack(pady=10)
        ttk.Button(button_frame, text="Hash", command=self.hash_text).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Load File", command=lambda: self.load_file(self.hash_input)).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Help", command=lambda: self.show_help("Hash")).pack(side=tk.LEFT, padx=5)

        self.hash_output = self.create_text_widget(parent, height=2)
        ttk.Button(parent, text="Copy Hash", command=lambda: self.copy_to_clipboard(self.hash_output.get("1.0", "end-1c"))).pack(pady=5)

    def create_password_tab(self, parent):
        ttk.Label(parent, text="Password Length:").pack(pady=10)
        self.password_length = tk.IntVar(value=16)
        ttk.Entry(parent, textvariable=self.password_length).pack(pady=5)

        self.use_uppercase = tk.BooleanVar(value=True)
        self.use_lowercase = tk.BooleanVar(value=True)
        self.use_digits = tk.BooleanVar(value=True)
        self.use_symbols = tk.BooleanVar(value=True)

        ttk.Checkbutton(parent, text="Uppercase", variable=self.use_uppercase).pack(pady=5)
        ttk.Checkbutton(parent, text="Lowercase", variable=self.use_lowercase).pack(pady=5)
        ttk.Checkbutton(parent, text="Digits", variable=self.use_digits).pack(pady=5)
        ttk.Checkbutton(parent, text="Symbols", variable=self.use_symbols).pack(pady=5)

        button_frame = ttk.Frame(parent)
        button_frame.pack(pady=10)
        ttk.Button(button_frame, text="Generate Password", command=self.generate_password).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Help", command=lambda: self.show_help("Password")).pack(side=tk.LEFT, padx=5)

        self.password_output = self.create_text_widget(parent, height=2)
        ttk.Button(parent, text="Copy Password", command=lambda: self.copy_to_clipboard(self.password_output.get("1.0", "end-1c"))).pack(pady=5)
        
    def encrypt(self):
        text = self.encrypt_input.get("1.0", "end-1c")
        key = self.encrypt_key_entry.get()
        if not self.validate_input(text, "Text to encrypt") or not self.validate_key(key):
            return
        try:
            encrypted = self.fernet_encrypt(text, key)
            self.encrypt_output.delete("1.0", "end")
            self.encrypt_output.insert("1.0", encrypted)
        except Exception as e:
            messagebox.showerror("Error", f"Encryption failed: {str(e)}")

    def decrypt(self):
        text = self.decrypt_input.get("1.0", "end-1c")
        key = self.decrypt_key_entry.get()
        if not self.validate_input(text, "Encrypted text") or not self.validate_key(key):
            return
        try:
            decrypted = self.fernet_decrypt(text, key)
            self.decrypt_output.delete("1.0", "end")
            self.decrypt_output.insert("1.0", decrypted)
        except Exception as e:
            messagebox.showerror("Error", f"Decryption failed: {str(e)}")

    def obfuscate(self):
        text = self.obfuscate_input.get("1.0", "end-1c")
        if not self.validate_input(text, "Text to obfuscate"):
            return
        obfuscated = base64.b85encode(text.encode()).decode()
        self.obfuscate_output.delete("1.0", "end")
        self.obfuscate_output.insert("1.0", obfuscated)

    def deobfuscate(self):
        text = self.deobfuscate_input.get("1.0", "end-1c")
        if not self.validate_input(text, "Obfuscated text"):
            return
        try:
            deobfuscated = base64.b85decode(text.encode()).decode()
            self.deobfuscate_output.delete("1.0", "end")
            self.deobfuscate_output.insert("1.0", deobfuscated)
        except Exception as e:
            messagebox.showerror("Error", f"Deobfuscation failed: {str(e)}")

    def hash_text(self):
        text = self.hash_input.get("1.0", "end-1c")
        if not self.validate_input(text, "Text to hash"):
            return
        algorithm = self.hash_algorithm.get()
        try:
            if algorithm == "MD5":
                hash_object = hashes.Hash(hashes.MD5(), backend=default_backend())
            elif algorithm == "SHA1":
                hash_object = hashes.Hash(hashes.SHA1(), backend=default_backend())
            elif algorithm == "SHA256":
                hash_object = hashes.Hash(hashes.SHA256(), backend=default_backend())
            elif algorithm == "SHA512":
                hash_object = hashes.Hash(hashes.SHA512(), backend=default_backend())
            else:
                raise ValueError("Invalid hash algorithm")
            
            hash_object.update(text.encode())
            hashed = hash_object.finalize().hex()
            self.hash_output.delete("1.0", "end")
            self.hash_output.insert("1.0", hashed)
        except Exception as e:
            messagebox.showerror("Error", f"Hashing failed: {str(e)}")

    def generate_password(self):
        try:
            length = self.password_length.get()
            if length <= 0:
                raise ValueError("Password length must be positive")
            
            character_set = ""
            if self.use_uppercase.get():
                character_set += string.ascii_uppercase
            if self.use_lowercase.get():
                character_set += string.ascii_lowercase
            if self.use_digits.get():
                character_set += string.digits
            if self.use_symbols.get():
                character_set += string.punctuation
            
            if not character_set:
                raise ValueError("At least one character set must be selected")
            
            password = ''.join(secrets.choice(character_set) for _ in range(length))
            self.password_output.delete("1.0", "end")
            self.password_output.insert("1.0", password)
        except Exception as e:
            messagebox.showerror("Error", f"Password generation failed: {str(e)}")

    def load_file(self, text_widget):
        file_path = filedialog.askopenfilename(filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if file_path:
            try:
                with open(file_path, 'r', encoding='utf-8') as file:
                    content = file.read()
                text_widget.delete("1.0", "end")
                text_widget.insert("1.0", content)
            except Exception as e:
                messagebox.showerror("Error", f"Failed to load file: {str(e)}")

    def generate_key(self):
        key = Fernet.generate_key().decode()
        self.encrypt_key_entry.delete(0, "end")
        self.encrypt_key_entry.insert(0, key)

    def toggle_key_visibility(self, entry_widget, show_var):
        entry_widget.config(show="" if show_var.get() else "*")

    def copy_to_clipboard(self, text):
        pyperclip.copy(text)
        messagebox.showinfo("Copied", "Text copied to clipboard!")

    def fernet_encrypt(self, text, key):
        key = self.pad_key(key)
        f = Fernet(base64.urlsafe_b64encode(key.encode()))
        return f.encrypt(text.encode()).decode()

    def fernet_decrypt(self, text, key):
        key = self.pad_key(key)
        f = Fernet(base64.urlsafe_b64encode(key.encode()))
        return f.decrypt(text.encode()).decode()

    def pad_key(self, key):
        if len(key) < 32:
            return key.ljust(32, '0')
        elif len(key) > 32:
            return key[:32]
        return key

    def validate_input(self, text, field_name):
        if not text.strip():
            messagebox.showerror("Error", f"{field_name} cannot be empty")
            return False
        return True

    def validate_key(self, key):
        if not key:
            messagebox.showerror("Error", "Encryption key cannot be empty")
            return False
        return True

    def show_help(self, tool):
        help_texts = {
            "Encrypt": "Encrypt your text using Fernet symmetric encryption. Enter your text, provide a key (32 characters recommended), and click 'Encrypt'.",
            "Decrypt": "Decrypt Fernet-encrypted text. Enter the encrypted text, provide the correct key, and click 'Decrypt'.",
            "Obfuscate": "Obfuscate your text using Base85 encoding. Enter your text and click 'Obfuscate'.",
            "Deobfuscate": "Deobfuscate Base85 encoded text. Enter the obfuscated text and click 'Deobfuscate'.",
            "Hash": "Generate a hash of your text using various algorithms. Choose an algorithm, enter your text, and click 'Hash'.",
            "Password": "Generate a secure random password. Set the length and character types, then click 'Generate Password'."
        }
        messagebox.showinfo(f"{tool} Help", help_texts[tool])

if __name__ == "__main__":
    root = tk.Tk()
    app = CryptoApp(root)
    root.mainloop()