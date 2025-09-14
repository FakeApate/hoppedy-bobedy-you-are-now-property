import os
import json
import hashlib
import binascii
import tkinter as tk
from tkinter import messagebox, filedialog
from tkinter.scrolledtext import ScrolledText

DATA_DIR = "data"
USERS_FILE = os.path.join(DATA_DIR, "users.json")
KDF_ITERATIONS = 100_000  

# ---------- pomocnicze funkcje do przechowywania haseł ----------
def ensure_data_dir():
    os.makedirs(DATA_DIR, exist_ok=True)


def load_users():
    ensure_data_dir()
    if not os.path.exists(USERS_FILE):
        return {}
    with open(USERS_FILE, "r", encoding="utf-8") as f:
        try:
            return json.load(f)
        except Exception:
            return {}


def save_users(users):
    ensure_data_dir()
    with open(USERS_FILE, "w", encoding="utf-8") as f:
        json.dump(users, f, indent=2, ensure_ascii=False)


def hash_password(password: str, salt: bytes):
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, KDF_ITERATIONS)
    return binascii.hexlify(dk).decode("ascii")


def make_salt():
    return os.urandom(16)


def verify_password(stored_hash_hex: str, salt_hex: str, password_attempt: str):
    salt = binascii.unhexlify(salt_hex)
    attempt_hash = hash_password(password_attempt, salt)
    return attempt_hash == stored_hash_hex



class NotatnikApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Notatnik — logowanie / rejestracja")
        self.geometry("700x500")

        self.users = load_users()
        self.current_user = None

        
        self.login_frame = tk.Frame(self)
        self.main_frame = tk.Frame(self)

        self.create_login_frame()
        self.create_main_frame()

        self.show_login()

    
    def create_login_frame(self):
        frame = self.login_frame
        tk.Label(frame, text="Witaj — zaloguj się lub zarejestruj", font=("Arial", 14)).pack(pady=10)

        form = tk.Frame(frame)
        form.pack(pady=10, fill="x")  

        tk.Label(form, text="Nazwa użytkownika:").grid(row=0, column=0, sticky="e", padx=5, pady=5)
        self.username_entry = tk.Entry(form, width=30)
        self.username_entry.grid(row=0, column=1, padx=5, pady=5, sticky="w") 
        tk.Label(form, text="Hasło:").grid(row=1, column=0, sticky="e", padx=5, pady=5)
        self.password_entry = tk.Entry(form, width=30, show="*")
        self.password_entry.grid(row=1, column=1, padx=5, pady=5, sticky="w")

        btn_frame = tk.Frame(frame)
        btn_frame.pack(pady=10)
        tk.Button(btn_frame, text="Zaloguj", width=12, command=self.login).grid(row=0, column=0, padx=6)
        tk.Button(btn_frame, text="Zarejestruj", width=12, command=self.register).grid(row=0, column=1, padx=6)
        tk.Button(btn_frame, text="Wyjdź", width=12, command=self.quit).grid(row=0, column=2, padx=6)

    def show_login(self):
        self.main_frame.pack_forget()
        self.login_frame.pack(expand=True, fill="both")

    def login(self):
        username = self.username_entry.get().strip()
        password = self.password_entry.get()
        if not username or not password:
            messagebox.showwarning("Błąd", "Wypełnij nazwę użytkownika i hasło.")
            return

        user = self.users.get(username)
        if not user:
            messagebox.showerror("Błąd", "Użytkownik nie istnieje. Zarejestruj się.")
            return

        if verify_password(user["password_hash"], user["salt"], password):
            self.current_user = username
            self.username_entry.delete(0, tk.END)
            self.password_entry.delete(0, tk.END)
            self.open_user_notebook()
        else:
            messagebox.showerror("Błąd", "Niepoprawne hasło.")

    def register(self):
        username = self.username_entry.get().strip()
        password = self.password_entry.get()
        if not username or not password:
            messagebox.showwarning("Błąd", "Wypełnij nazwę użytkownika i hasło.")
            return

        if username in self.users:
            messagebox.showerror("Błąd", "Taki użytkownik już istnieje.")
            return

        salt = make_salt()
        salt_hex = binascii.hexlify(salt).decode("ascii")
        pwd_hash = hash_password(password, salt)
        self.users[username] = {
            "salt": salt_hex,
            "password_hash": pwd_hash,
        }
        save_users(self.users)

        user_folder = os.path.join(DATA_DIR, username)
        os.makedirs(user_folder, exist_ok=True)
        notes_path = os.path.join(user_folder, "notes.txt")
        if not os.path.exists(notes_path):
            with open(notes_path, "w", encoding="utf-8") as f:
                f.write("")

        messagebox.showinfo("Sukces", "Zarejestrowano. Możesz się teraz zalogować.")

    # ---------- ekran notatnika ----------
    def create_main_frame(self):
        frame = self.main_frame

        top = tk.Frame(frame)
        top.pack(fill="x", pady=6, padx=6)
        self.lbl_user = tk.Label(top, text="Zalogowany: —", font=("Arial", 12))
        self.lbl_user.pack(side="left")

        btns = tk.Frame(top)
        btns.pack(side="right")
        tk.Button(btns, text="Zapisz", command=self.save_notes).pack(side="left", padx=4)
        tk.Button(btns, text="Zapisz jako...", command=self.save_as).pack(side="left", padx=4)
        tk.Button(btns, text="Wyloguj", command=self.logout).pack(side="left", padx=4)

        self.text = ScrolledText(frame, wrap="word", font=("Arial", 12))
        self.text.pack(fill="both", expand=True, padx=6, pady=6)

        self.protocol("WM_DELETE_WINDOW", self.on_closing)

    def open_user_notebook(self):
        if not self.current_user:
            return

        self.lbl_user.config(text=f"Zalogowany: {self.current_user}")
        self.login_frame.pack_forget()
        self.main_frame.pack(fill="both", expand=True)

        notes_path = os.path.join(DATA_DIR, self.current_user, "notes.txt")
        if os.path.exists(notes_path):
            with open(notes_path, "r", encoding="utf-8") as f:
                content = f.read()
        else:
            content = ""
        self.text.delete("1.0", tk.END)
        self.text.insert(tk.END, content)
        self.title(f"Notatnik — {self.current_user}")

    def save_notes(self):
        if not self.current_user:
            messagebox.showwarning("Błąd", "Brak zalogowanego użytkownika.")
            return
        content = self.text.get("1.0", tk.END)
        user_folder = os.path.join(DATA_DIR, self.current_user)
        os.makedirs(user_folder, exist_ok=True)
        notes_path = os.path.join(user_folder, "notes.txt")
        try:
            with open(notes_path, "w", encoding="utf-8") as f:
                f.write(content)
            messagebox.showinfo("Zapisano", "Notatki zapisane.")
        except Exception as e:
            messagebox.showerror("Błąd zapisu", str(e))

    def save_as(self):
        content = self.text.get("1.0", tk.END)
        path = filedialog.asksaveasfilename(
            title="Zapisz notatki jako...",
            defaultextension=".txt",
            filetypes=[("Pliki tekstowe", "*.txt"), ("Wszystkie pliki", "*.*")],
        )
        if path:
            try:
                with open(path, "w", encoding="utf-8") as f:
                    f.write(content)
                messagebox.showinfo("Zapisano", f"Zapisano do {path}")
            except Exception as e:
                messagebox.showerror("Błąd", str(e))

    def logout(self):
        if messagebox.askyesno("Wyloguj", "Na pew   no chcesz się wylogować?"):
            self.current_user = None
            self.text.delete("1.0", tk.END)
            self.title("Notatnik — logowanie / rejestracja")
            self.main_frame.pack_forget()
            self.login_frame.pack(expand=True)

    def on_closing(self):
        if self.current_user:
            try:
                self.save_notes()
            except Exception:
                pass
        self.destroy()


if __name__ == "__main__":
    ensure_data_dir()
    app = NotatnikApp()
    app.mainloop()