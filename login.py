# login_app.py
import tkinter as tk
from tkinter import messagebox
from tkinter import ttk
import sqlite3
import hashlib
import os
import datetime
import re

DB_PATH = "users.db"

# -----------------------
# Utility / DB functions
# -----------------------
def center_window(win, w=380, h=260):
    win.update_idletasks()
    sw = win.winfo_screenwidth()
    sh = win.winfo_screenheight()
    x = (sw // 2) - (w // 2)
    y = (sh // 2) - (h // 2)
    win.geometry(f"{w}x{h}+{x}+{y}")

def init_db():
    """Create the SQLite DB & users table. Add a default admin if empty."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL,
            role TEXT DEFAULT 'user',
            created_at TEXT
        )
    """)
    c.execute("SELECT COUNT(*) FROM users")
    if c.fetchone()[0] == 0:
        # create a default admin (username=admin, password=123) - hashed
        try:
            create_user("admin", "123", role="admin", conn=conn)
            print("Default admin created (username=admin, password=123).")
        except sqlite3.IntegrityError:
            pass
    conn.commit()
    conn.close()

def create_user(username, password, role="user", conn=None):
    """Create user with salt + hashed password. Raises sqlite3.IntegrityError if username exists."""
    close_conn = False
    if conn is None:
        conn = sqlite3.connect(DB_PATH)
        close_conn = True

    salt = os.urandom(16).hex()
    password_hash = hashlib.sha256((salt + password).encode()).hexdigest()
    created_at = datetime.datetime.now().isoformat()

    c = conn.cursor()
    c.execute(
        "INSERT INTO users (username, password_hash, salt, role, created_at) VALUES (?, ?, ?, ?, ?)",
        (username, password_hash, salt, role, created_at)
    )
    conn.commit()
    if close_conn:
        conn.close()

def verify_user(username, password):
    """Return True if username/password match; False otherwise."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT password_hash, salt FROM users WHERE username=?", (username,))
    row = c.fetchone()
    conn.close()
    if not row:
        return False
    stored_hash, salt = row
    check_hash = hashlib.sha256((salt + password).encode()).hexdigest()
    return check_hash == stored_hash
# -----------------------------------------------------------------------------------

# GUI (Place geometry only)
def start_app():
    init_db()

    root = tk.Tk()
    root.title("Login Module")
    root.resizable(False, False)
    center_window(root, 800, 500)
    root.configure(bg="#f7f7f7")

    # Title
    lbl_title = tk.Label(root, text="User Login", font=("Arial", 40, "bold"), bg="#f7f7f7")
    lbl_title.place(x=270, y=30)

    # Username
    lbl_user = tk.Label(root, text="Username:", font=("Arial", 20), bg="#f7f7f7")
    lbl_user.place(x=90, y=170)

    #design this
    entry_user = tk.Entry(
        root,
        relief="flat",
        font=("Arial", 25),
        bg="#f0f0f0",
        highlightthickness=3,
        highlightbackground="#DDDAD0",
        insertbackground="#0D92F4",
        highlightcolor="#0D92F4",

        )
    entry_user.place(x=243, y=170, width=440)

    # Password
    lbl_pw = tk.Label(root, text="Password:", font=("Arial", 20), bg="#f7f7f7")
    lbl_pw.place(x=90, y=230)

    #design this
    entry_pw = tk.Entry(
        root,
        relief="flat",
        font=("Arial", 25),
        show="*",
        bg="#f0f0f0",
        highlightthickness=3,
        highlightbackground="#DDDAD0",
        insertbackground="#0D92F4",
        highlightcolor = "#0D92F4"

    )
    entry_pw.place(x=243, y=230, width=440)

    # Show/hide password toggle
    def toggle_pw():
        if entry_pw.cget("show") == "*":
            entry_pw.config(show="")
            btn_show_pw.config(text="Hide")
        else:
            entry_pw.config(show="*")
            btn_show_pw.config(text="Show")

    btn_show_pw = tk.Button(
        root,
        relief="flat",
        text="Show",
        command=toggle_pw,
        width=6,
        font= ("Arial", 12),
        bg=root["bg"],
        bd=0,
        activebackground=root["bg"],
        highlightthickness=0,
        fg="blue",
        cursor="hand2"
    )
    btn_show_pw.place(x=610, y=240)

    # Login function
    def do_login(event=None):
        user = entry_user.get().strip()
        pw = entry_pw.get()
        if not user or not pw:
            messagebox.showwarning("Input required", "Please enter username and password.")
            return
        if verify_user(user, pw):
            open_welcome(root, user)
        else:
            messagebox.showerror("Login Failed", "Invalid username or password.")

    # Buttons: Login / Register / Exit
    btn_login = tk.Button(root, text="Login", width=9, bg="#0D92F4", fg="white", command=do_login,font= ("Arial", 16) )
    btn_login.place(x=340, y=290)

    def open_register():
        reg = tk.Toplevel(root)
        reg.title("Register")
        reg.resizable(False, False)
        center_window(reg, 800, 500)
        reg.configure(bg="#f7f7f7")

        tk.Label(reg, text="Create Account", font=("Arial", 35, "bold"), bg="#f7f7f7").place(x=230, y=25)

        tk.Label(reg, text="Username:", font=("Arial", 20), bg="#f7f7f7").place(x=80, y=150)
        entry_r_user = tk.Entry(
            reg,
            relief="flat",
            font=("Arial", 25),
            bg="#f0f0f0",
            highlightthickness=3,
            highlightbackground="#DDDAD0",
            insertbackground="#0D92F4",
            highlightcolor="#0D92F4"
        )

        entry_r_user.place(x=345, y=145, width=350)

        tk.Label(reg, text="Password:", font=("Arial", 20), bg="#f7f7f7").place(x=80, y=210)
        entry_r_pw = tk.Entry(
            reg,
            relief="flat",
            font=("Arial", 25),
            show="*",
            bg="#f0f0f0",
            highlightthickness=3,
            highlightbackground="#DDDAD0",
            insertbackground="#0D92F4",
            highlightcolor="#0D92F4"
        )
        entry_r_pw.place(x=345, y=205, width=350)

        tk.Label(reg, text="Confirm Password:", font=("Arial", 20), bg="#f7f7f7").place(x=80, y=270)
        entry_r_pw2 = tk.Entry(
            reg,
            relief = "flat",
            font = ("Arial", 25),
            show = "*",
            bg = "#f0f0f0",
            highlightthickness = 3,
            highlightbackground = "#DDDAD0",
            insertbackground = "#0D92F4",
            highlightcolor = "#0D92F4"
        )
        entry_r_pw2.place(x=345, y=265, width=350)

        def toggle_reg_pw():
            if entry_r_pw.cget("show") == "*":
                entry_r_pw.config(show="")
                entry_r_pw2.config(show="")
                btn_reg_show.config(text="Hide")
            else:
                entry_r_pw.config(show="*")
                entry_r_pw2.config(show="*")
                btn_reg_show.config(text="Show")

        btn_reg_show = tk.Button(
            reg,
            text="Show",
            width=6,
            command=toggle_reg_pw,
            relief = "flat",
            font = ("Arial", 12),
            bg = root["bg"],
            bd = 0,
            activebackground = root["bg"],
            highlightthickness = 0,
            fg = "blue",
            cursor = "hand2"
            )
        btn_reg_show.place(x=626, y=217)

        def submit_register():
            uname = entry_r_user.get().strip()
            p1 = entry_r_pw.get()
            p2 = entry_r_pw2.get()

            # Basic validation
            if not uname or not p1 or not p2:
                messagebox.showwarning("Input required", "Please fill all fields.", parent=reg)
                return
            if p1 != p2:
                messagebox.showerror("Mismatch", "Passwords do not match.", parent=reg)
                return
            if len(uname) < 3 or len(p1) < 4:
                messagebox.showwarning("Weak", "Username must be 3+ chars and password 4+ chars.", parent=reg)
                return
            # no spaces in username
            if re.search(r"\s", uname):
                messagebox.showwarning("Invalid", "Username cannot contain spaces.", parent=reg)
                return

            try:
                create_user(uname, p1, role="user")
                messagebox.showinfo("Success", "Account created successfully! You may now login.", parent=reg)
                reg.destroy()
            except sqlite3.IntegrityError:
                messagebox.showerror("Exists", "Username already exists. Choose another.", parent=reg)

        tk.Button(reg, text="Register", width=12, bg="#007bff", fg="white", command=submit_register, font=("Arial", 18)).place(x=310, y=350)
        tk.Button(reg, text="<", width=3, command=reg.destroy, font= ("Arial", 15),bg="#f44336", fg="white" ).place(x=13, y=13)





    lbl_pw = tk.Label(root, text="___________________________________________", font=("Arial", 20), bg="#f7f7f7")
    lbl_pw.place(x=78, y=335)

    btn_register = tk.Button(root, text="Create new account", width=20, command=open_register, font=("Arial",18),bg="#4CAF50", fg="white")
    btn_register.place(x=260, y=395)

    btn_exit = tk.Button(root, text="X", width=3, bg="#f44336", fg="white", command=root.quit, font= ("Arial", 15))
    btn_exit.place(x=740, y=13)

    # Bind Enter to login
    root.bind("<Return>", do_login)

    root.mainloop()

def open_welcome(root, user):
    """Open a Toplevel welcome screen and keep root closed/hidden."""
    # Hide the main root window instead of destroying (keeps app stable)
    root.withdraw()
    welcome = tk.Toplevel()
    welcome.title("Welcome")
    welcome.resizable(False, False)
    center_window(welcome, 800, 500)
    welcome.configure(bg="#e6f7ff")

    tk.Label(welcome, text=f"Welcome, {user}!", font=("Arial", 45, "bold"), bg="#e6f7ff").place(x=160, y=140)
    tk.Button(welcome, text="Logout", width=12, command=lambda: do_logout(welcome, root), font=('Arial', 20), bg="#EDA35A", fg="white").place(x=300, y=260)
    welcome.protocol("WM_DELETE_WINDOW", lambda: do_logout(welcome, root))  # handle close button

def do_logout(welcome, root):
    welcome.destroy()
    root.deiconify()

if __name__ == "__main__":
    start_app()
