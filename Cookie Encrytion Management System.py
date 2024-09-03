import tkinter as tk
from tkinter import messagebox, scrolledtext, Toplevel, filedialog
from cryptography.fernet import Fernet
from PIL import Image, ImageDraw, ImageFont, ImageTk
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import os
import math


key = Fernet.generate_key()
cipher_suite = Fernet(key)


def encrypt_data(data):
    encrypted_text = cipher_suite.encrypt(data.encode('utf-8'))
    return encrypted_text


def decrypt_data(encrypted_data):
    try:
        decrypted_text = cipher_suite.decrypt(encrypted_data).decode('utf-8')
        return decrypted_text
    except Exception as e:
        messagebox.showerror("Error", f"Decryption failed: {str(e)}")
        return None


def store_cookie():
    cookie_data = entry_cookie.get()
    if not cookie_data:
        messagebox.showwarning("Input Error", "Please enter cookie data.")
        return
    encrypted_cookie = encrypt_data(cookie_data)
    with open("cookie.dat", "wb") as file:
        file.write(encrypted_cookie)
    display_encryption_details(cookie_data, encrypted_cookie.decode('utf-8'))
    messagebox.showinfo("Success", "Cookie stored securely!")



def load_cookie():
    try:
        with open("cookie.dat", "rb") as file:
            encrypted_cookie = file.read()
        decrypted_cookie = decrypt_data(encrypted_cookie)
        if decrypted_cookie is not None:
            entry_cookie.delete(0, tk.END)
            entry_cookie.insert(0, decrypted_cookie)
            display_encryption_details(decrypted_cookie, encrypted_cookie.decode('utf-8'))
            messagebox.showinfo("Success", "Cookie loaded successfully!")
    except FileNotFoundError:
        messagebox.showerror("Error", "No stored cookie found.")


def clear_field():
    entry_cookie.delete(0, tk.END)
    text_details.delete(1.0, tk.END)
    label_original_data.config(text="Original Data:")
    label_encrypted_data.config(text="Encrypted Data:")


def display_encryption_details(decrypted, encrypted):
    text_details.delete(1.0, tk.END)
    text_details.insert(tk.END, "Encryption and Decryption Process:\n\n")
    text_details.insert(tk.END, "1. Original data is converted to bytes.\n")
    text_details.insert(tk.END, "2. Data is encrypted using the generated key.\n")
    text_details.insert(tk.END, "3. Encrypted data is stored securely.\n")
    text_details.insert(tk.END, "4. To retrieve, encrypted data is read and decrypted using the same key.\n")
    label_original_data.config(text=f"Original Data: {decrypted}")
    label_encrypted_data.config(text=f"Encrypted Data: {encrypted}")


def convert_size(size_bytes):
    if size_bytes == 0:
        return "0B"
    size_name = ("B", "KB", "MB", "GB")
    i = int(math.floor(math.log(size_bytes, 1024)))
    p = math.pow(1024, i)
    s = round(size_bytes / p, 2)
    return f"{s} {size_name[i]}"


def show_encrypted_data_window():
    cookie_data = entry_cookie.get()
    if not cookie_data:
        messagebox.showwarning("Input Error", "Please enter cookie data.")
        return

    encrypted_data = encrypt_data(cookie_data).decode('utf-8')
    original_data_size = len(cookie_data.encode('utf-8'))
    encrypted_data_size = len(encrypted_data.encode('utf-8'))

    new_window = Toplevel(root)
    new_window.title("Encrypted Data Visualization")
    new_window.configure(bg='lightgray')
    
    
    label_plain_data = tk.Label(new_window, text="Original Data:", bg='lightblue', font=("Arial", 12, "bold"))
    label_plain_data.pack(padx=10, pady=10)
    original_data_display = tk.Label(new_window, text=cookie_data, bg='white', font=("Arial", 12), wraplength=400)
    original_data_display.pack(padx=10, pady=5)
    
    
    label_encrypted_data = tk.Label(new_window, text="Encrypted Data:", bg='lightgreen', font=("Arial", 12, "bold"))
    label_encrypted_data.pack(padx=10, pady=10)
    encrypted_data_display = tk.Label(new_window, text=encrypted_data, bg='white', font=("Arial", 12), wraplength=400)
    encrypted_data_display.pack(padx=10, pady=5)

   
    original_size_label = tk.Label(new_window, text=f"Original Data Size: {convert_size(original_data_size)}", bg='lightgray', font=("Arial", 12, "bold"))
    original_size_label.pack(padx=10, pady=5)
    encrypted_size_label = tk.Label(new_window, text=f"Encrypted Data Size: {convert_size(encrypted_data_size)}", bg='lightgray', font=("Arial", 12, "bold"))
    encrypted_size_label.pack(padx=10, pady=5)
    
    
    fig, ax = plt.subplots(figsize=(8, 4))
    ax.bar(['Original Data', 'Encrypted Data'], [original_data_size, encrypted_data_size], color=['blue', 'green'])
    ax.set_title('Data Size Comparison')
    ax.set_ylabel('Size (bytes)')

    
    chart_canvas = FigureCanvasTkAgg(fig, master=new_window)
    chart_canvas.draw()
    chart_canvas.get_tk_widget().pack(padx=10, pady=10)


def select_file_to_encrypt():
    file_path = filedialog.askopenfilename()
    if file_path:
        with open(file_path, 'rb') as file:
            file_data = file.read()
        encrypted_data = cipher_suite.encrypt(file_data)
        save_path = filedialog.asksaveasfilename(defaultextension=".enc", filetypes=[("Encrypted files", "*.enc")])
        if save_path:
            with open(save_path, 'wb') as file:
                file.write(encrypted_data)
            messagebox.showinfo("Success", f"File encrypted and saved as {os.path.basename(save_path)}")


def select_file_to_decrypt():
    file_path = filedialog.askopenfilename(filetypes=[("Encrypted files", "*.enc")])
    if file_path:
        with open(file_path, 'rb') as file:
            encrypted_data = file.read()
        try:
            decrypted_data = cipher_suite.decrypt(encrypted_data)
            save_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
            if save_path:
                with open(save_path, 'wb') as file:
                    file.write(decrypted_data)
                messagebox.showinfo("Success", f"File decrypted and saved as {os.path.basename(save_path)}")
        except Exception as e:
            messagebox.showerror("Error", f"Decryption failed: {str(e)}")


root = tk.Tk()
root.title("Advanced Secure Cookie Management System")
root.configure(bg='lightgray')

label_cookie = tk.Label(root, text="Cookie Data:", bg='lightgray', font=("Arial", 12, "bold"))
label_cookie.grid(row=0, column=0, padx=10, pady=10, sticky='w')

entry_cookie = tk.Entry(root, width=50)
entry_cookie.grid(row=0, column=1, padx=10, pady=10, sticky='w')

button_store = tk.Button(root, text="Store Cookie", command=store_cookie, bg='lightblue', font=("Arial", 10, "bold"))
button_store.grid(row=1, column=0, padx=10, pady=10)

button_load = tk.Button(root, text="Load Cookie", command=load_cookie, bg='lightblue', font=("Arial", 10, "bold"))
button_load.grid(row=1, column=1, padx=10, pady=10)

button_clear = tk.Button(root, text="Clear", command=clear_field, bg='lightyellow', font=("Arial", 10, "bold"))
button_clear.grid(row=1, column=2, padx=10, pady=10)

button_encrypt = tk.Button(root, text="Encrypt Cookie", command=lambda: display_encryption_details(entry_cookie.get(), encrypt_data(entry_cookie.get()).decode('utf-8')), bg='lightgreen', font=("Arial", 10, "bold"))
button_encrypt.grid(row=1, column=3, padx=10, pady=10)

button_show_encrypted = tk.Button(root, text="Show Encrypted Data", command=show_encrypted_data_window, bg='lightgreen', font=("Arial", 10, "bold"))
button_show_encrypted.grid(row=1, column=4, padx=10, pady=10)

button_exit = tk.Button(root, text="Exit Program", command=root.quit, bg='lightcoral', font=("Arial", 10, "bold"))
button_exit.grid(row=1, column=5, padx=10, pady=10)

label_original_data = tk.Label(root, text="Original Data:", bg='lightgray', font=("Arial", 12))
label_original_data.grid(row=2, column=0, columnspan=3, padx=10, pady=10, sticky='w')

label_encrypted_data = tk.Label(root, text="Encrypted Data:", bg='lightgray', font=("Arial", 12))
label_encrypted_data.grid(row=3, column=0, columnspan=3, padx=10, pady=10, sticky='w')

text_details = scrolledtext.ScrolledText(root, width=70, height=15, font=("Arial", 10))
text_details.grid(row=4, column=0, columnspan=6, padx=10, pady=10)


button_select_file_encrypt = tk.Button(root, text="Select File to Encrypt", command=select_file_to_encrypt, bg='lightblue', font=("Arial", 10, "bold"))
button_select_file_encrypt.grid(row=6, column=0, columnspan=2, padx=10, pady=10)

button_select_file_decrypt = tk.Button(root, text="Select File to Decrypt", command=select_file_to_decrypt, bg='lightblue', font=("Arial", 10, "bold"))
button_select_file_decrypt.grid(row=6, column=2, columnspan=2, padx=10, pady=10)


author_label = tk.Label(root, text="Author: Pavani Wijegunawardhana", bg='lightgray', font=("Arial", 10, "italic"))
author_label.grid(row=7, column=0, columnspan=6, pady=10)

root.mainloop()
