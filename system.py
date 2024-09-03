import hashlib
import json
from time import time
import tkinter as tk
from tkinter import messagebox, scrolledtext, Toplevel, filedialog, ttk
from cryptography.fernet import Fernet
from PIL import Image, ImageDraw, ImageFont, ImageTk
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import pandas as pd
from sklearn.ensemble import IsolationForest
import os
import math
import joblib

# Blockchain Implementation
class Block:
    def __init__(self, index, timestamp, transactions, previous_hash):
        self.index = index
        self.timestamp = timestamp
        self.transactions = transactions
        self.previous_hash = previous_hash
        self.hash = self.hash_block()

    def hash_block(self):
        block_string = json.dumps(self.__dict__, sort_keys=True).encode()
        return hashlib.sha256(block_string).hexdigest()

class Blockchain:
    def __init__(self):
        self.chain = []
        self.current_transactions = []
        self.new_block(previous_hash='1', proof=100)

    def new_block(self, proof, previous_hash=None):
        block = Block(
            index=len(self.chain) + 1,
            timestamp=time(),
            transactions=self.current_transactions,
            previous_hash=previous_hash or self.chain[-1].hash
        )
        self.current_transactions = []
        self.chain.append(block)
        return block

    def new_transaction(self, sender, recipient, amount):
        self.current_transactions.append({
            'sender': sender,
            'recipient': recipient,
            'amount': amount,
        })
        return self.last_block.index + 1

    @property
    def last_block(self):
        return self.chain[-1]

    def proof_of_work(self, last_proof):
        proof = 0
        while self.valid_proof(last_proof, proof) is False:
            proof += 1
        return proof

    @staticmethod
    def valid_proof(last_proof, proof):
        guess = f'{last_proof}{proof}'.encode()
        guess_hash = hashlib.sha256(guess).hexdigest()
        return guess_hash[:4] == "0000"

    def secure_sum_transaction_amounts(self, encryption_keys):
        encrypted_amounts = []
        for block in self.chain:
            for transaction in block.transactions:
                encrypted_amount = sum_encrypt(transaction['amount'], encryption_keys)
                encrypted_amounts.append(encrypted_amount)

        total_encrypted_sum = sum(encrypted_amounts)
        return sum_decrypt(total_encrypted_sum, encryption_keys)

# Function to securely encrypt and decrypt numbers for MPC
def sum_encrypt(value, keys):
    encrypted_value = value
    for key in keys:
        cipher_suite = Fernet(key)
        encrypted_value = int.from_bytes(cipher_suite.encrypt(encrypted_value.to_bytes(16, 'big')), 'big')
    return encrypted_value

def sum_decrypt(value, keys):
    decrypted_value = value
    for key in reversed(keys):
        cipher_suite = Fernet(key)
        decrypted_value = int.from_bytes(cipher_suite.decrypt(decrypted_value.to_bytes(32, 'big')), 'big')
    return decrypted_value

# Generate a key for encryption and decryption
key = Fernet.generate_key()
cipher_suite = Fernet(key)

# Function to encrypt data
def encrypt_data(data):
    encrypted_text = cipher_suite.encrypt(data.encode('utf-8'))
    return encrypted_text

# Function to decrypt data
def decrypt_data(encrypted_data):
    try:
        decrypted_text = cipher_suite.decrypt(encrypted_data).decode('utf-8')
        return decrypted_text
    except Exception as e:
        messagebox.showerror("Error", f"Decryption failed: {str(e)}")
        return None

# Function to store the cookie
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

# Function to load the cookie
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

# Function to clear the input field
def clear_field():
    entry_cookie.delete(0, tk.END)
    text_details.delete(1.0, tk.END)
    label_original_data.config(text="Original Data:")
    label_encrypted_data.config(text="Encrypted Data:")

# Function to display encryption and decryption details
def display_encryption_details(decrypted, encrypted):
    text_details.delete(1.0, tk.END)
    text_details.insert(tk.END, "Encryption and Decryption Process:\n\n")
    text_details.insert(tk.END, "1. Original data is converted to bytes.\n")
    text_details.insert(tk.END, "2. Data is encrypted using the generated key.\n")
    text_details.insert(tk.END, "3. Encrypted data is stored securely.\n")
    text_details.insert(tk.END, "4. To retrieve, encrypted data is read and decrypted using the same key.\n")
    label_original_data.config(text=f"Original Data: {decrypted}")
    label_encrypted_data.config(text=f"Encrypted Data: {encrypted}")

# Function to convert bytes to KB or MB
def convert_size(size_bytes):
    if size_bytes == 0:
        return "0B"
    size_name = ("B", "KB", "MB", "GB")
    i = int(math.floor(math.log(size_bytes, 1024)))
    p = math.pow(1024, i)
    s = round(size_bytes / p, 2)
    return f"{s} {size_name[i]}"

# Function to show encrypted data in a new window with charts
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
    
    # Original Data Label
    label_plain_data = tk.Label(new_window, text="Original Data:", bg='lightblue', font=("Arial", 12, "bold"))
    label_plain_data.pack(padx=10, pady=10)
    original_data_display = tk.Label(new_window, text=cookie_data, bg='white', font=("Arial", 12), wraplength=400)
    original_data_display.pack(padx=10, pady=5)
    
    # Encrypted Data Label
    label_encrypted_data = tk.Label(new_window, text="Encrypted Data:", bg='lightgreen', font=("Arial", 12, "bold"))
    label_encrypted_data.pack(padx=10, pady=10)
    encrypted_data_display = tk.Label(new_window, text=encrypted_data, bg='white', font=("Arial", 12), wraplength=400)
    encrypted_data_display.pack(padx=10, pady=5)

    # Data Size Information
    original_size_label = tk.Label(new_window, text=f"Original Data Size: {convert_size(original_data_size)}", bg='lightgray', font=("Arial", 12, "bold"))
    original_size_label.pack(padx=10, pady=5)
    encrypted_size_label = tk.Label(new_window, text=f"Encrypted Data Size: {convert_size(encrypted_data_size)}", bg='lightgray', font=("Arial", 12, "bold"))
    encrypted_size_label.pack(padx=10, pady=5)
    
    # Create a bar chart to visualize the data size
    fig, ax = plt.subplots(figsize=(8, 4))
    ax.bar(['Original Data', 'Encrypted Data'], [original_data_size, encrypted_data_size], color=['blue', 'green'])
    ax.set_title('Data Size Comparison')
    ax.set_ylabel('Size (bytes)')

    # Embed the plot in the Tkinter window
    chart_canvas = FigureCanvasTkAgg(fig, master=new_window)
    chart_canvas.draw()
    chart_canvas.get_tk_widget().pack(padx=10, pady=10)

# Function to select a file to encrypt
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

# Function to select a file to decrypt
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

class AnomalyDetectionApp:
    def __init__(self, root):
        self.root = root
        self.model = None
        self.create_anomaly_detection_widgets()

    def create_anomaly_detection_widgets(self):
        style = ttk.Style()
        style.configure("TButton", font=("Arial", 12), padding=10)
        style.configure("TLabel", font=("Arial", 12), padding=10)

        self.root.configure(bg='#f0f0f0')
        
        self.load_button = tk.Button(self.root, text="Load CSV File", command=self.load_csv, bg='#007BFF', fg='white', font=('Arial', 12, 'bold'))
        self.load_button.pack(pady=10)

        self.param_frame = tk.LabelFrame(self.root, text="Isolation Forest Parameters", padx=10, pady=10, bg='#f0f0f0', font=('Arial', 12, 'bold'))
        self.param_frame.pack(padx=10, pady=10, fill="x")

        tk.Label(self.param_frame, text="Contamination:", bg='#f0f0f0', font=('Arial', 12)).grid(row=0, column=0, padx=5, pady=5, sticky="e")
        self.contamination_var = tk.DoubleVar(value=0.1)
        self.contamination_entry = tk.Entry(self.param_frame, textvariable=self.contamination_var, font=('Arial', 12))
        self.contamination_entry.grid(row=0, column=1, padx=5, pady=5)

        tk.Label(self.param_frame, text="Number of Estimators:", bg='#f0f0f0', font=('Arial', 12)).grid(row=1, column=0, padx=5, pady=5, sticky="e")
        self.n_estimators_var = tk.IntVar(value=100)
        self.n_estimators_entry = tk.Entry(self.param_frame, textvariable=self.n_estimators_var, font=('Arial', 12))
        self.n_estimators_entry.grid(row=1, column=1, padx=5, pady=5)

        self.detect_button = tk.Button(self.root, text="Detect Anomalies", command=self.detect_anomalies, state=tk.DISABLED, bg='#28a745', fg='white', font=('Arial', 12, 'bold'))
        self.detect_button.pack(pady=10)

        self.data_frame = ttk.Frame(self.root)
        self.data_frame.pack(padx=10, pady=10, fill="both", expand=True)

        self.treeview = ttk.Treeview(self.data_frame, columns=[], show="headings")
        self.treeview.pack(side="left", fill="both", expand=True)

        self.scrollbar = ttk.Scrollbar(self.data_frame, orient="vertical", command=self.treeview.yview)
        self.scrollbar.pack(side="right", fill="y")

        self.treeview.configure(yscroll=self.scrollbar.set)

        self.fig = plt.Figure(figsize=(6, 4), dpi=100)
        self.ax = self.fig.add_subplot(111)
        self.canvas = FigureCanvasTkAgg(self.fig, master=self.root)
        self.canvas.get_tk_widget().pack(padx=10, pady=10, fill="both", expand=True)

        self.save_button = tk.Button(self.root, text="Save Results", command=self.save_results, state=tk.DISABLED, bg='#ffc107', fg='black', font=('Arial', 12, 'bold'))
        self.save_button.pack(side='left', padx=20, pady=10)

        self.save_model_button = tk.Button(self.root, text="Save Model", command=self.save_model, state=tk.DISABLED, bg='#ffc107', fg='black', font=('Arial', 12, 'bold'))
        self.save_model_button.pack(side='left', padx=20, pady=10)

        self.load_model_button = tk.Button(self.root, text="Load Model", command=self.load_model, bg='#ffc107', fg='black', font=('Arial', 12, 'bold'))
        self.load_model_button.pack(side='left', padx=20, pady=10)

        self.go_back_button = tk.Button(self.root, text="Go Back", command=self.root.destroy, bg='#6c757d', fg='white', font=('Arial', 12, 'bold'))
        self.go_back_button.pack(side='left', padx=20, pady=10)

        self.exit_button = tk.Button(self.root, text="Exit Program", command=self.root.quit, bg='#dc3545', fg='white', font=('Arial', 12, 'bold'))
        self.exit_button.pack(side='right', padx=20, pady=10)

        self.author_label = tk.Label(self.root, text="Author: Pavani Wijegunawardhana", bg='#f0f0f0', fg='black', font=('Arial', 10, 'italic'))
        self.author_label.pack(side='bottom', pady=10)

    def load_csv(self):
        file_path = filedialog.askopenfilename(filetypes=[("CSV Files", "*.csv")])
        if file_path:
            self.data = pd.read_csv(file_path)
            print("Data types:\n", self.data.dtypes)
            print("First few rows of data:\n", self.data.head())
            self.display_data()
            messagebox.showinfo("Info", "CSV file loaded successfully!")
            self.detect_button.config(state=tk.NORMAL)

    def display_data(self):
        self.treeview.delete(*self.treeview.get_children())
        self.treeview["columns"] = list(self.data.columns)
        for col in self.data.columns:
            self.treeview.heading(col, text=col)
            self.treeview.column(col, width=100, anchor='center')
        for index, row in self.data.iterrows():
            self.treeview.insert("", "end", values=list(row))

    def detect_anomalies(self):
        if not hasattr(self, 'data'):
            messagebox.showerror("Error", "No data loaded!")
            return

        try:
            self.data = self.data.apply(pd.to_numeric, errors='coerce')
            print("Data after conversion to numeric:\n", self.data.head())
            print("Number of NaNs per column:\n", self.data.isna().sum())

            threshold = len(self.data) * 0.5
            self.data = self.data.dropna(thresh=threshold, axis=1)
            print("Data after dropping columns with too many NaNs:\n", self.data.head())

            self.data.dropna(inplace=True)
            print("Data after dropping rows with NaNs:\n", self.data.head())

            if self.data.empty:
                messagebox.showerror("Error", "No valid data available after cleaning!")
                return

            features = self.data.columns
            X = self.data[features].values

            if self.model is None:
                self.model = IsolationForest(contamination=self.contamination_var.get(), n_estimators=self.n_estimators_var.get())
            
            self.data['anomaly'] = self.model.fit_predict(X)

            self.display_data()

            self.ax.clear()
            self.ax.scatter(self.data.index, self.data[features[0]], c=self.data['anomaly'], cmap='coolwarm', label='Anomalies')
            self.ax.set_title('Anomaly Detection')
            self.ax.set_xlabel('Index')
            self.ax.set_ylabel(features[0])
            self.ax.legend()
            self.canvas.draw()

            self.save_button.config(state=tk.NORMAL)
            self.save_model_button.config(state=tk.NORMAL)

        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {e}")

    def save_results(self):
        if not hasattr(self, 'data'):
            messagebox.showerror("Error", "No data available to save!")
            return

        file_path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV Files", "*.csv")])
        if file_path:
            self.data.to_csv(file_path, index=False)
            messagebox.showinfo("Info", "Results saved successfully!")

    def save_model(self):
        if self.model is None:
            messagebox.showerror("Error", "No model to save!")
            return

        file_path = filedialog.asksaveasfilename(defaultextension=".model", filetypes=[("Model Files", "*.model")])
        if file_path:
            joblib.dump(self.model, file_path)
            messagebox.showinfo("Info", "Model saved successfully!")

    def load_model(self):
        file_path = filedialog.askopenfilename(filetypes=[("Model Files", "*.model")])
        if file_path:
            self.model = joblib.load(file_path)
            messagebox.showinfo("Info", "Model loaded successfully!")
            self.detect_button.config(state=tk.NORMAL)

# Integrate the anomaly detection app into the existing system
def integrate_anomaly_detection_app():
    new_window = Toplevel(root)
    new_window.title("Cookie Data Anomaly Detection")
    new_window.geometry("900x600")
    new_window.attributes('-fullscreen', True)  # Fullscreen mode
    app = AnomalyDetectionApp(new_window)

# Blockchain Integration
blockchain = Blockchain()

def add_block_to_blockchain():
    sender = entry_sender.get()
    recipient = entry_recipient.get()
    amount = entry_amount.get()

    if not sender or not recipient or not amount:
        messagebox.showwarning("Input Error", "Please enter all transaction details.")
        return

    blockchain.new_transaction(sender, recipient, float(amount))
    last_proof = blockchain.last_block.index
    proof = blockchain.proof_of_work(last_proof)
    previous_hash = blockchain.last_block.hash
    block = blockchain.new_block(proof, previous_hash)

    messagebox.showinfo("Success", "Block added to blockchain!")
    display_blockchain()

def display_blockchain():
    text_blockchain.delete(1.0, tk.END)
    for block in blockchain.chain:
        text_blockchain.insert(tk.END, f"Block {block.index}:\n")
        text_blockchain.insert(tk.END, f"Timestamp: {block.timestamp}\n")
        text_blockchain.insert(tk.END, f"Transactions: {block.transactions}\n")
        text_blockchain.insert(tk.END, f"Previous Hash: {block.previous_hash}\n")
        text_blockchain.insert(tk.END, f"Hash: {block.hash}\n\n")

def calculate_secure_sum():
    # Perform secure sum of transaction amounts using MPC
    encryption_keys = [Fernet.generate_key() for _ in range(3)]  # Example with 3 keys
    total_sum = blockchain.secure_sum_transaction_amounts(encryption_keys)
    messagebox.showinfo("Secure Sum", f"The secure sum of transaction amounts is: {total_sum}")

# GUI Setup for the main application
root = tk.Tk()
root.title("Hybrid System: Secure Cookie Management, Anomaly Detection, and Blockchain")
root.configure(bg='lightgray')

# Cookie management section
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

# File encryption and decryption buttons
button_select_file_encrypt = tk.Button(root, text="Select File to Encrypt", command=select_file_to_encrypt, bg='lightblue', font=("Arial", 10, "bold"))
button_select_file_encrypt.grid(row=6, column=0, columnspan=2, padx=10, pady=10)

button_select_file_decrypt = tk.Button(root, text="Select File to Decrypt", command=select_file_to_decrypt, bg='lightblue', font=("Arial", 10, "bold"))
button_select_file_decrypt.grid(row=6, column=2, columnspan=2, padx=10, pady=10)

# Button to integrate anomaly detection
button_anomaly_detection = tk.Button(root, text="Anomaly Detection", command=integrate_anomaly_detection_app, bg='#007BFF', fg='white', font=("Arial", 10, "bold"))
button_anomaly_detection.grid(row=6, column=4, columnspan=2, padx=10, pady=10)

# Blockchain section
label_sender = tk.Label(root, text="Sender:", bg='lightgray', font=("Arial", 12, "bold"))
label_sender.grid(row=7, column=0, padx=10, pady=10, sticky='w')
entry_sender = tk.Entry(root, width=50)
entry_sender.grid(row=7, column=1, padx=10, pady=10, sticky='w')

label_recipient = tk.Label(root, text="Recipient:", bg='lightgray', font=("Arial", 12, "bold"))
label_recipient.grid(row=8, column=0, padx=10, pady=10, sticky='w')
entry_recipient = tk.Entry(root, width=50)
entry_recipient.grid(row=8, column=1, padx=10, pady=10, sticky='w')

label_amount = tk.Label(root, text="Amount:", bg='lightgray', font=("Arial", 12, "bold"))
label_amount.grid(row=9, column=0, padx=10, pady=10, sticky='w')
entry_amount = tk.Entry(root, width=50)
entry_amount.grid(row=9, column=1, padx=10, pady=10, sticky='w')

button_add_block = tk.Button(root, text="Add Block to Blockchain", command=add_block_to_blockchain, bg='lightblue', font=("Arial", 10, "bold"))
button_add_block.grid(row=10, column=0, columnspan=2, padx=10, pady=10)

text_blockchain = scrolledtext.ScrolledText(root, width=70, height=15, font=("Arial", 10))
text_blockchain.grid(row=11, column=0, columnspan=6, padx=10, pady=10)

# Secure sum button
button_secure_sum = tk.Button(root, text="Secure Sum of Transactions", command=calculate_secure_sum, bg='lightblue', font=("Arial", 10, "bold"))
button_secure_sum.grid(row=12, column=0, columnspan=2, padx=10, pady=10)

# Author label
author_label = tk.Label(root, text="Author: Pavani Wijegunawardhana", bg='lightgray', font=("Arial", 10, "italic"))
author_label.grid(row=13, column=0, columnspan=6, pady=10)

root.mainloop()
