import tkinter as tk
from tkinter import filedialog, messagebox
from tkinter import ttk
import pandas as pd
from sklearn.ensemble import IsolationForest
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg



class AnomalyDetectionApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Cookie Data Anomaly Detection")
        self.root.geometry("900x600")
        self.create_widgets()

    def create_widgets(self):
        
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

            
            clf = IsolationForest(contamination=self.contamination_var.get(), n_estimators=self.n_estimators_var.get())
            self.data['anomaly'] = clf.fit_predict(X)

            self.display_data()

            
            self.ax.clear() 
            self.ax.scatter(self.data.index, self.data[features[0]], c=self.data['anomaly'], cmap='coolwarm', label='Anomalies')
            self.ax.set_title('Anomaly Detection')
            self.ax.set_xlabel('Index')
            self.ax.set_ylabel(features[0])
            self.ax.legend()
            self.canvas.draw()
            
            
            self.save_button.config(state=tk.NORMAL)

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

if __name__ == "__main__":
    root = tk.Tk()
    app = AnomalyDetectionApp(root)
    root.mainloop()
