import hashlib
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import os


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Hash Generator")
        self.geometry("450x450")

        # create menu
        self.menu = tk.Menu(self)
        self.file_menu = tk.Menu(self.menu, tearoff=0)
        self.file_menu.add_command(label="Open", command=self.choose_file)
        self.file_menu.add_command(label="Save Hash Log", command=self.save_hash_log)
        self.file_menu.add_separator()
        self.file_menu.add_command(label="Exit", command=self.quit)
        self.menu.add_cascade(label="File", menu=self.file_menu)

        self.help_menu = tk.Menu(self.menu, tearoff=0)
        self.help_menu.add_command(label="About", command=self.about)
        self.menu.add_cascade(label="Help", menu=self.help_menu)
        self.config(menu=self.menu)

        # create input and output widgets
        tk.Label(self, text="Enter text or choose a file:").pack(pady=5)
        self.text_entry = tk.Entry(self, width=50)
        self.text_entry.pack(pady=5)

        tk.Button(self, text="Choose File", command=self.choose_file).pack(pady=5)

        # create hash algorithm selection
        self.hash_var = tk.StringVar(value="all")
        hash_frame = tk.Frame(self)
        hash_frame.pack(pady=5)
        tk.Label(hash_frame, text="Hash Algorithm:").pack(side=tk.LEFT)
        tk.OptionMenu(hash_frame, self.hash_var, "all", "md5", "sha1", "sha256").pack(side=tk.LEFT)

        # create progress bar
        # self.progress = tk.DoubleVar()
        # self.progress_bar = tk.ttk.Progressbar(self, variable=self.progress, maximum=10, mode="indeterminate")
        # self.progress_bar.pack(pady=5)

        tk.Button(self, text="Generate Hash", command=self.generate_hash).pack(pady=5)

        self.hash_label = tk.Label(self, text="")
        self.hash_label.pack(pady=5)

        # self.compare_entry = tk.Entry(self, width= 40)
        # self.compare_entry.pack(pady=5)
        # tk.Button(self,text="Compare with other hashes",command=self.compare_hashes).pack(pady=5)
        tk.Button(self, text="Copy Hash", command=self.copy_hash).pack(pady=5)

        # create clear button
        tk.Button(self, text="Clear", command=self.clear).pack(pady=5)

        # create hash log
        self.log_file = open("../../hash_log.txt", "a")

    def choose_file(self):
        filename = filedialog.askopenfilename()
        if filename:
            self.text_entry.delete(0, tk.END)
            self.text_entry.insert(0, filename)

    def generate_hash(self):
        text = self.text_entry.get()

        # Check if the input text is empty
        if not text:
            messagebox.showerror("Error", "Please enter some text or choose a file.")
            return

        try:
            bytes = self.read_bytes(text)
        except Exception as e:
            messagebox.showerror("Error", f"Could not read bytes: {e}")
            return

        try:
            md5_hash, sha1_hash, sha256_hash = self.calculate_hashes(bytes)
        except Exception as e:
            messagebox.showerror("Error", f"Could not calculate hashes: {e}")
            return

        self.display_hashes(md5_hash, sha1_hash, sha256_hash)
        self.log_hashes(text, md5_hash, sha1_hash, sha256_hash)

    def read_bytes(self, text):
        if os.path.isfile(text):
            with open(text, "rb") as f:
                bytes = f.read()
        else:
            bytes = text.encode()
        return bytes

    def calculate_hashes(self, bytes):
        hash_type = self.hash_var.get()
        if hash_type == "md5":
            md5_hash = hashlib.md5(bytes).hexdigest()
            return md5_hash, None, None
        elif hash_type == "sha1":
            sha1_hash = hashlib.sha1(bytes).hexdigest()
            return None, sha1_hash, None
        elif hash_type == "sha256":
            sha256_hash = hashlib.sha256(bytes).hexdigest()
            return None, None, sha256_hash
        else:
            md5_hash = hashlib.md5(bytes).hexdigest()
            sha1_hash = hashlib.sha1(bytes).hexdigest()
            sha256_hash = hashlib.sha256(bytes).hexdigest()
            return md5_hash, sha1_hash, sha256_hash

    def display_hashes(self, md5_hash, sha1_hash, sha256_hash):
        self.hash_label.config(text=f"MD5: {md5_hash}\nSHA1: {sha1_hash}\nSHA256: {sha256_hash}")

    def log_hashes(self, text, md5_hash, sha1_hash, sha256_hash):
        self.log_file.write(f"{text}\nMD5: {md5_hash}\nSHA1: {sha1_hash}\nSHA256: {sha256_hash}\n\n")

    def save_hash_log(self):
        hash_text = self.hash_label.cget("text")
        if hash_text:
            filename = filedialog.asksaveasfilename(defaultextension=".txt")
            if filename:
                with open(filename, "w") as f:
                    f.write(hash_text)

    # def compare_hashes(self):
    #     compare_text = self.compare_entry.get()
    #     hash_type = self.hash_var.get()
    #     if not compare_text:
    #         messagebox.showerror("Error", "Please enter a hash value to compare.")
    #         return
    #
    #     try:
    #         bytes = self.read_bytes(compare_text)
    #     except Exception as e:
    #         messagebox.showerror("Error", f"Could not read bytes: {e}")
    #         return
    #
    #     try:
    #         if hash_type == "md5":
    #             generated_hash = hashlib.md5(bytes).hexdigest()
    #         elif hash_type == "sha1":
    #             generated_hash = hashlib.sha1(bytes).hexdigest()
    #         elif hash_type == "sha256":
    #             generated_hash = hashlib.sha256(bytes).hexdigest()
    #         else:
    #             messagebox.showerror("Error", "Please select a hash algorithm.")
    #             return
    #     except Exception as e:
    #         messagebox.showerror("Error", f"Could not calculate hash: {e}")
    #         return
    #
    #     if generated_hash.lower() == compare_text.lower():
    #         messagebox.showinfo("Match", "Hashes match.")
    #     else:
    #         messagebox.showinfo("No match", "Hashes do not match.")

    def save_hash_log(self):
        self.log_file.close()
        filename = filedialog.asksaveasfilename(defaultextension=".txt")
        if filename:
            os.rename("../../hash_log.txt", filename)
            self.log_file = open("../../hash_log.txt", "a")
            messagebox.showinfo("Info", "Hash log saved successfully.")

    def about(self):
        messagebox.showinfo("About", "Hash Generator is a program that allows you to generate hash values for text and files using different hash algorithms. You can also save the generated hash values to a file and compare them to other hash values.\n \n Hash Generator v1.0\n Aakash Pun Magar")

    def copy_hash(self):
        hash_text = self.hash_label.cget("text")
        if hash_text:
            self.clipboard_clear()
            self.clipboard_append(hash_text)
            messagebox.showinfo("Info", "Hash copied to clipboard.")

    def clear(self):
        self.text_entry.delete(0, tk.END)
        self.hash_label.config(text="")
        self.progress.set(0)

app = App()
app.mainloop()