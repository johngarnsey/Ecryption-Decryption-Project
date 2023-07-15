import tkinter as tk
from tkinter import ttk
import sys
import os
from encryption import encrypt_folder_gcm
from decryption import decrypt_folder_gcm

def encrypt_or_decrypt_folder():
    global password, folder_path, encryption_level, mode
    path = folder_path.get()
    pwd = password.get()
    encryption_level_value = encryption_level.get()

    # Update mode based on folder path
    mode.set('decrypt' if path.endswith('.enc') else 'encrypt')

    if mode.get() == 'encrypt':
        encrypted_folder_path, encryption_password = encrypt_folder_gcm(
            path, pwd, encryption_level_value
        )
        print(f"Folder encrypted: {encrypted_folder_path}")

        # Update folder_path variable with encrypted_folder_path
        folder_path.set(encrypted_folder_path)
    elif mode.get() == 'decrypt':
        decrypted_folder_path, encryption_password = decrypt_folder_gcm(
            path, pwd
        )
        print(f"Folder decrypted: {decrypted_folder_path}")

        # Update folder_path variable with decrypted_folder_path
        folder_path.set(decrypted_folder_path)
        file_path_label.config(text="Current File: " + folder_path.get())


window = tk.Tk()
window.title("Folder Encryption App")
window.geometry("600x300")

file_path_label = ttk.Label(window, text="Current File: ", font=("Arial", 14, "bold"))
file_path_label.pack(pady=(30, 10))

encryption_label = ttk.Label(window, text="Select Encryption Level:")
encryption_label.pack()

encryption_frame = ttk.Frame(window)
encryption_frame.pack()

encryption_level = tk.StringVar(value="128")
encryption_128 = ttk.Radiobutton(encryption_frame, text="AES-128", variable=encryption_level, value="128")
encryption_128.grid(row=0, column=0, sticky="w")
low_label_128 = ttk.Label(encryption_frame, text="(Low)")
low_label_128.grid(row=0, column=1, sticky="w")

encryption_192 = ttk.Radiobutton(encryption_frame, text="AES-192", variable=encryption_level, value="192")
encryption_192.grid(row=1, column=0, sticky="w")
medium_label_192 = ttk.Label(encryption_frame, text="(Medium)")
medium_label_192.grid(row=1, column=1, sticky="w")

encryption_256 = ttk.Radiobutton(encryption_frame, text="AES-256", variable=encryption_level, value="256")
encryption_256.grid(row=2, column=0, sticky="w")
high_label_256 = ttk.Label(encryption_frame, text="(High)")
high_label_256.grid(row=2, column=1, sticky="w")

password_label = ttk.Label(window, text="Enter Password/Passphrase/PIN:")
password_label.pack()

password = tk.StringVar()
password_entry = ttk.Entry(window, show="*", textvariable=password)
password_entry.pack()

progress_bar = ttk.Progressbar(window, orient="horizontal", length=400, mode="determinate")
progress_bar.pack(pady=10)

folder_path = tk.StringVar(value=sys.argv[1] if len(sys.argv) > 1 else "")
file_path_label.config(text="Current File: " + folder_path.get())

mode = tk.StringVar(value="decrypt" if folder_path.get().endswith('.enc') else "encrypt")

encrypt_button = ttk.Button(window, text="Encrypt/Decrypt Folder", command=encrypt_or_decrypt_folder)
encrypt_button.pack(pady=10)

window.mainloop()
