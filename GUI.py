import tkinter as tk
from tkinter import ttk
import subprocess
import os
import shutil
import sys
from encryption import encrypt_folder_gcm
from decryption import decrypt_folder_gcm
from Crypto.Random import get_random_bytes


#=======================================================
# Author: John Garnsey
# Master's Project: Folder Encryption Application
# A simple GUI for encrypting folders using AES encryption
# with selectable encryption levels (128, 192, or 256 bit)
# Users may also right-click for more information / options
#=======================================================

decryption_nonces = None  #global var

def open_about_window():
    subprocess.Popen(["python", "about.py"], shell=True)

def open_settings_window():
    subprocess.Popen(["python", "settings.py"], shell=True)

def encrypt_or_decrypt_folder():
    global is_folder_encrypted, encryption_password, folder_path, encrypted_folder_path, decryption_nonces

    # Get the password from the password entry field
    password = password_entry.get()

    if check_folder_status():
        # Folder is encrypted, perform decryption
        if password == encryption_password:
            if decryption_nonces is not None:
                decrypted_folder_path, encryption_password = decrypt_folder_gcm(
                    folder_path, password, encryption_level.get(), decryption_nonces
                )

                if decrypted_folder_path:
                    print("Folder decrypted:", decrypted_folder_path)
                    # Remove the old encrypted folder
                    shutil.rmtree(encrypted_folder_path)
                    # Update the folder path with the decrypted folder path
                    folder_path = decrypted_folder_path
                    encrypted_folder_path = ""
                else:
                    print("No files were decrypted.")
                progress_bar.stop()
                is_folder_encrypted = False
            else:
                print("No nonces available for decryption. Please encrypt a folder first.")
                return
        else:
            print("Incorrect password for decryption!")
    else:
        # Folder is not encrypted, perform encryption
        if folder_path:
            encrypted_folder_path, encryption_password, decryption_nonces = encrypt_folder_gcm(folder_path, password, encryption_level.get())
            if encrypted_folder_path:
                print("Folder encrypted:", encrypted_folder_path)
                progress_bar.start()
                is_folder_encrypted = True
            else:
                print("No files were encrypted.")


    if check_folder_status():
        encrypt_button.config(text="Decrypt Folder")
    else:
        encrypt_button.config(text="Encrypt Folder")


def set_folder_path(path):
    global folder_path, is_folder_encrypted, encrypted_folder_path

    folder_path = path
    file_path_label.config(text="Current File: " + folder_path)

    if folder_path.endswith(".enc"):
        is_folder_encrypted = True
        encrypt_button.config(text="Decrypt Folder")
        encrypted_folder_path = os.path.splitext(folder_path)[0]
    else:
        is_folder_encrypted = False
        encrypt_button.config(text="Encrypt Folder")
        encrypted_folder_path = ""

def check_folder_status():
    global is_folder_encrypted
    return is_folder_encrypted

def show_menu(event):
    menu.post(event.x_root, event.y_root)

def set_folder_path_from_command_line():
    if len(sys.argv) > 1:
        folder_path = sys.argv[1]
        set_folder_path(folder_path)

window = tk.Tk()
window.title("Folder Encryption App")
window.geometry("600x300")

file_path_label = ttk.Label(window, text="Current File: ", font=("Arial", 14, "bold"))
file_path_label.pack(pady=(30, 10))

encryption_label = ttk.Label(window, text="Select Encryption Level:")
encryption_label.pack()

encryption_frame = ttk.Frame(window)
encryption_frame.pack()

encryption_level = tk.StringVar()
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

password_entry = ttk.Entry(window, show="*")
password_entry.pack()

progress_bar = ttk.Progressbar(window, orient="horizontal", length=400, mode="determinate")
progress_bar.pack(pady=10)

is_folder_encrypted = False
encryption_password = ""
folder_path = ""
encrypted_folder_path = ""
decryption_nonce = None

encrypt_button = ttk.Button(window, text="Encrypt Folder", command=encrypt_or_decrypt_folder)
encrypt_button.pack(pady=10)

menu = tk.Menu(window, tearoff=0)
menu.add_command(label="Settings", command=open_settings_window)
menu.add_command(label="About", command=open_about_window)

window.bind("<Button-3>", show_menu)

set_folder_path_from_command_line()

window.mainloop()
