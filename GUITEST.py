import tkinter as tk
from tkinter import ttk

# Create the main application window
window = tk.Tk()
window.title("Folder Encryption App")
window.geometry("500x250")

# Function to handle the "Encrypt" button click
def encrypt_folder():
    encryption_level = encryption_var.get()
    print(f"Folder encryption level selected: {encryption_level}")

# Create the encryption section
encryption_label = ttk.Label(window, text="Select Encryption Level:")
encryption_label.pack()



encryption_var = tk.StringVar()
encryption_var.set("128")



# Create the Encrypt button
encrypt_button = ttk.Button(window, text="Encrypt", command=encrypt_folder)
encrypt_button.pack()

# Run the main event loop
window.mainloop()
