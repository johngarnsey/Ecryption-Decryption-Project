import tkinter as tk
from tkinter import messagebox

def open_about_window():
    messagebox.showinfo("About", "Folder Encryption Application\nVersion 1.0\n\nAuthor: John Garnsey")

# Create the About window
about_window = tk.Tk()
about_window.title("About")
about_window.geometry("300x150")

# Label with the application information
label = tk.Label(about_window, text="Folder Encryption Application\nVersion 1.0\n\nAuthor: John Garnsey")
label.pack(pady=20)

# Button to close the About window
close_button = tk.Button(about_window, text="Close", command=about_window.destroy)
close_button.pack(pady=10)

# Show the About window
about_window.mainloop()
