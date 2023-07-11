import tkinter as tk
from tkinter import ttk

def save_settings():
    theme = theme_var.get()
    # Save the selected theme to a settings file or configuration database

# Create Settings window
settings_window = tk.Tk()
settings_window.title("Settings")
settings_window.geometry("300x150")

# Heading for the Theme section
theme_label = ttk.Label(settings_window, text="Theme")
theme_label.pack(pady=10)

# Store the selected theme
theme_var = tk.StringVar()

# Radio buttons for theme selection
light_theme_radio = ttk.Radiobutton(settings_window, text="Light", variable=theme_var, value="Light")
light_theme_radio.pack()

dark_theme_radio = ttk.Radiobutton(settings_window, text="Dark", variable=theme_var, value="Dark")
dark_theme_radio.pack()

# Button to save the settings
save_button = ttk.Button(settings_window, text="Save", command=save_settings)
save_button.pack(pady=20)

# Show the Settings window
settings_window.mainloop()
