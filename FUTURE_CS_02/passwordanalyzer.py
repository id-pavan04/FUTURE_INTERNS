import tkinter as tk
from tkinter import messagebox
import hashlib
import re

# Function to check password strength
def check_password_strength(password):
    length_criteria = len(password) >= 8
    uppercase_criteria = bool(re.search(r'[A-Z]', password))
    lowercase_criteria = bool(re.search(r'[a-z]', password))
    number_criteria = bool(re.search(r'[0-9]', password))
    special_char_criteria = bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', password))

    strength_score = sum([length_criteria, uppercase_criteria, lowercase_criteria, number_criteria, special_char_criteria])

    if strength_score == 5:
        return "Strong", "green"
    elif strength_score >= 3:
        return "Medium", "orange"
    else:
        return "Weak", "red"

# Function to hash the password
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# GUI Functionality
def check_password():
    password = entry.get()
    if not password:
        messagebox.showwarning("Warning", "Please enter a password!")
        return

    strength, color = check_password_strength(password)
    hashed_password = hash_password(password)

    strength_label.config(text=f"Strength: {strength}", fg=color)
    hash_label.config(text=f"Hashed Password: {hashed_password}")

# GUI Setup
root = tk.Tk()
root.title("🔐 Password Strength Analyzer")
root.geometry("400x350")
root.configure(bg="#1E1E1E")  # Dark background

# Title
tk.Label(root, text="Password Strength Analyzer", font=("Arial", 16, "bold"), fg="white", bg="#1E1E1E").pack(pady=10)

# Input Label & Entry
tk.Label(root, text="Enter Password:", font=("Arial", 12), fg="white", bg="#1E1E1E").pack()
entry = tk.Entry(root, show="*", width=30, font=("Arial", 12), bg="#333333", fg="white")
entry.pack(pady=5)

# Submit Button
tk.Button(root, text="Check Strength", font=("Arial", 12, "bold"), bg="#00ADB5", fg="white", command=check_password).pack(pady=10)

# Strength Label
strength_label = tk.Label(root, text="", font=("Arial", 12, "bold"), bg="#1E1E1E")
strength_label.pack()

# Hash Label
hash_label = tk.Label(root, text="", font=("Arial", 10), wraplength=380, fg="white", bg="#1E1E1E")
hash_label.pack(pady=10)

# Run GUI
root.mainloop()
