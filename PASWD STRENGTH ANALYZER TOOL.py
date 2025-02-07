import tkinter as tk
import re
import hashlib

# Create main app window
root = tk.Tk()
root.title("Password Strength Analyzer")
root.geometry("400x300") 

# Create label to prompt password input
label = tk.Label(root, text="Enter Password:")
label.pack(pady = 10)

# Create an entry field for password input (masked as *)

password_entry = tk.Entry(root, show="*", width=30)
password_entry.pack(pady=10)


# Function to analyze password strength
def analyze_password(password):
    strength = 0
    criteria = {
        "Length >= 8 characters": len(password) >= 8,
        "Contains uppercase letter": re.search(r"[A-Z]", password),
        "Contains lowercase letter": re.search(r"[a-z]", password),
        "Contains digit": re.search(r"\d", password),
        "Contains special character": re.search(r"[\W_]", password)
    }

    for condition, met in criteria.items():
       if met:
           strength += 1

    return strength, criteria

# Function to hash the password using SHA-256

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

  # Function to analyze and display password strength and hash
def analyze_and_display():
    password = password_entry.get()  # Get the entered password
    strength, criteria = analyze_password(password)  # Analyze password strength
    hashed_password = hash_password(password)  # Hash the password
     
   # Display password strength
    result = f"\nPassword Strength: {strength}/5\n"
    for criterion, met in criteria.items():
        result += f"{criterion}: {'Passed' if met else 'Failed'}\n"

# Display hashed password
    result += f"\nHashed Password (SHA-256): {hashed_password}"

# Update the result label with password analysis and hash
    result_label.config(text=result)

# Create a button that triggers password analysis

analyze_button = tk.Button(root, text="Analyze Password", command=analyze_and_display)
analyze_button.pack(pady=10)


# Create a label to display the results
result_label = tk.Label(root, text="")
result_label.pack(pady=10)

# Start the GUI main loop
root.mainloop()