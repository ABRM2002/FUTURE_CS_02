## FUTURE_CS_02

### HELLO 😀
### Here is the walkthrough documentation of how I completed Task 2 of the Cyber Security Internship at Future Interns :-

---

# Task 2 : **Build a Password Strength Analyzer Tool**
![image](https://github.com/user-attachments/assets/6356f8bc-b5c8-48dd-9c16-2378d81ea280)

---
## STEPS :-

## Step 1: Set Up Your Environment :-

- Ensure you have Python installed and necessary libraries like tkinter (for GUI) and hashlib (for encryption).

- Install Python : https://www.python.org/downloads

- install Tkinter : Open your cmd and type in pip install tk

---

## Step 2: Create Basic GUI Structure with Tkinter :-

- Start by creating a simple window with tkinter where users can input a password and click a button to analyze it.

- On your VS Code type :-
  
       import tkinter as tk

## Create the main window :-

     root = tk.Tk()
     root.title("Password Strength Analyzer")
---

## Create entry for password input :-

     label = tk.Label(root, text="Enter Password:")
     label.pack()
     password_entry = tk.Entry(root, show="*")
     password_entry.pack()

---

## Create a button to analyze password :-
     analyze_button = tk.Button(root, text="Analyze Password")
     analyze_button.pack()
     root.mainloop()

---

## Step 3: Add Password Analysis Logic :-

- Implement the logic to check for password strength using conditions like length, uppercase letters, lowercase letters, numbers, and special characters.

         import re

         def analyze_password(password):
         strength = 0
         criteria = {
         "length": len(password) >= 8,
         "uppercase": re.search(r"[A-Z]", password),
         "lowercase": re.search(r"[a-z]", password),
         "digit": re.search(r"\d", password),
         "special_char": re.search(r"[\W_]", password) }
          for condition, met in criteria.items():
          if met:
          strength += 1
          return strength, criteria

---

## Step 4: Display the Results in the GUI :-

- Update the tkinter GUI to display the password strength to the user when they click the "Analyze Password" button.

       def analyze_and_display():
       password = password_entry.get()
       strength, criteria = analyze_password(password)
       result = f"Password Strength: {strength}/5\n"
       for criterion, met in criteria.items():
       result += f"{criterion}: {'Passed' if met else 'Failed'}\n"
       result_label.config(text=result)

## Update button functionality :-
       analyze_button.config(command=analyze_and_display)

## Create a label to display the results :-
    result_label = tk.Label(root, text="")
    result_label.pack()
    root.mainloop()

---

## Step 5: Add Encryption (Hashing) with hashlib :-

- To enhance security, you can include password hashing using the hashlib library. This will hash the password and display the hash to the user.


       import hashlib

      def hash_password(password):
       return hashlib.sha256(password.encode()).hexdigest()

       def analyze_and_display():
       password = password_entry.get()
       strength, criteria = analyze_password(password)
       hashed_password = hash_password(password)
    
       result = f"Password Strength: {strength}/5\n"
       for criterion, met in criteria.items():
        result += f"{criterion}: {'Passed' if met else 'Failed'}\n"
    
      result += f"\nHashed Password: {hashed_password}"
    
      result_label.config(text=result)

   ---

## Step 7: Add Hashing with hashlib for Encryption :-

  - To enhance security, you can hash the password using the hashlib library.

         import hashlib

## Function to hash the password :-
    def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

## Update the analyze_and_display function to include password hashing :-
    
    def analyze_and_display():
    password = password_entry.get()  # Get password input
    strength, criteria = analyze_password(password)  # Analyze password
    hashed_password = hash_password(password)  # Hash the password

    result_text = f"Password Strength: {strength}/5\n"
    for criterion, met in criteria.items():
        result_text += f"{criterion}: {'Passed' if met else 'Failed'}\n"
    
    result_text += f"\nHashed Password (SHA-256): {hashed_password}"
    result_label.config(text=result_text)  # Update result label

- We create a hash_password function that hashes the password using the SHA-256 algorithm.

- The hashed password is displayed alongside the strength analysis results.

## **Here is the output i got for the input : ABHIabi123##**
  
![Screenshot 2025-02-07 101430](https://github.com/user-attachments/assets/8a6b0ed7-1e92-40e2-80ff-558348d66cb7)




