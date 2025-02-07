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
      import re
      import hashlib

## Create the main window :-

     root = tk.Tk()
     root.title("Password Strength Analyzer")
     root.geometry("400x300") 
---

## Create a label to prompt for password input :-

     label = tk.Label(root, text="Enter Password:")
     label.pack(pady=10)

---

## Create an entry field for password input (masked as *)
     password_entry = tk.Entry(root, show="*", width=30)
     password_entry.pack(pady=10)

---

## Step 3: Function to analyze password strength :-

- Implement the logic to check for password strength using conditions like length, uppercase letters, lowercase letters, numbers, and special characters.

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

---

 ## Function to hash the password using SHA-256 :-

    def hash_password(password):
      return hashlib.sha256(password.encode()).hexdigest()

---

 

## Step 4:  Function to analyze and display password strength and hash :-

    def analyze_and_display():
    password = password_entry.get()  # Get the entered password
    strength, criteria = analyze_password(password)  # Analyze password strength
    hashed_password = hash_password(password)  # Hash the password
    
---


# Display password strength :-
    result = f"Password Strength: {strength}/5\n"
    for criterion, met in criteria.items():
        result += f"{criterion}: {'Passed' if met else 'Failed'}\n"
    
    # Display hashed password
    result += f"\nHashed Password (SHA-256): {hashed_password}"
    
    # Update the result label with password analysis and hash
    result_label.config(text=result)

---

# Create a button that triggers password analysis :-
     analyze_button = tk.Button(root, text="Analyze Password", command=analyze_and_display)
     analyze_button.pack(pady=10)

---

# Create a label to display the results
    result_label = tk.Label(root, text="")
    result_label.pack(pady=10)

---

# Start the GUI main loop
    root.mainloop()

---

- We create a hash_password function that hashes the password using the SHA-256 algorithm.

- The hashed password is displayed alongside the strength analysis results.


## Overall code :-

    import tkinter as tk
    import re
    import hashlib

    root = tk.Tk()
    root.title("Password Strength Analyzer")
    root.geometry("400x300") 


    label = tk.Label(root, text="Enter Password:")
    label.pack(pady = 10)



    password_entry = tk.Entry(root, show="*", width=30)
    password_entry.pack(pady=10)



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



    def hash_password(password):
        return hashlib.sha256(password.encode()).hexdigest()

  
    def analyze_and_display():
        password = password_entry.get()  # Get the entered password
        strength, criteria = analyze_password(password)  # Analyze password strength
        hashed_password = hash_password(password)  # Hash the password
     
   
        result = f"\nPassword Strength: {strength}/5\n"
        for criterion, met in criteria.items():
            result += f"{criterion}: {'Passed' if met else 'Failed'}\n"


        result += f"\nHashed Password (SHA-256): {hashed_password}"


        result_label.config(text=result)



    analyze_button = tk.Button(root, text="Analyze Password", command=analyze_and_display)
    analyze_button.pack(pady=10)



    result_label = tk.Label(root, text="")
    result_label.pack(pady=10)


    root.mainloop()

---

## **Here is the output i got for the input : ABHIabi123##**
  
![Screenshot 2025-02-07 101430](https://github.com/user-attachments/assets/8a6b0ed7-1e92-40e2-80ff-558348d66cb7)


## **Here is the output i got for the input : 1234**

 ![image](https://github.com/user-attachments/assets/9c6cf796-a858-4688-917b-6fac870d593d)



