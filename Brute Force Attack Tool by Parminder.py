import itertools
import string
import time
import logging
import tkinter as tk
from tkinter import ttk, messagebox
import threading  # Import threading for background execution

# Setup logging to output to a file
logging.basicConfig(filename='bruteforce.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')


# Define a class for the GUI application
class BruteForceApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Brute Force Attack Tool")
        self.attack_stopped = False  # Flag to stop the attack
        self.attack_thread = None  # Thread to handle brute force

        # Create GUI elements
        self.label = tk.Label(root, text="Brute Force Attack Simulation by Parminder ", font=("Helvetica", 12))
        self.label.pack(pady=10)

        self.password_label = tk.Label(root, text="Enter Target Password (1-8 characters):")
        self.password_label.pack()

        self.password_entry = tk.Entry(root, show="*")
        self.password_entry.pack(pady=5)

        self.charset_label = tk.Label(root, text="Character Set:")
        self.charset_label.pack()

        self.lowercase_var = tk.IntVar()
        self.uppercase_var = tk.IntVar()
        self.digits_var = tk.IntVar()
        self.special_var = tk.IntVar()

        self.lowercase_check = tk.Checkbutton(root, text="Lowercase Letters", variable=self.lowercase_var)
        self.uppercase_check = tk.Checkbutton(root, text="Uppercase Letters", variable=self.uppercase_var)
        self.digits_check = tk.Checkbutton(root, text="Digits", variable=self.digits_var)
        self.special_check = tk.Checkbutton(root, text="Special Characters", variable=self.special_var)

        self.lowercase_check.pack()
        self.uppercase_check.pack()
        self.digits_check.pack()
        self.special_check.pack()

        self.start_button = tk.Button(root, text="Start Brute Force Attack", command=self.start_attack)
        self.start_button.pack(pady=10)

        self.stop_button = tk.Button(root, text="Stop Attack", fg="red", command=self.stop_attack)
        self.stop_button.pack(pady=5)

        self.result_text = tk.Text(root, height=10, width=50, state=tk.DISABLED)
        self.result_text.pack(pady=5)

        # Real-Time Statistics
        self.attempt_label = tk.Label(root, text="Attempts: 0")
        self.attempt_label.pack(pady=5)

        self.time_elapsed_label = tk.Label(root, text="Time Elapsed: 0s")
        self.time_elapsed_label.pack(pady=5)

        self.speed_label = tk.Label(root, text="Speed: 0 attempts/sec")
        self.speed_label.pack(pady=5)

    def start_attack(self):
        # Reset the flag and the GUI elements if starting a new attack
        self.attack_stopped = False
        self.reset_gui()

        # Get the target password
        target_password = self.password_entry.get()

        # Validate password length
        if not (1 <= len(target_password) <= 8):
            messagebox.showerror("Invalid Password", "Please enter a password with 1-8 characters.")
            return

        # Generate the character set based on the user's selection
        charset = ""
        if self.lowercase_var.get():
            charset += string.ascii_lowercase
        if self.uppercase_var.get():
            charset += string.ascii_uppercase
        if self.digits_var.get():
            charset += string.digits
        if self.special_var.get():
            charset += "!@#$%^&*(){}[]:\";',.?"

        if not charset:
            messagebox.showerror("No Character Set Selected", "Please select at least one character set.")
            return

        logging.info(f'Target password: {target_password}')
        logging.info(f'Charset: {charset}')

        # Disable the buttons during the attack
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)

        # Start the brute force attack in a separate thread
        self.attack_thread = threading.Thread(target=self.brute_force, args=(target_password, charset))
        self.attack_thread.start()

    def brute_force(self, target, charset):
        start_time = time.time()
        attempts = 0
        found = False
        total_combinations = sum(len(charset) ** i for i in range(1, 9))

        # Clear the result text box
        self.result_text.config(state=tk.NORMAL)
        self.result_text.delete(1.0, tk.END)

        # Loop through all possible lengths of passwords
        for password_length in range(1, 9):
            self.result_text.insert(tk.END, f"[*] Trying passwords of length {password_length}...\n")
            self.result_text.update()

            # Generate all possible combinations of the charset for the given length
            for guess in itertools.product(charset, repeat=password_length):
                if self.attack_stopped:
                    self.result_text.insert(tk.END, "[-] Attack stopped by user.\n")
                    logging.info('Attack stopped by user.')
                    self.enable_buttons()
                    return

                guess = ''.join(guess)
                attempts += 1

                # Update Real-Time Statistics
                elapsed_time = time.time() - start_time
                speed = attempts / elapsed_time if elapsed_time > 0 else 0
                self.attempt_label.config(text=f"Attempts: {attempts}")
                self.time_elapsed_label.config(text=f"Time Elapsed: {elapsed_time:.2f}s")
                self.speed_label.config(text=f"Speed: {speed:.2f} attempts/sec")

                # Display progress every 10000 attempts
                if attempts % 10000 == 0:
                    self.result_text.insert(tk.END, f'[*] {attempts} attempts made. Current guess: {guess}\n')
                    self.result_text.update()

                # If the guess matches the target password
                if guess == target:
                    found = True
                    end_time = time.time()
                    elapsed_time = end_time - start_time
                    self.result_text.insert(tk.END, f"[+] Password '{guess}' found!\n")
                    self.result_text.insert(tk.END, f"[*] Time taken: {elapsed_time:.2f} seconds\n")
                    self.result_text.insert(tk.END, f"[*] Total attempts: {attempts}\n")
                    logging.info(f'Password "{guess}" found in {elapsed_time:.2f} seconds.')

                    # Pop-up success message
                    messagebox.showinfo("Success", f"Password '{guess}' found in {elapsed_time:.2f} seconds!\nTotal attempts: {attempts}")
                    self.enable_buttons()
                    return

            if found:
                break

        if not found:
            self.result_text.insert(tk.END, "[-] Password not found.\n")
            logging.info('Password not found.')

            # Pop-up failure message
            messagebox.showwarning("Failed", "Password not found after all attempts.")

        self.enable_buttons()

    def stop_attack(self):
        self.attack_stopped = True  # Set the flag to stop the attack

    def enable_buttons(self):
        # Re-enable the start button and disable the stop button after the attack
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)

    def reset_gui(self):
        # Reset all GUI elements to their initial state
        self.result_text.config(state=tk.NORMAL)
        self.result_text.delete(1.0, tk.END)
        self.attempt_label.config(text="Attempts: 0")
        self.time_elapsed_label.config(text="Time Elapsed: 0s")
        self.speed_label.config(text="Speed: 0 attempts/sec")
        self.attack_stopped = False  # Reset the stop flag


# Initialize the main Tkinter window
root = tk.Tk()
app = BruteForceApp(root)
root.mainloop()



