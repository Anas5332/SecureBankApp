import sqlite3
import hashlib
import os
from getpass import getpass
from datetime import datetime

# Connect to SQLite database (creates bank.db file if it doesn't exist)
conn = sqlite3.connect("bank.db")
cursor = conn.cursor()

# Create the users table to store account credentials securely
cursor.execute('''
CREATE TABLE IF NOT EXISTS users (
    username TEXT PRIMARY KEY,
    hashed_password TEXT NOT NULL,
    salt TEXT NOT NULL
);
''')

# Create the transactions table to log deposits/withdrawals with timestamps
cursor.execute('''
CREATE TABLE IF NOT EXISTS transactions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    type TEXT NOT NULL,
    amount REAL NOT NULL,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(username) REFERENCES users(username)
);
''')
conn.commit()

# Generate a secure random salt (hex encoded) using CSPRNG
def generate_salt():
    return os.urandom(16).hex()

# Hash the password using PBKDF2 with the salt and SHA-256 (safe for storing)
def hash_password(password, salt):
    return hashlib.pbkdf2_hmac('sha256', password.encode(), bytes.fromhex(salt), 100000).hex()

# Handle user registration with secure password hashing and salting
def register():
    username = input("Choose a username: ")
    password = getpass("Choose a password: ")  # Hides password input
    salt = generate_salt()
    hashed = hash_password(password, salt)

    try:
        cursor.execute("INSERT INTO users (username, hashed_password, salt) VALUES (?, ?, ?)",
                       (username, hashed, salt))
        conn.commit()
        print("Registration successful.")
    except sqlite3.IntegrityError:
        print("Username already exists.")

# Handle login with password verification and simulated OTP (MFA)
def login():
    username = input("Username: ")
    password = getpass("Password: ")

    # Look up user's hashed password and salt
    cursor.execute("SELECT hashed_password, salt FROM users WHERE username = ?", (username,))
    row = cursor.fetchone()

    if row:
        # Re-hash the entered password with the stored salt
        hashed_input = hash_password(password, row[1])
        if hashed_input == row[0]:
            # Generate a secure OTP and simulate MFA
            otp = str(os.urandom(3).hex())  # 6-digit hex OTP
            print(f"[DEBUG] OTP: {otp}")    # (In real apps, you'd send this via email/SMS)
            entered = input("Enter OTP: ")
            if entered == otp:
                print("Login successful!")
                return username
            else:
                print("Invalid OTP.")
        else:
            print("Incorrect password.")
    else:
        print("User not found.")
    return None

# Deposit money for the current logged-in user
def deposit(user):
    amount = float(input("Amount to deposit: "))
    cursor.execute("INSERT INTO transactions (username, type, amount) VALUES (?, 'deposit', ?)",
                   (user, amount))
    conn.commit()
    print("Deposit successful.")

# Withdraw money if balance is sufficient
def withdraw(user):
    amount = float(input("Amount to withdraw: "))
    if amount > get_balance(user):
        print("Insufficient funds.")
        return
    cursor.execute("INSERT INTO transactions (username, type, amount) VALUES (?, 'withdraw', ?)",
                   (user, amount))
    conn.commit()
    print("Withdrawal successful.")

# Calculate and return the user's balance by adding/subtracting transactions
def get_balance(user):
    cursor.execute("SELECT type, amount FROM transactions WHERE username = ?", (user,))
    rows = cursor.fetchall()
    balance = 0
    for t, amt in rows:
        balance += amt if t == 'deposit' else -amt
    return balance

# Main menu loop for interacting with the banking system
def main():
    while True:
        print("\n1. Register\n2. Login\n3. Exit")
        choice = input("Choose an option: ")
        if choice == '1':
            register()
        elif choice == '2':
            user = login()
            if user:
                while True:
                    print("\n1. Deposit\n2. Withdraw\n3. Balance\n4. Logout")
                    op = input("Choose an option: ")
                    if op == '1':
                        deposit(user)
                    elif op == '2':
                        withdraw(user)
                    elif op == '3':
                        print("Balance:", get_balance(user))
                    elif op == '4':
                        break
        elif choice == '3':
            print("Goodbye!")
            break
        else:
            print("Invalid option.")

# Run the application
main()

# Close the database connection on exit
conn.close()
