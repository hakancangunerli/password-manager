import json
import random
from cryptography.fernet import Fernet
import os
# Sample services and passwords for testing
services = ["gmail", "yahoo", "hotmail", "facebook", "twitter", "amazon", "ebay", "netflix", "hulu", "disneyplus"]
passwords = ["password123", "password456", "password789", "password000", "password111", "password222", "password333", "password444", "password555", "password666"]

.# Load the master key
def load_master_key():
    with open("master_key.json", "rb") as f:
        return f.read() 

# Encrypt a message
def encrypt_message(message, key):
    f = Fernet(key)
    encrypted_message = f.encrypt(message.encode())
    return encrypted_message.decode()

# Load passwords if the file exists
def load_passwords():
    if os.path.exists("passwords.json"):
        with open("passwords.json", "r") as f:
            return json.load(f)
    return {}

# Save passwords to a file
def save_passwords(passwords):
    with open("passwords.json", "w") as f:
        json.dump(passwords, f)

def main():
    master_key = load_master_key()
    existing_passwords = load_passwords()

    # Randomly shuffle the lists
    random.shuffle(services)
    random.shuffle(passwords)

    # Encrypt and save passwords
    for service, password in zip(services, passwords):
        encrypted_password = encrypt_message(password, master_key)
        existing_passwords[service] = encrypted_password

    save_passwords(existing_passwords)
    print("Sample passwords saved successfully!")

if __name__ == "__main__":
    main()
