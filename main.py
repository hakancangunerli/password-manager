import getpass
import os
import json
from cryptography.fernet import Fernet
import hashlib
import difflib
from sentence_transformers import SentenceTransformer, util
model = SentenceTransformer('paraphrase-MiniLM-L6-v2')

# Master Password
def set_master_password():
    password = getpass.getpass("Set your master password: ")
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    with open("master_password.json", "w") as f:
        f.write(hashed_password)

def check_master_password():
    password = getpass.getpass("Enter your master password: ")
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    with open("master_password.json", "r") as f:
        stored_password = f.read().strip()
    return hashed_password == stored_password

# Encryption and Decryption
def generate_key():
    return Fernet.generate_key()

def save_master_key(master_key):
    with open("master_key.json", "wb") as f:
        f.write(master_key)

def load_master_key():
    with open("master_key.json", "rb") as f:
        return f.read()

def encrypt_message(message, key):
    f = Fernet(key)
    encrypted_message = f.encrypt(message.encode())
    return encrypted_message

def decrypt_message(encrypted_message, key):
    f = Fernet(key)
    decrypted_message = f.decrypt(encrypted_message).decode()
    return decrypted_message

# Load and Save Passwords
def load_passwords():
    if os.path.exists("passwords.json"):
        with open("passwords.json", "r") as f:
            return json.load(f)
    return {}

def save_passwords(passwords):
    with open("passwords.json", "w") as f:
        json.dump(passwords, f)

# Similarity Search
def find_similar_services(query, services):
    return difflib.get_close_matches(query, services, n=5, cutoff=0.6)

def find_closest_intent(user_input):
    possibilities = ["add a password", "delete a password", "update a password", "retrieve a password"]
    embeddings = model.encode(possibilities, convert_to_tensor=True)
    user_input_embedding = model.encode(user_input, convert_to_tensor=True)

    max_similarity = -1
    closest_possibility = None

    for possibility, embedding in zip(possibilities, embeddings):
        similarity = util.pytorch_cos_sim(user_input_embedding, embedding)
        if similarity > max_similarity:
            max_similarity = similarity
            closest_possibility = possibility

    return closest_possibility

def process_message(message, master_key, passwords):
    intent = find_closest_intent(message)

    if intent == "add a password":
        service = input("For which service would you like to add a password? ")
        password = input(f"Please enter the password for {service}: ")
        encrypted_password = encrypt_message(password, master_key).decode()
        passwords[service] = encrypted_password
        return f"Password for {service} added successfully!"

    elif intent == "delete a password":
        service = input("For which service would you like to delete the password? ")
        if service in passwords:
            del passwords[service]
            return f"Password for {service} deleted successfully!"
        else:
            return f"No password found for {service}."

    elif intent == "update a password":
        service = input("For which service would you like to update the password? ")
        if service in passwords:
            password = input(f"Please enter the new password for {service}: ")
            encrypted_password = encrypt_message(password, master_key).decode()
            passwords[service] = encrypted_password
            return f"Password for {service} updated successfully!"
        else:
            return f"No password found for {service}."

    elif intent == "retrieve a password":
        service = input("For which service would you like to retrieve the password? ")
        if service in passwords:
            decrypted_password = decrypt_message(passwords[service].encode(), master_key)
            return f"Password for {service}: {decrypted_password}"
        else:
            similar_services = find_similar_services(service, passwords.keys())
            if similar_services:
                print(f"Did you mean any of these services? {', '.join(similar_services)}")
                selected_service = input("Please enter the exact service name from the list above: ")
                if selected_service in similar_services:
                    decrypted_password = decrypt_message(passwords[selected_service].encode(), master_key)
                    return f"Password for {selected_service}: {decrypted_password}"
                else:
                    return "Invalid selection!"
            else:
                return f"No password found for {service}."

    else:
        return "Sorry, I didn't understand that. Please specify what you want to do with your passwords."


def main():
    # Check if master_password.json exists; if not, set master password.
    if not os.path.exists("master_password.json"):
        print("Setting up master password for the first time...")
        set_master_password()

    # Now, check the master password
    if not check_master_password():
        print("Incorrect master password!")
        return

    # If master_key.json doesn't exist, generate and save one.
    if not os.path.exists("master_key.json"):
        master_key = generate_key()
        save_master_key(master_key)
    else:
        master_key = load_master_key()

    passwords = load_passwords()

    print("Hello! How can I assist you with your passwords?")
    while True:
        message = input("You: ")
        if message.lower() in ["quit", "exit", "bye"]:
            save_passwords(passwords)
            print("Goodbye!")
            break
        response = process_message(message, master_key, passwords)
        print(f"AI: {response}")

main()