
import getpass
import os
import json
import bcrypt
from cryptography.fernet import Fernet
import difflib
from sentence_transformers import SentenceTransformer, util

model = SentenceTransformer('paraphrase-MiniLM-L6-v2')

# Similarity Search Function
def find_similar_services(query, services):
    return difflib.get_close_matches(query, services, n=5, cutoff=0.6)
def save_passwords(email, passwords):
    with open(f"{PASSWORDS_DIR}/passwords_{email}.json", "w") as f:
        json.dump(passwords, f)


def process_message(message, master_key, email, passwords):
    intent = find_closest_intent(message)

    if intent == "add a password":
        service = input("For which service would you like to add credentials? ")
        username = input(f"Please enter the username for {service}: ")
        password = input(f"Please enter the password for {service}: ")
        encrypted_username = encrypt_message(username, master_key).decode()
        encrypted_password = encrypt_message(password, master_key).decode()
        passwords[service] = {"username": encrypted_username, "password": encrypted_password}
        save_passwords(email, passwords)
        return f"Credentials for {service} added successfully!"

    elif intent == "delete a password":
        service = input("For which service would you like to delete the credentials? ")
        if service in passwords:
            del passwords[service]
            save_passwords(email, passwords)
            return f"Credentials for {service} deleted successfully!"
        else:
            return f"No credentials found for {service}."

    elif intent == "update a password":
        service = input("For which service would you like to update the credentials? ")
        if service in passwords:
            username = input(f"Please enter the new username for {service} (press Enter to keep current): ")
            password = input(f"Please enter the new password for {service}: ")
            if username:
                encrypted_username = encrypt_message(username, master_key).decode()
                passwords[service]["username"] = encrypted_username
            encrypted_password = encrypt_message(password, master_key).decode()
            passwords[service]["password"] = encrypted_password
            save_passwords(email, passwords)
            return f"Credentials for {service} updated successfully!"
        else:
            return f"No credentials found for {service}."

    elif intent == "retrieve a password":
        service = input("For which service would you like to retrieve the credentials? ")
        if service in passwords:
            decrypted_username = decrypt_message(passwords[service]["username"].encode(), master_key)
            decrypted_password = decrypt_message(passwords[service]["password"].encode(), master_key)
            return f"Credentials for {service}: Username: {decrypted_username}, Password: {decrypted_password}"
        else:
            return f"No credentials found for {service}."

    else:
        return "Sorry, I didn't understand that. Please specify what you want to do with your passwords."





# Intent Recognition Function
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

# Directories for storing different data
USER_DATA_DIR = "user_data"  # New directory for user registration data
MASTER_KEY_DIR = "master_keys"
PASSWORDS_DIR = "passwords"

# Ensure directories exist
os.makedirs(USER_DATA_DIR, exist_ok=True)
os.makedirs(MASTER_KEY_DIR, exist_ok=True)
os.makedirs(PASSWORDS_DIR, exist_ok=True)

# Function to register a new user
def register_user():
    email = input("Enter your email: ")
    password = getpass.getpass("Set your master password: ")
    hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    user_data = {'email': email, 'password': hashed_password}
    with open(f"{USER_DATA_DIR}/user_{email}.json", "w") as f:
        json.dump(user_data, f)

# Function for user login
def login_user():
    email = input("Enter your email: ")
    password = getpass.getpass("Enter your master password: ")
    user_file = f"{USER_DATA_DIR}/user_{email}.json"
    if not os.path.exists(user_file):
        print("User not found. Please register first.")
        return False, None
    with open(user_file, "r") as f:
        user_data = json.load(f)
        if user_data['email'] == email and bcrypt.checkpw(password.encode(), user_data['password'].encode()):
            return True, email
        else:
            print("Incorrect email or password.")
            return False, None

# Encryption and Decryption Functions
def generate_key():
    return Fernet.generate_key()

def save_master_key(email, master_key):
    with open(f"{MASTER_KEY_DIR}/master_key_{email}.json", "wb") as f:
        f.write(master_key)

def load_master_key(email):
    with open(f"{MASTER_KEY_DIR}/master_key_{email}.json", "rb") as f:
        return f.read()

def encrypt_message(message, key):
    f = Fernet(key)
    encrypted_message = f.encrypt(message.encode())
    return encrypted_message

def decrypt_message(encrypted_message, key):
    f = Fernet(key)
    decrypted_message = f.decrypt(encrypted_message).decode()
    return decrypted_message

# Load and Save Passwords Functions
def load_passwords(email):
    if os.path.exists(f"{PASSWORDS_DIR}/passwords_{email}.json"):
        with open(f"{PASSWORDS_DIR}/passwords_{email}.json", "r") as f:
            return json.load(f)
    return {}
    

# Main Function with User Login/Registration
def main():
    if input("Do you have an account? (yes/no): ").lower() == 'no':
        register_user()

    login_success, email = login_user()
    if not login_success:
        return

    master_key_file = f"{MASTER_KEY_DIR}/master_key_{email}.json"
    if not os.path.exists(master_key_file):
        master_key = generate_key()
        save_master_key(email, master_key)
    else:
        master_key = load_master_key(email)

    passwords = load_passwords(email)

    print("Hello! How can I assist you with your passwords?")
    while True:
        message = input("You: ")
        if message.lower() in ["quit", "exit", "bye"]:
            print("Goodbye!")
            break
        response = process_message(message, master_key, email, passwords)
        print(f"AI: {response}")

if __name__ == '__main__':
    main()
