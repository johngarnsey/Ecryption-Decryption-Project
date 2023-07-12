import os
import shutil
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes
import hashlib

def encrypt_folder_gcm(folder_path, password, encryption_level):
    # Generate a 32-byte key based on the user's password
    key = hashlib.sha256(password.encode()).digest()

    # Determine the AES key size based on the encryption level
    if encryption_level == "128":
        key = key[:16]
    elif encryption_level == "192":
        key = key[:24]
    elif encryption_level == "256":
        key = key[:32]

    # Check if the folder is already encrypted
    if check_folder_status(folder_path):
        print("Folder is already encrypted. Skipping encryption.")
        return None, None, None, None

    # Check if the folder is empty
    if not os.listdir(folder_path):
        print("Folder is empty. Creating an empty encrypted folder.")
        encrypted_folder_path = os.path.splitext(folder_path)[0] + ".enc"
        counter = 1

        # Append a unique number to the folder name if it already exists
        while os.path.exists(encrypted_folder_path):
            encrypted_folder_path = os.path.splitext(folder_path)[0] + f"_{counter}.enc"
            counter += 1

        try:
            os.makedirs(encrypted_folder_path)
            print("Folder encrypted:", encrypted_folder_path)

            # Remove the original empty folder
            remove_original_folder(folder_path)

            return encrypted_folder_path, password, encryption_level, nonce_dict
        except Exception as e:
            print("Error creating encrypted folder:", e)
            return None, None, None, None

    # Create a new folder for the encrypted files
    encrypted_folder_path = os.path.splitext(folder_path)[0] + ".enc"
    counter = 1

    # Append a unique number to the folder name if it already exists
    while os.path.exists(encrypted_folder_path):
        encrypted_folder_path = os.path.splitext(folder_path)[0] + f"_{counter}.enc"
        counter += 1

    try:
        os.makedirs(encrypted_folder_path)
    except Exception as e:
        print("Error creating encrypted folder:", e)
        return None, None, None, None

    nonce_dict = {} #Dictionary to store nonces for each file

    # Read the contents of the folder and encrypt each file
    encrypted = False  # Flag to track if at least one file is encrypted
    for root, dirs, files in os.walk(folder_path):
        for file in files:
            nonce = get_random_bytes(12) #generate a new nonce for each file
            nonce_dict[file] = nonce #store the nonce
            file_path = os.path.join(root, file)
            with open(file_path, "rb") as f:
                plaintext = f.read()

            # Create the AES cipher object for each file
            nonce = nonce_dict[file]
            key_length = int(encryption_level) // 8  # convert bits to bytes
            key = get_key(password, key_length)
            cipher = AES.new(key, AES.MODE_GCM)


            ciphertext, tag = cipher.encrypt_and_digest(plaintext)
            encrypted_file_path = os.path.join(encrypted_folder_path, file + ".enc")
            with open(encrypted_file_path, "wb") as f:
                f.write(cipher.nonce + tag + ciphertext)
            encrypted = True  # Set the flag to True if at least one file is encrypted
            print("File encrypted:", file_path)
            print("Encrypted file path:", encrypted_file_path)
            print("Password:", password)
            print("Encryption Level:", encryption_level)
            print("Key:", key)
            print("Nonce:", nonce)

    # Remove the original folder after successful encryption
    if encrypted:
        remove_original_folder(folder_path)
        print("Folder encrypted:", encrypted_folder_path)
        return encrypted_folder_path, password, nonce_dict
    else:
        print("No files were encrypted.")
        # Remove the empty encrypted folder
        os.rmdir(encrypted_folder_path)
        return None, None, None, None


def remove_original_folder(folder_path):
    # Remove the original folder
    shutil.rmtree(folder_path)


def check_folder_status(folder_path):
    if folder_path.endswith(".enc"):
        return True
    else:
        return False

def get_key(password, key_length):
    return hashlib.sha256(password.encode()).digest()[:key_length]
