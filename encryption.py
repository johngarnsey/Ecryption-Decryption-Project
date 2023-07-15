import os
import shutil
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
import hashlib
from Crypto.Hash import SHA256
import pickle

def get_key(password, key_length, encryption_level):
    key_length = int(encryption_level)
    if key_length not in [16, 24, 32]:
        raise ValueError("Invalid AES key length: " + str(key_length))
    
    key_length = key_length // 8 #converting to bytes
    password_hash = SHA256.new(password.encode()).digest()
    return password_hash[:key_length]

def encrypt_file_gcm(file_path, password, key_length, encrypted_folder_path):
    file_name = os.path.basename(file_path)
    encrypted_file_path = os.path.join(encrypted_folder_path, file_name + ".enc")   

    with open(file_path, 'rb') as file:
        data = file.read()

    # Password should be bytes
    password = password.encode('utf-8')

    # Derive a key of the correct length from the password
    salt = get_random_bytes(16)
    key = PBKDF2(password, salt, key_length)

    cipher = AES.new(key, AES.MODE_GCM)

    ciphertext, tag = cipher.encrypt_and_digest(data)

    with open(encrypted_file_path, 'wb') as encrypted_file:
        [ encrypted_file.write(x) for x in (cipher.nonce, tag, ciphertext) ]

    return encrypted_file_path, password, (cipher.nonce, key_length, salt)

def encrypt_folder_gcm(folder_path, password, encryption_level):
    if encryption_level not in ["128", "192", "256"]:
        raise ValueError("Invalid encryption level: " + str(encryption_level))
    
    key_length = int(encryption_level) // 8

    encrypted_folder_path = folder_path + ".enc"
    os.makedirs(encrypted_folder_path, exist_ok=True)

    file_encryption_data = {}
    for root, dirs, files in os.walk(folder_path):
        for file in files:
            file_path = os.path.join(root, file)
            encrypted_file_path, encryption_password, nonce_and_key_length_and_salt = encrypt_file_gcm(file_path, password, key_length, encrypted_folder_path)
            file_encryption_data[encrypted_file_path] = nonce_and_key_length_and_salt
            
    print(f"Saving nonce.pkl to: {os.path.join(encrypted_folder_path, 'nonce.pkl')}")

    with open(os.path.join(encrypted_folder_path, 'nonce.pkl'), 'wb') as nonce_file:
        pickle.dump(file_encryption_data, nonce_file)

            
    # Pickle the nonces and key lengths
    with open(os.path.join(encrypted_folder_path, 'nonce.pkl'), 'wb') as file:
        pickle.dump(file_encryption_data, file)
        print(f"Saved file_encryption_data: {file_encryption_data}")


    return encrypted_folder_path, password
