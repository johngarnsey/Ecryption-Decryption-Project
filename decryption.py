
import os
import pickle
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2

def decrypt_file_gcm(encrypted_file_path, password, nonce_and_key_length_and_salt):
    nonce, key_length, salt = nonce_and_key_length_and_salt

    # Derive the key from the password using the same salt as encryption
    key = PBKDF2(password, salt, key_length)

    with open(encrypted_file_path, 'rb') as encrypted_file:
        nonce, tag, ciphertext = [ encrypted_file.read(x) for x in (16, 16, -1) ]

    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    data = cipher.decrypt_and_verify(ciphertext, tag)

    decrypted_file_path = os.path.splitext(encrypted_file_path)[0]

    with open(decrypted_file_path, 'wb') as decrypted_file:
        decrypted_file.write(data)

    return decrypted_file_path, password

def decrypt_folder_gcm(encrypted_folder_path, password):
    nonce_file_path = os.path.join(encrypted_folder_path, 'nonce.pkl')

    if os.path.exists(nonce_file_path):
        with open(nonce_file_path, 'rb') as nonce_file:
            file_encryption_data = pickle.load(nonce_file)
    else:
        print(f"Expected path to nonce.pkl: {nonce_file_path}")
        print(f"nonce.pkl exists at the expected path: {os.path.exists(nonce_file_path)}")
        raise ValueError("Nonce file not found in encrypted folder. Decryption cannot proceed.")

    decrypted_folder_path = os.path.splitext(encrypted_folder_path)[0]
    os.makedirs(decrypted_folder_path, exist_ok=True)

    for encrypted_file_path in file_encryption_data.keys():
        if os.path.exists(encrypted_file_path):
            nonce_and_key_length_and_salt = file_encryption_data[encrypted_file_path]
            decrypted_file_path, password = decrypt_file_gcm(encrypted_file_path, password, nonce_and_key_length_and_salt)
        else:
            print(f"Skipping file '{os.path.basename(encrypted_file_path)}' as it is not present in the encrypted folder.")

    return decrypted_folder_path, password
