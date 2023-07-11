from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import hashlib
import os
import shutil

def decrypt_folder_gcm(encrypted_folder_path, password, encryption_level, decryption_nonces):
    decrypted_folder_path = None
    successful_decryptions = 0
    original_folder_path = os.path.splitext(encrypted_folder_path)[0]
    key = hashlib.sha256(password.encode()).digest()

    if encryption_level == "128":
        key = key[:16]
    elif encryption_level == "192":
        key = key[:24]
    elif encryption_level == "256":
        key = key[:32]

    decrypted_folder_path = original_folder_path
    os.makedirs(decrypted_folder_path, exist_ok=True)

    files = os.listdir(encrypted_folder_path)
    total_files = len(files)

    for file in files:
        if file.endswith(".enc"):
            file_path = os.path.join(encrypted_folder_path, file)
            decrypted_file_path = os.path.join(decrypted_folder_path, file[:-4])

            with open(file_path, "rb") as f:
                ciphertext = f.read()

            file_bytes = file.encode('utf-8')
            nonce = None

            for key, value in decryption_nonces.items():
                if key.encode('utf-8')[:len(file_bytes)] == file_bytes:
                    nonce = value
                    break

            if nonce is None:
                print("Decryption failed due to missing nonce:", file)
                continue

            tag = ciphertext[:16]
            ciphertext = ciphertext[16:]
            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
            try:
                plaintext = cipher.decrypt_and_verify(ciphertext, tag)
                plaintext = unpad(plaintext, AES.block_size)
                print("File decrypted:", decrypted_file_path)
                successful_decryptions += 1

                print("Original ciphertext:", ciphertext)
                print("Decrypted plaintext:", plaintext)
                print("Decryption nonce:", nonce)

                with open(decrypted_file_path, "wb") as f:
                    f.write(plaintext)
                    print("Decrypted file written:", decrypted_file_path)

                print("Decrypted folder exists:", os.path.exists(decrypted_folder_path))
                print("Decrypted file exists:", os.path.exists(decrypted_file_path))

                #os.remove(file_path)

            except ValueError:
                print("Decryption failed for file:", file)
                print("Encrypted file path:", file_path)
                print("Password:", password)
                print("Encryption Level:", encryption_level)
                print("Decryption Nonces:", decryption_nonces)
                print("Key:", key)
                print("File Path:", decrypted_file_path)
                continue

    if successful_decryptions == total_files:
        decrypted_files = os.listdir(decrypted_folder_path)
        print("Files in decrypted folder after decryption:", decrypted_files)
        print("Decrypted folder exists:", os.path.exists(decrypted_folder_path))

        print("Decrypted folder path:", decrypted_folder_path)
        print("Original files:", files)
        print("Total files:", total_files)
        if len(decrypted_files) == total_files:
            shutil.rmtree(encrypted_folder_path)
            return decrypted_folder_path, password
        else:
            print("Decryption failed. Number of decrypted files does not match the original.")
            return None, None
