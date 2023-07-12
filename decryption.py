from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import hashlib
import os
import shutil
from Crypto.Hash import SHA256

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

    print("Key length:", len(key))

    decrypted_folder_path = original_folder_path
    os.makedirs(decrypted_folder_path, exist_ok=True)

    print("Encrypted folder path:", encrypted_folder_path)

    files = os.listdir(encrypted_folder_path)
    print("Files to decrypt:", files)
    total_files = len(files)
    print("Decryption nonces:", decryption_nonces)

    for file in files:
        if file.endswith(".enc"):
            file_path = os.path.join(encrypted_folder_path, file)
            decrypted_file_path = os.path.join(decrypted_folder_path, file[:-4])

            print("Decrypting file:", file_path)
            print("Decrypted file path:", decrypted_file_path)

            with open(file_path, "rb") as f:
                ciphertext = f.read()

            file_bytes = file.encode('utf-8')
            nonce = None

            for key, value in decryption_nonces.items():
                if key.encode('utf-8')[:len(file_bytes)] == file_bytes:
                    nonce = value
                    break

            file_without_extension = os.path.splitext(file)[0]
            nonce = decryption_nonces.get(file_without_extension)

            if nonce is None:
                print("Decryption failed due to missing nonce:", file)
                continue

            tag = ciphertext[:16]
            ciphertext = ciphertext[16:]
            print("Key length:", len(key))
            key_length = len(key)
            key = get_key(password, key_length // 8)
            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)

            try:
                plaintext = cipher.decrypt_and_verify(ciphertext, tag)
                plaintext = unpad(plaintext, AES.block_size)
                print("File decrypted:", decrypted_file_path)
                successful_decryptions += 1

                with open(decrypted_file_path, "wb") as f:
                    f.write(plaintext)
                    print("Decrypted file written:", decrypted_file_path)

                    print("Does the decrypted file exist after writing? ", os.path.exists(decrypted_file_path))

                print("Does the decrypted file exist after closing? ", os.path.exists(decrypted_file_path))

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

    print("Decryption completed with", successful_decryptions, "successful decryptions out of", total_files)
    return decrypted_folder_path, password

def get_key(password, key_length):
    """
    Generate a key from the given password and key length.
    """
    # The key length for AES must be either 16, 24, or 32 bytes.
    if key_length not in [128, 192, 256]:
        raise ValueError("Invalid AES key length: " + str(key_length))

    # Use SHA256 hash to generate a key from the password.
    password_hash = SHA256.new(password.encode()).digest()

    # Truncate or pad the password hash to get a valid AES key.
    if key_length == 128:
        return password_hash[:16]  # Truncate to 16 bytes (128 bits).
    elif key_length == 192:
        return password_hash[:24]  # Truncate to 24 bytes (192 bits).
    else:  # key_length == 256
        # Pad to 32 bytes (256 bits).
        # The padding is done by repeating the hash until it reaches the desired length.
        return (password_hash * 2)[:32]

