from Crypto.Cipher import AES
import os

def encrypt_file(file_path, key):
    cipher = AES.new(key, AES.MODE_EAX)
    
    with open(file_path, 'rb') as f:
        data = f.read()
    
    ciphertext, tag = cipher.encrypt_and_digest(data)

    # Save encrypted file in the same directory as original
    encrypted_file_path = file_path + ".enc"
    
    with open(encrypted_file_path, 'wb') as ef:
        ef.write(cipher.nonce + tag + ciphertext)
    
    # Remove the original file after encryption
    os.remove(file_path)
    
    return encrypted_file_path  # Return encrypted file path

def decrypt_file(encrypted_file_path, key):
    if not os.path.exists(encrypted_file_path):
        raise FileNotFoundError(f"Error: Encrypted file not found at {encrypted_file_path}")

    with open(encrypted_file_path, 'rb') as ef:
        nonce = ef.read(16)  # Read first 16 bytes (nonce)
        tag = ef.read(16)    # Read next 16 bytes (tag)
        ciphertext = ef.read()  # Read remaining bytes (actual encrypted data)

    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    
    try:
        data = cipher.decrypt_and_verify(ciphertext, tag)

        # Ensure TEMP_FOLDER exists
        temp_folder = "temp"
        if not os.path.exists(temp_folder):
            os.makedirs(temp_folder)

        # Save the decrypted file in the TEMP folder
        original_filename = os.path.basename(encrypted_file_path).replace(".enc", "")
        decrypted_file_path = os.path.join(temp_folder, original_filename)

        # Debugging: Print paths
        print(f"Saving decrypted file to: {decrypted_file_path}")

        with open(decrypted_file_path, 'wb') as of:
            of.write(data)

        return decrypted_file_path  # Return the correct path
    except ValueError:
        raise ValueError("Decryption failed. Invalid key or data corrupted.")
