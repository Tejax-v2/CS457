import os
import base64
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

# Generate key from password
def generate_key(password):
    return hashlib.sha256(password.encode()).digest()

def encrypt_file(file_path, password, isFile = True):

    key = generate_key(password)
    cipher = AES.new(key, AES.MODE_CBC)
    
    if isFile:    
        with open(file_path, 'rb') as file:
            plaintext = file.read() 
    else:
        plaintext = file_path
    
    # Pad the plaintext to be a multiple of the block size
    padded_data = pad(plaintext, AES.block_size)
    
    # Encrypt the data
    ciphertext = cipher.encrypt(padded_data)
    
    if isFile:
        # Write the IV and ciphertext to a new file
        with open(file_path + '.enc', 'wb') as enc_file:
            enc_file.write(cipher.iv + ciphertext)
    else:
        return cipher.iv + ciphertext

def decrypt_file(enc_file_path, password, isFile=True):

    key = generate_key(password)

    if isFile:
        with open(enc_file_path, 'rb') as enc_file:
            iv = enc_file.read(16)  # Read the IV (first 16 bytes)
            ciphertext = enc_file.read()  # Read the rest of the file
    else:
        iv = enc_file_path[:16]
        ciphertext = enc_file_path[16:]
    
    cipher = AES.new(key, AES.MODE_CBC, iv)
    
    # Decrypt and unpad the data
    padded_plaintext = cipher.decrypt(ciphertext)
    
    try:
        plaintext = unpad(padded_plaintext, AES.block_size)

        if isFile:
            # Write the decrypted data back to a new file
            with open(enc_file_path[:-4], 'wb') as dec_file:  # Remove '.enc' extension
                dec_file.write(plaintext)
        else:
            return plaintext
            
    except ValueError as e:
        print("Incorrect decryption:", e)

# Example usage
if __name__ == "__main__":

    choice = input("Select an operation: 1. Encrypt, 2. Decrypt, 3. Quit\n")

    if choice == '1':
        file_path = input("Enter file path: ")
        password = input("Enter password: ")
        try:
            encrypt_file(file_path, password)
            print("File encrypted successfully.")
        except:
            print("Error: File not found or invalid password")
    
    elif choice == '2':
        file_path = input("Enter encrypted file path: ")
        password = input("Enter password: ")
        try:
            decrypt_file(file_path, password)
            print("File decrypted successfully.")
        except:
            print("Error: Invalid password or file not found")
    
    elif choice == '3':
        print("Goodbye!")
        exit(0)
    
    else:
        print("Invalid choice. Terminating...")
        exit(0)
