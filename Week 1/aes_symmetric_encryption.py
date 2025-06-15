import os

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def encrypt_message(key, plainText):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plainText.encode('utf-8')) + encryptor.finalize()
    return iv + ciphertext

def decrypt_message(key, ciphertext):
    iv = ciphertext[:16]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    plainText = decryptor.update(ciphertext[16:]) + decryptor.finalize()
    return plainText.decode('utf-8')

if __name__ == "__main__":
    key = os.urandom(32)
    message = "This is a secret message"

    encrypted = encrypt_message(key, message)
    print(f"Plaintext = {message}")
    print(f"Ciphertext = {encrypted}")

    decrypted = decrypt_message(key, encrypted)
    print(f"Decrypted = {decrypted}")
