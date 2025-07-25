# Task 2: Secure File Exchange Using RSA + AES (8 pts)

import hashlib

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad


def generate_rsa_keypair():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()

    # Save to files
    with open('private.pem', 'wb') as f:
        f.write(private_key)
    with open('public.pem', 'wb') as f:
        f.write(public_key)

    return private_key, public_key


def generate_aes_key():
    return get_random_bytes(32), get_random_bytes(16)  # 256-bit key, 128-bit IV


def encrypt_file_aes(input_file, output_file, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)

    with open(input_file, 'rb') as f_in:
        plaintext = f_in.read()

    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))

    with open(output_file, 'wb') as f_out:
        f_out.write(iv + ciphertext)  # Prepend IV to ciphertext


def encrypt_aes_key(key, public_key):
    rsa_key = RSA.import_key(public_key)
    cipher_rsa = PKCS1_OAEP.new(rsa_key)
    return cipher_rsa.encrypt(key)


def decrypt_aes_key(encrypted_key, private_key):
    rsa_key = RSA.import_key(private_key)
    cipher_rsa = PKCS1_OAEP.new(rsa_key)
    return cipher_rsa.decrypt(encrypted_key)


def decrypt_file_aes(input_file, output_file, key):
    with open(input_file, 'rb') as f_in:
        data = f_in.read()

    iv = data[:16]  # Extract IV from the beginning
    ciphertext = data[16:]

    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)

    with open(output_file, 'wb') as f_out:
        f_out.write(plaintext)


def calculate_file_hash(filename):
    sha256 = hashlib.sha256()
    with open(filename, 'rb') as f:
        while chunk := f.read(4096):
            sha256.update(chunk)
    return sha256.hexdigest()


if __name__ == "__main__":
    # Step 1: Bob generates the RSA key pair
    private_key, public_key = generate_rsa_keypair()

    # Step 2: Alice creates a plaintext message
    alice_message = b"This is Alice's secret message for Bob, secured with hybrid encryption."
    with open('alice_message.txt', 'wb') as f:
        f.write(alice_message)

    # Step 3: Alice generates the AES key and IV
    aes_key, iv = generate_aes_key()

    # Step 4: Encrypt the file with AES
    encrypt_file_aes('alice_message.txt', 'encrypted_file.bin', aes_key, iv)

    # Step 5: Encrypt the AES key with Bob's public key
    encrypted_aes_key = encrypt_aes_key(aes_key, public_key)
    with open('aes_key_encrypted.bin', 'wb') as f:
        f.write(encrypted_aes_key)

    # Bob's decryption process
    # Step 6: Decrypt the AES key with the private key
    with open('aes_key_encrypted.bin', 'rb') as f:
        encrypted_key = f.read()
    decrypted_aes_key = decrypt_aes_key(encrypted_key, private_key)

    # Step 7: Decrypt the file with the AES key
    decrypt_file_aes('encrypted_file.bin', 'decrypted_message.txt', decrypted_aes_key)

    # Step 8: Verify integrity with SHA-256
    original_hash = calculate_file_hash('alice_message.txt')
    decrypted_hash = calculate_file_hash('decrypted_message.txt')

    print("Original file SHA-256:", original_hash)
    print("Decrypted file SHA-256:", decrypted_hash)
    print("Integrity verified:", original_hash == decrypted_hash)
