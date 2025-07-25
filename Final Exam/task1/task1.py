# Task 1: Encrypted Messaging App Prototype (8 pts)

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes


def generate_rsa_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key


def encrypt_message_aes(message, aes_key=None):
    if aes_key is None:
        aes_key = get_random_bytes(32)  # 256-bit key

    cipher = AES.new(aes_key, AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad_message(message))
    return aes_key, cipher.iv, ciphertext


def encrypt_aes_key_with_rsa(aes_key, public_key):
    rsa_key = RSA.import_key(public_key)
    cipher_rsa = PKCS1_OAEP.new(rsa_key)
    enc_aes_key = cipher_rsa.encrypt(aes_key)
    return enc_aes_key


def decrypt_aes_key_with_rsa(enc_aes_key, private_key):
    rsa_key = RSA.import_key(private_key)
    cipher_rsa = PKCS1_OAEP.new(rsa_key)
    aes_key = cipher_rsa.decrypt(enc_aes_key)
    return aes_key


def decrypt_message_aes(ciphertext, iv, aes_key):
    cipher = AES.new(aes_key, AES.MODE_CBC, iv=iv)
    plaintext = unpad_message(cipher.decrypt(ciphertext))
    return plaintext


def pad_message(message):
    pad_length = 16 - (len(message) % 16)
    return message + bytes([pad_length] * pad_length)


def unpad_message(message):
    pad_length = message[-1]
    return message[:-pad_length]


def save_to_file(filename, data):
    with open(filename, 'wb') as f:
        f.write(data)


def read_from_file(filename):
    with open(filename, 'rb') as f:
        return f.read()


if __name__ == "__main__":
    # User A
    private_key, public_key = generate_rsa_keys()

    # User B
    message = b"Secret message to be encrypted with combined RSA+AES"
    save_to_file('message.txt', message)

    # Encrypt with AES
    aes_key, iv, ciphertext = encrypt_message_aes(message)
    save_to_file('encrypted_message.bin', iv + ciphertext)  # Store IV with ciphertext

    # Encrypt the AES key with RSA
    enc_aes_key = encrypt_aes_key_with_rsa(aes_key, public_key)
    save_to_file('aes_key_encrypted.bin', enc_aes_key)

    # User A decrypts
    # Load encrypted files
    enc_data = read_from_file('encrypted_message.bin')
    iv = enc_data[:16]  # The first 16 bytes are IV
    ciphertext = enc_data[16:]
    enc_aes_key = read_from_file('aes_key_encrypted.bin')

    # Decrypt the AES key with the RSA private key
    dec_aes_key = decrypt_aes_key_with_rsa(enc_aes_key, private_key)

    # Decrypt message with AES
    decrypted_message = decrypt_message_aes(ciphertext, iv, dec_aes_key)
    save_to_file('decrypted_message.txt', decrypted_message)

    print("Original plaintext:", message.decode())
    print("Decrypted plaintext:", decrypted_message.decode())