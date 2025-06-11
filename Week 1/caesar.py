

def caesar_cipher_encrypt(text, shift):
    result = ""
    for i in range(len(text)):
        char = text[i]
        if char.isspace():
            result += char
            continue
        if char.isupper():
            result += chr((ord(char) + shift - 65) % 26 + 65)
        else:
            result += chr((ord(char) + shift - 97) % 26 + 97)
    return result

def caesar_cipher_decrypt(text, shift):
    return caesar_cipher_encrypt(text, -shift)

if __name__ == "__main__":
    text = input("Enter the text to encrypt: ")
    shift = int(input("Enter the shift value: "))
    mode = input("Enter the mode (encrypt/decrypt): ")
    if mode == "encrypt":
        print("Encrypted text:", caesar_cipher_encrypt(text, shift))
    elif mode == "decrypt":
        print("Decrypted text:", caesar_cipher_decrypt(text, shift))
    else:
        print("Invalid mode. Please enter 'encrypt' or 'decrypt'.")