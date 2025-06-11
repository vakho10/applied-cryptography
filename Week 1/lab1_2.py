# Step 1: Caesar Cipher Challenge
# Ciphertext: mznxpz
# Challenge: Perform a brute-force or frequency analysis attack to decrypt the Caesar-encrypted text.
# Clue: The ciphertext is an encrypted anagram of the passphrase.
from itertools import cycle

import caesar

if __name__ == "__main__":
    textToAnalyze = "mznxpz"
    for i in range(1, 26 + 1):
        decryptedText = caesar.caesar_cipher_encrypt(textToAnalyze, -i)
        print(f"Shift: {i}, Decrypted Text: {decryptedText}")
    print("Done.")

    # Found -> "Shift: 21, Decrypted Text: rescue"

    # Step 2: Solve the Anagram
    # Decrypted Text: Rearrange the decrypted words to form the original passphrase.
    # Hint: The final passphrase is a fundamental concept in cryptography.

    # Anagrams of "rescue" (5 letter words) are: cereus, ceruse, recuse, rescue and secure.
    # "Secure" is the only anagram of "rescue" that makes sense and is "a fundamental concept in cryptography".

    # Step 3: XOR Decryption
    # Given Ciphertext in base64: Jw0KBlIMAEUXHRdFKyoxVRENEgkPEBwCFkQ=
    # Instructions:
    # 1. Use the recovered passphrase from Step 2 to XOR-decrypt the message
    # (first you must convert base64 then decrypt).

    import base64

    cipherText = "Jw0KBlIMAEUXHRdFKyoxVRENEgkPEBwCFkQ=";
    cipherTextBytes = base64.b64decode(cipherText)

    def xor_crypt_string(data, key='oh my god!'):
        # In Python 3, zip is already an iterator, no need for izip
        # Also, we need to handle bytes properly
        xored = bytes(a ^ b for a, b in zip(data, cycle(key.encode())))
        return xored

    result = xor_crypt_string(data=cipherTextBytes, key="secure")
    print(f"Result = '{result}'")
    # Result = 'b'This is the XOR challenge!''
