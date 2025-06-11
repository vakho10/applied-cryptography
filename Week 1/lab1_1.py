# Task: decrypt given cyphertext: “Hvs Eiwqy Pfckb Tcl Xiadg Cjsf Hvs Zonm Rcu.”
# Challenge: Perform Frequency Analysis or brute-force attack to decrypt a ciphertext.
# Provide python code solution with GitHub.

import caesar

if __name__ == "__main__":
    textToAnalyze = 'Hvs Eiwqy Pfckb Tcl Xiadg Cjsf Hvs Zonm Rcu'
    for i in range(1, 26 + 1):
        decryptedText = caesar.caesar_cipher_encrypt(textToAnalyze, -i)
        print(f"Shift: {i}, Decrypted Text: {decryptedText}")
    print("Done.")

# Found -> "Shift: 14, Decrypted Text: The Quick Brown Fox Jumps Over The Lazy Dog"

# (1) Why is Caesar cipher insecure?
# Caesar's cipher is easy to brute-force because it uses a fixed shift value for each character. The number of possible
# shifts is basically 26 (the number of alphabet characters).
# This means that if we know the shift value, we can easily decrypt the message.

# (2) Where might legacy systems still use similar encryption?
# People may still use this cipher in some legacy systems or in places where basic character encryption is required
# as an intermediate process before more complex encryption is used. It may be used in obfuscating some data also.
