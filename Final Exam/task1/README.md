# Task 1 Explanation

This system combines RSA and AES encryption to securely transmit messages between two users.

## Encryption Flow

1. **Key Generation (User A)**
   - User A generates an RSA key pair (public and private keys)
   - User A shares their public key with User B

2. **Message Encryption (User B)**
   - User B writes a secret message (`message.txt`)
   - The system generates a random AES-256 key
   - The message is encrypted with AES-256 in CBC mode:
     - A random Initialization Vector (IV) is generated
     - The message is padded to match AES block size
     - Encryption produces ciphertext
     - The IV and ciphertext are saved together (`encrypted_message.bin`)
   - The AES key is encrypted with User A's public RSA key (`aes_key_encrypted.bin`)

3. **Message Decryption (User A)**
   - User A receives both encrypted files
   - The AES key is decrypted using User A's private RSA key
   - The message is decrypted using the AES key and IV
   - The decrypted message is saved (`decrypted_message.txt`)

## Files

- `message.txt`: Original plaintext message
- `encrypted_message.bin`: Encrypted message (AES-256) with IV prepended
- `aes_key_encrypted.bin`: AES key encrypted with RSA public key
- `decrypted_message.txt`: Decrypted plaintext message (should match original)