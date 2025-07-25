# Task 2 Explanation

This system demonstrates a hybrid encryption protocol combining RSA and AES for secure file exchange
between participants: Alice and Bob.

## Encryption/Decryption Flow

1. **Key Generation (Bob)**
    - Bob generates an RSA key pair (2048-bit)
    - Public key saved as `public.pem`
    - Private key saved as `private.pem`

2. **Message Preparation (Alice)**
    - Alice creates a plaintext message in `alice_message.txt`
    - Generates random AES-256 key (32 bytes) and IV (16 bytes)

3. **File Encryption (Alice)**
    - Encrypts `alice_message.txt` using AES-256-CBC
        - Uses generated key and IV
        - Output saved as `encrypted_file.bin` (IV prepended to ciphertext)
    - Encrypts AES key with Bob's public RSA key
        - Output saved as `aes_key_encrypted.bin`

4. **File Decryption (Bob)**
    - Decrypts AES key using his private RSA key
    - Uses decrypted AES key and IV to decrypt `encrypted_file.bin`
    - Saves decrypted message as `decrypted_message.txt`

5. **Integrity Verification**
    - SHA-256 hashes of original and decrypted files are compared
    - Matching hashes confirm successful decryption and data integrity

## RSA vs AES Comparison

| Characteristic  | RSA (Asymmetric)                          | AES (Symmetric)                           |
|-----------------|-------------------------------------------|-------------------------------------------|
| **Key Type**    | Public/Private key pair                   | Single shared key                         |
| **Speed**       | Slower (suitable for small data)          | Faster (optimized for bulk data)          |
| **Use Case**    | Key exchange, digital signatures          | Data encryption                           |
| **Key Size**    | Typically 2048-4096 bits                  | 128, 192, or 256 bits                     |
| **Security**    | Based on integer factorization            | Based on substitution-permutation network |
| **Performance** | ~1000x slower than AES for same data size | Optimized for hardware acceleration       |