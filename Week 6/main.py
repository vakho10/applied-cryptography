from binascii import unhexlify

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

BLOCK_SIZE = 16  # AES block size is 16 bytes
KEY = b"this_is_16_bytes"

# Ciphertext = IV + encrypted blocks (from check_decrypt.py success)
CIPHERTEXT_HEX = (
    "746869735f69735f31365f6279746573"
    "9404628dcdf3f003482b3b0648bd920b"
    "3f60e13e89fa6950d3340adbbbb41c12"
    "b3d1d97ef97860e9df7ec0d31d13839a"
    "e17b3be8f69921a07627021af16430e1"
)


def padding_oracle(ciphertext: bytes) -> bool:
    """Returns True if the ciphertext decrypts with valid padding, False otherwise."""

    if len(ciphertext) % BLOCK_SIZE != 0:
        return False
    try:
        iv = ciphertext[:BLOCK_SIZE]
        ct = ciphertext[BLOCK_SIZE:]
        cipher = Cipher(algorithms.AES(KEY), modes.CBC(iv))
        decryptor = cipher.decryptor()
        decrypted = decryptor.update(ct) + decryptor.finalize()
        unpadder = padding.PKCS7(BLOCK_SIZE * 8).unpadder()
        unpadder.update(decrypted)
        unpadder.finalize()
        return True
    except (ValueError, TypeError):
        return False


# Task 1: Understand the Components

# 1. Analyze the padding_oracle function.
# How does it determine if padding is valid?
# Answer:
# The function determines padding validity by checking whether the decrypted
# plaintext can be successfully unpadded with PKCS#7 rules.

# 2. What is the purpose of the IV in CBC mode?
# Answer:
# IV is an initialization vector and its purpose is to do XOR operation
# with the first plaintext block before encryption. This means that even if the same text is encrypted
# many times with the same key, we'll get different results.

# 3. Why does the ciphertext need to be a multiple of the block size?
# Answer:
# Because the CBC decryption requires block-aligned input. If the size is different, it cannot be processed correctly.

# Task 2
def split_blocks(data: bytes, block_size: int = BLOCK_SIZE) -> list[bytes]:
    """Split the input data into blocks of fixed size."""
    blocks = []
    for start in range(0, len(data), block_size):
        end = start + block_size
        block = data[start:end]
        blocks.append(block)
    return blocks


# Task 3
def decrypt_block(prev_block: bytes, target_block: bytes) -> bytes:
    """
    Decrypt a single block using the padding oracle attack. Returns the decrypted plaintext block.
    """
    block_size = len(prev_block)
    intermediate = bytearray(block_size)
    recovered = bytearray(block_size)

    for padding_value in range(1, block_size + 1):
        for guess in range(256):
            fake_block = bytearray(block_size)

            for i in range(1, padding_value):
                fake_block[-i] = intermediate[-i] ^ padding_value

            fake_block[-padding_value] = guess
            test_cipher = bytes(fake_block) + target_block

            if padding_oracle(test_cipher):
                intermediate_byte = guess ^ padding_value
                intermediate[-padding_value] = intermediate_byte

                recovered_byte = intermediate_byte ^ prev_block[-padding_value]
                recovered[-padding_value] = recovered_byte
                break
    return bytes(recovered)


# Task 4
def padding_oracle_attack(ciphertext: bytes) -> bytes:
    """Perform the padding oracle attack on the entire ciphertext."""
    blocks = split_blocks(ciphertext, BLOCK_SIZE)
    recovered_plaintext = b""

    for i in range(1, len(blocks)):
        prev_block = blocks[i - 1]
        curr_block = blocks[i]
        print(f"[*] Decrypting block {i}/{len(blocks) - 1}...")
        decrypted_block = decrypt_block(prev_block, curr_block)
        recovered_plaintext += decrypted_block

    return recovered_plaintext


# Task 5
def unpad_and_decode(plaintext: bytes) -> str:
    """Attempt to unpad and decode the plaintext."""
    try:
        unpadder = padding.PKCS7(BLOCK_SIZE * 8).unpadder()
        unpadded = unpadder.update(plaintext) + unpadder.finalize()
        return unpadded.decode('utf-8')
    except (ValueError, UnicodeDecodeError) as e:
        return f"[!] Failed to decode plaintext: {e}"


if __name__ == "__main__":
    try:
        ciphertext = unhexlify(CIPHERTEXT_HEX)
        print(f"[*] Ciphertext length: {len(ciphertext)} bytes")
        print(f"[*] IV: {ciphertext[:BLOCK_SIZE].hex()}")

        recovered = padding_oracle_attack(ciphertext)

        print("\n[+] Decryption complete!")
        print(f" Recovered plaintext (raw bytes): {recovered}")
        print(f" Hex: {recovered.hex()}")

        decoded = unpad_and_decode(recovered)
        print("\n Final plaintext:")
        print(decoded)
    except Exception as e:
        print(f"\n Error occurred: {e}")

# RESULT: "This is a top secret message. Decrypt me if you can!"