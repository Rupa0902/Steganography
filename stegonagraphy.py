# Steganography with AES Encryption

# Steganography with AES Encryption

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from PIL import Image
import numpy as np
import base64
import os

# AES Encryption/Decryption Functions

def encrypt_message(message, key):
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(message.encode(), AES.block_size))
    return base64.b64encode(cipher.iv + ct_bytes).decode()

def decrypt_message(enc_message, key):
    enc = base64.b64decode(enc_message)
    iv = enc[:AES.block_size]
    ct = enc[AES.block_size:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ct), AES.block_size).decode()

# Convert data to binary and back

def to_bin(data):
    return ''.join([format(byte, '08b') for byte in data])

def from_bin(binary):
    byte_array = [binary[i:i+8] for i in range(0, len(binary), 8)]
    return bytes([int(b, 2) for b in byte_array])

# Embedding Function

def embed_message(img_path, message, key, output_path):
    img = Image.open(img_path)
    encoded = img.copy()
    message = encrypt_message(message, key)
    message_bin = to_bin(message.encode('utf-8')) + '1111111111111110'

    pixels = np.array(encoded)
    flat_pixels = pixels.flatten()

    for i in range(len(message_bin)):
        flat_pixels[i] = (flat_pixels[i] & ~1) | int(message_bin[i])

    new_pixels = flat_pixels.reshape(pixels.shape)
    new_img = Image.fromarray(new_pixels.astype('uint8'))
    new_img.save(output_path)
    print("Message embedded and image saved.")

# Extraction Function

def extract_message(stego_path, key):
    img = Image.open(stego_path)
    pixels = np.array(img).flatten()

    bits = []
    for byte in pixels:
        bits.append(str(byte & 1))
        if ''.join(bits[-16:]) == '1111111111111110':
            break

    binary_data = ''.join(bits[:-16])
    encrypted_bytes = from_bin(binary_data)
    decrypted = decrypt_message(encrypted_bytes.decode('utf-8'), key)
    print("Extracted Message:", decrypted)

# Example Usage
if __name__ == '__main__':
    key = get_random_bytes(16)  # AES requires 16-byte key
    embed_message('stegoimage.png', 'Secret Message Here', key, 'stegoimage.png')
    extract_message('stegoimage.png', key)
