from OpenSSL import crypto
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import secrets
import binascii



def encrypt_file(input_file, output_file, key):
    cipher = AES.new(key, AES.MODE_ECB)
    with open(input_file, 'rb') as file_in:
        with open(output_file, 'wb') as file_out:
            while True:
                chunk = file_in.read(16)
                if len(chunk) == 0:
                    break
                elif len(chunk) % 16 != 0:
                    chunk = pad(chunk, AES.block_size)
                encrypted_chunk = cipher.encrypt(chunk)
                hex_data = binascii.hexlify(encrypted_chunk)
                file_out.write(hex_data)

def decrypt_file(input_file, output_file, key):
    cipher = AES.new(key, AES.MODE_ECB)
    with open(input_file, 'rb') as file_in:
        with open(output_file, 'wb') as file_out:
            while True:
                chunk = file_in.read(32)
                if len(chunk) == 0:
                    break
                binary_data = binascii.unhexlify(chunk)
                decrypted_chunk = cipher.decrypt(binary_data)
                """
                checks if there are no more bytes left to read in the file. If this is true, 
                then the current chunk is the last chunk of the file 
                """
                if file_in.peek() == b'':
                    try:
                        decrypted_chunk = unpad(decrypted_chunk, AES.block_size)
                    except ValueError:
                        # Padding is incorrect, assume data was not padded
                        pass
                file_out.write(decrypted_chunk)

# Usage example this is hardcodeded for testing purposes
# will be changed when using GUI
input_file = "D:\Mostafa\Senior-2\First term\Computer Security\project\Computer_Security\\testcases\\testcase1\input.txt"
encrypted_file = "D:\Mostafa\Senior-2\First term\Computer Security\project\Computer_Security\\testcases\\testcase1\encrypted.txt"
decrypted_file = "D:\Mostafa\Senior-2\First term\Computer Security\project\Computer_Security\\testcases\\testcase1\decrypted.txt"

key = b'1234123421341234'

encrypt_file(input_file, encrypted_file, key)
decrypt_file(encrypted_file, decrypted_file, key)

