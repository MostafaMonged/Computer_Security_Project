from OpenSSL import crypto
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import secrets
import binascii



def encrypt_file(input_file, output_file, key):
    cipher = AES.new(key, AES.MODE_ECB)
    data = ""
    with open(input_file, 'rb') as file_in:
        data = file_in.read()
    data = pad(data, AES.block_size)
    encrypted_data = cipher.encrypt(data)
    with open(output_file, 'wb') as file_out:
        file_out.write(binascii.hexlify(encrypted_data))


def decrypt_file(input_file, output_file, key):
    cipher = AES.new(key, AES.MODE_ECB)
    data = b''
    with open(input_file, 'rb') as file_in:
        data = binascii.unhexlify(file_in.read())
    decrypted_data = unpad(cipher.decrypt(data), AES.block_size)
    with open(output_file, 'wb') as file_out:
        file_out.write(decrypted_data)


# Usage example this is hardcodeded for testing purposes
# will be changed when using GUI
input_file = "D:\Mostafa\Senior-2\First term\Computer Security\project\Computer_Security\\testcases\\testcase1\input.txt"
encrypted_file = "D:\Mostafa\Senior-2\First term\Computer Security\project\Computer_Security\\testcases\\testcase1\encrypted.txt"
decrypted_file = "D:\Mostafa\Senior-2\First term\Computer Security\project\Computer_Security\\testcases\\testcase1\decrypted.txt"

key = b'1234123421341234'

encrypt_file(input_file, encrypted_file, key)
decrypt_file(encrypted_file, decrypted_file, key)

