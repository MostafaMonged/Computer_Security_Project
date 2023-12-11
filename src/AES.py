from OpenSSL import crypto
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import secrets
import binascii

##########ECB mode##########
def encrypt_file_ECB(input_file, output_file, key):
    cipher = AES.new(key, AES.MODE_ECB)
    data = b''
    with open(input_file, 'rb') as file_in:
        data = file_in.read()
    data = pad(data, AES.block_size)
    encrypted_data = cipher.encrypt(data)
    with open(output_file, 'wb') as file_out:
        file_out.write(binascii.hexlify(encrypted_data))


def decrypt_file_ECB(input_file, output_file, key):
    cipher = AES.new(key, AES.MODE_ECB)
    data = b''
    with open(input_file, 'rb') as file_in:
        data = binascii.unhexlify(file_in.read())
    decrypted_data = unpad(cipher.decrypt(data), AES.block_size)
    with open(output_file, 'wb') as file_out:
        file_out.write(decrypted_data)

##########CBC mode##########
def encrypt_file_CBC(input_file, output_file, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    data = b''
    with open(input_file, 'rb') as file_in:
        data = file_in.read()
    data = pad(data, AES.block_size)
    encrypted_data = cipher.encrypt(data)
    with open(output_file, 'wb') as file_out:
        file_out.write(binascii.hexlify(iv + encrypted_data))

def decrypt_file_CBC(input_file, output_file, key):
    with open(input_file, 'rb') as file_in:
        data = binascii.unhexlify(file_in.read())
    iv = data[:16]
    encrypted_data = data[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)
    with open(output_file, 'wb') as file_out:
        file_out.write(decrypted_data)


# Usage example this is hardcodeded for testing purposes
# will be changed when using GUI
input_file = "D:\Mostafa\Senior-2\First term\Computer Security\project\Computer_Security\\testcases\\testcase1\input.txt"
encrypted_file = "D:\Mostafa\Senior-2\First term\Computer Security\project\Computer_Security\\testcases\\testcase1\encrypted.txt"
decrypted_file = "D:\Mostafa\Senior-2\First term\Computer Security\project\Computer_Security\\testcases\\testcase1\decrypted.txt"

key = b'1234123412341234'
iv = b'abcdefghijklmnop'

encrypt_file_CBC(input_file, encrypted_file, key, iv)
decrypt_file_CBC(encrypted_file, decrypted_file, key)

