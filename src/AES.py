from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import binascii


# ==========ECB mode===========
def encrypt_file_ECB(input_file, output_file, key):
    byte_array = binascii.unhexlify(key)
    cipher = AES.new(byte_array, AES.MODE_ECB)
    data = b''
    with open(input_file, 'rb') as file_in:
        data = file_in.read()
    data = pad(data, AES.block_size)
    encrypted_data = cipher.encrypt(data)
    with open(output_file, 'wb') as file_out:
        file_out.write(binascii.hexlify(encrypted_data))


def decrypt_file_ECB(input_file, output_file, key):
    byte_array = binascii.unhexlify(key)
    cipher = AES.new(byte_array, AES.MODE_ECB)
    data = b''
    with open(input_file, 'rb') as file_in:
        data = binascii.unhexlify(file_in.read())
    decrypted_data = unpad(cipher.decrypt(data), AES.block_size)
    with open(output_file, 'wb') as file_out:
        file_out.write(decrypted_data)


# =========CBC mode==========
# iv = b'abcdefghijklmnop'


def encrypt_file_CBC(input_file, output_file, key, iv):
    byte_array = binascii.unhexlify(key)
    cipher = AES.new(byte_array, AES.MODE_CBC, iv)
    data = b''
    with open(input_file, 'rb') as file_in:
        data = file_in.read()
    data = pad(data, AES.block_size)
    encrypted_data = cipher.encrypt(data)
    with open(output_file, 'wb') as file_out:
        file_out.write(binascii.hexlify(iv + encrypted_data))


def decrypt_file_CBC(input_file, output_file, key):
    byte_array = binascii.unhexlify(key)
    with open(input_file, 'rb') as file_in:
        data = binascii.unhexlify(file_in.read())
    iv = data[:16]
    encrypted_data = data[16:]
    cipher = AES.new(byte_array, AES.MODE_CBC, iv)
    decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)
    with open(output_file, 'wb') as file_out:
        file_out.write(decrypted_data)

# Usage example this is hard coded for testing purposes
# will be changed when using GUI
# input_file = "O:\ASU\Repositories\Computer_Security_Project\src\MSG.txt"
# encrypted_file = "O:\ASU\Repositories\Computer_Security_Project\src\encrypted.txt"
# decrypted_file = "O:\ASU\Repositories\Computer_Security_Project\src\decrypted.txt"
#
# key = '12345678123456781234567812345678'
#
# encrypt_file_ECB(input_file, encrypted_file, key)
# decrypt_file_ECB(encrypted_file, decrypted_file, key)
