import hashlib

# Input data
data_to_hash = b"Hello, SHA-512!"

# Creating a SHA-512 hash object

def get_hash_value(data_to_hash):
    hash_object = hashlib.sha512()
    # Updating the hash object with input data
    hash_object.update(data_to_hash)
    # Getting the hexadecimal representation of the hash
    hash_result = hash_object.hexdigest()
    return hash_result

print("SHA-512 Hash:", get_hash_value(data_to_hash))

