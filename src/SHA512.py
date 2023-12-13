import hashlib

# Input data
data_to_hash = b"Hello, SHA-512!"

# Creating a SHA-512 hash object
hash_object = hashlib.sha512()

# Updating the hash object with input data
hash_object.update(data_to_hash)

# Getting the hexadecimal representation of the hash
hash_result = hash_object.hexdigest()

print("SHA-512 Hash:", hash_result)

