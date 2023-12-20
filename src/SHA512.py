import hashlib


def hash_SHA512(data):
    data = data.encode('utf-8')
    # Creating a SHA-512 hash object
    hash_object = hashlib.sha512()

    # Updating the hash object with input data
    hash_object.update(data)

    # Getting the hexadecimal representation of the hash
    hash_result = hash_object.hexdigest()

    return hash_result
