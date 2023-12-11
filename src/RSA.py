from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa

# Generate RSA key pairs for Alice and Bob
alice_private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)

bob_private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)

privateKeys = {"Alice": alice_private_key, "Bob": bob_private_key}


def sign_RSA(plain_text, person):
    private_key = privateKeys.get(person)
    if private_key is None:
        raise ValueError(f"No private key found for {person}")

    # Sign the message
    signature = private_key.sign(
        plain_text.encode('utf-8'),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    # Write signature to file
    write_to_file(f"{person}_signed_text.txt", signature)

    return signature


def encrypt_RSA(plain_text, person):
    public_key = privateKeys[person].public_key()

    # Encrypt the message
    cipher_text = public_key.encrypt(
        plain_text.encode('utf-8'),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Write cipher text to file
    write_to_file(f"{person}_encrypted_text.txt", cipher_text)

    return cipher_text


def write_to_file(filename, data):
    mode = 'wb' if isinstance(data, bytes) else 'w'
    with open(filename, mode) as file:
        file.write(data)


def decrypt_RSA(cipher_text, person):
    private_key = privateKeys.get(person)
    if private_key is None:
        raise ValueError(f"No private key found for {person}")

    # Decrypt the message
    plain_text = private_key.decrypt(
        cipher_text,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Write decrypted text to file
    write_to_file(f"{person}_decrypted_text.txt", plain_text)


def verify_RSA(signature, message, person):
    public_key = privateKeys[person].public_key()

    try:
        # Verify the signature
        public_key.verify(
            signature,
            message.encode('utf-8'),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        write_to_file(f"{person}_verified_text.txt",
                      f"Verification successful." + "\n" + f"Message: \"{message}\" is authentic.")

    except Exception as e:
        write_to_file(f"{person}_verified_text.txt", f"{person} - Verification failed. {e}")
