import json
import binascii
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
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

# Convert private key to PEM format
pem_private_key_alice = alice_private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
)

pem_private_key_bob = bob_private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
)
# Store the PEM private key in a dictionary
privateKeys = {"Alice": pem_private_key_alice.decode('utf-8'), "Bob": pem_private_key_bob.decode('utf-8')}


def write_to_file(filename, data):
    mode = 'wb' if isinstance(data, bytes) else 'w'
    with open(filename, mode) as file:
        file.write(data)


def load_private_keys(file_path):
    global privateKeys
    with open(file_path, 'r', encoding='utf-8') as file:
        private_keys_data = json.load(file)

    private_keys = {}
    for key_name, pem_data in private_keys_data.items():
        # Decode base64 and load the PEM data
        pem_bytes = pem_data.encode('utf-8')
        private_key = serialization.load_pem_private_key(
            pem_bytes,
            password=None,
            backend=default_backend()
        )
        private_keys[key_name] = private_key

    privateKeys = private_keys


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
    write_to_file(f"{person}_encrypted_text.txt", binascii.hexlify(cipher_text))


def decrypt_RSA(cipher_text, person):
    private_key = privateKeys.get(person)

    # Decrypt the message
    plain_text = private_key.decrypt(
        binascii.unhexlify(cipher_text),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Write decrypted text to file
    write_to_file(f"{person}_decrypted_text.txt", plain_text)


def sign_RSA(plain_text, person):
    print("Plain text: Sign RSA ", plain_text)
    print("Person: sign RSA ", person)
    private_key = privateKeys.get(person)
    print("Private key: Sign RSA ", private_key)

    # Sign the message
    signature = private_key.sign(
        plain_text.encode('utf-8'),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    print("Signature: Sign RSA ", signature)

    # Write signature to file
    write_to_file(f"{person}_signed_text.txt", binascii.hexlify(signature))


def verify_RSA(signature, message, person):
    public_key = privateKeys[person].public_key()

    try:
        # Verify the signature
        public_key.verify(
            binascii.unhexlify(signature),
            message.encode('utf-8'),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        write_to_file(f"{person}_verified_text.txt",
                      f"Verification successful." + "\n" + f"Message: \"{message}\" is authentic.")

    except Exception:
        write_to_file(f"{person}_verified_text.txt", f"Verification failed.")
