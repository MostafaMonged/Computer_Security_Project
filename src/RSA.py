from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding


def sign_with_certificate(plain_text, private_key_path, certificate_path):
    # Load private key
    with open(private_key_path, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
        )

    # Load certificate
    with open(certificate_path, "rb") as cert_file:
        certificate = cert_file.read()

    # Sign the plain text
    signature = private_key.sign(
        plain_text.encode('utf-8') + certificate,
        padding.PKCS1v15(),
        hashes.SHA256()
    )

    return signature
