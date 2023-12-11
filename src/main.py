from src.RSA import *

if __name__ == "__main__":
    # Example usage
    message = "Hello, cryptography!"

    # Signing and verifying
    signature = sign_RSA(message, "Alice")
    verify_RSA(signature, message, "Alice")

    # Encryption and decryption
    cipher_text = encrypt_RSA(message, "Bob")
    decrypted_text = decrypt_RSA(cipher_text, "Bob")
