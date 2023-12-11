from src.RSA import *

if __name__ == "__main__":
    # Example usage
    message = "Hello, cryptography!"

    # Signing and verifying
    sign_RSA(message, "Alice")
    with open("Alice_signed_text.txt", "rb") as file:
        signature = file.read()
    verify_RSA(signature, message, "Alice")

    # Encryption and decryption
    encrypt_RSA(message, "Bob")
    with open("Bob_encrypted_text.txt", "rb") as file:
        encrypted = file.read()
    decrypted_text = decrypt_RSA(encrypted, "Bob")
