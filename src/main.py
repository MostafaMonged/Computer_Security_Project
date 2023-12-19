import os
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QIcon
from PyQt5.QtWidgets import *
from PyQt5.QtWidgets import QWidget, QVBoxLayout, QLabel, QPushButton
from PyQt5.uic import loadUiType

from AES import *
# Load the .ui file and generate the corresponding class dynamically
from RSA import *

Ui_MainWindow, _ = loadUiType("./GUI.ui")
terminals = ["IDENTIFIER", "NUMBER", "OP"]


# noinspection PyPep8Naming
class MyGUI(QMainWindow, Ui_MainWindow):
    inputXData = ""
    outputXData = ""
    AES_current_file_path = None  # Attribute to store the path of the loaded or created file

    def __init__(self):

        super(MyGUI, self).__init__()

        # Set up the user interface
        self.setupUi(self)

        # Creating the main window
        self.setGeometry(100, 100, 920, 500)
        self.setWindowTitle("Security Application")

        # Center the main window on the screen
        screen = QDesktopWidget().screenGeometry()
        size = self.geometry()
        x = ((screen.width() - size.width()) // 2) - 50
        y = ((screen.height() - size.height()) // 2) - 50
        self.move(x, y)

        # Load icon from the file
        icon = QIcon("MainIcon.png")
        self.setWindowIcon(icon)

        # Load the css
        self.setStyleSheet(open("css.css").read())

        self.overlay = OverlayWidget()
        self.overlay.setGeometry(780, 500, 200, 200)
        self.overlay.hide()
        # Show the overlay when the GUI starts
        self.overlay.show()
        # ========================================================================================================================
        # Tab 1 Code
        self.last_signer = None
        self.last_encryption_mode = None

        # Connect buttons to functions directly
        self.LOAD_MSG_X.clicked.connect(self.load_msg_MAIN)
        self.Load_RSA_Key_E_X.clicked.connect(self.load_rsa_key_MAIN)
        self.Sign_Alice_RSA_X.clicked.connect(self.sign_with_alice_MAIN)
        self.Sign_Bob_RSA_X.clicked.connect(self.sign_with_bob_MAIN)

        self.ECB_AES_E_X.clicked.connect(self.ecb_aes_encryption_MAIN)
        self.ECB_AES_D_X.clicked.connect(self.ecb_aes_decryption_MAIN)
        self.CBC_AES_E_X.clicked.connect(self.cbc_aes_encryption_MAIN)
        self.CBC_AES_D_X.clicked.connect(self.cbc_aes_decryption_MAIN)

        self.Load_RSA_Key_D_X.clicked.connect(self.load_rsa_key_MAIN)
        self.AES_Key_In_X.textChanged.connect(self.aes_key_changed_MAIN)
        self.Input_X.textChanged.connect(self.input_message_changed_MAIN)
        self.Output_X.textChanged.connect(self.output_changed_MAIN)
        self.Verify_Alice_X.clicked.connect(self.verify_with_alice)
        self.Verfy_Bob_X.clicked.connect(self.verify_with_bob)
        self.Clear_All_X.clicked.connect(self.clear_all)
        # Define your functions here
        # ========================================================================================================================
        # Tab 2 Code
        # Connect buttons to functions directly
        self.Load_Msg_AES.clicked.connect(self.load_msg_AES)
        self.ECB_E_AES_AES.clicked.connect(self.ecb_aes_encryption_AES)
        self.ECB_D_AES_AES.clicked.connect(self.ecb_aes_decryption_AES)
        self.CBC_E_AES_AES.clicked.connect(self.cbc_aes_encryption_AES)
        self.CBC_D_AES_AES.clicked.connect(self.cbc_aes_decryption_AES)
        self.InKeyAES_AES.textChanged.connect(self.aes_key_changed_MAIN)
        self.InputMsg_AES.textChanged.connect(self.input_message_changed_AES)
        self.Output_AES.textChanged.connect(self.output_changed_AES)
        self.Clear_All_AES.clicked.connect(self.clear_all)

        # ========================================================================================================================
        # Tab 3 Code

    def load_msg_MAIN(self):

        options = QFileDialog.Options()
        file_name, _ = QFileDialog.getOpenFileName(
            self, "Open File", "", "Text Files (*.txt);;All Files (*)", options=options
        )

        if file_name:
            try:
                with open(file_name, "r", encoding='utf-8') as file:
                    self.Input_X.append(file.read())
                    self.Output_X.append("\nLoaded Message.")
            except Exception as e:
                print(f"Error loading file: {e}")

    def load_rsa_key_MAIN(self):
        # Check if any specified sentence is in Input_X
        self.Output_X.append("\nLoading RSA Key...")
        file_path = self.choose_file()
        # Check if a valid file path was selected
        if not file_path:
            self.Output_X.append("\nRSA key loading canceled.")
            return
        load_private_keys(file_path)
        try:
            with open('PKeys.txt', 'r'):
                self.Output_X.append("\nRSA Key Loaded.")

        except FileNotFoundError:
            self.Output_X.append("\nError: 'PKeys.txt' not found.")

    def choose_file(self):
        options = QFileDialog.Options()
        file_name, _ = QFileDialog.getOpenFileName(
            self, "Choose File", "", "All Files (*)", options=options
        )

        return file_name

    def sign_with_alice_MAIN(self):
        person = "Alice"
        plain_text = self.Input_X.toPlainText()
        if not plain_text.strip():  # Check if plain_text is empty or contains only whitespace
            # Show a message box to inform the user to enter or load a message
            msg_box = QMessageBox()
            msg_box.setIcon(QMessageBox.Warning)
            msg_box.setWindowTitle("Message Required")
            msg_box.setText("Please write or load a message before signing.")
            msg_box.setWindowIcon(QIcon("msgbox.png"))  # Set the window icon
            msg_box.exec_()
            return  # Exit the function if plain_text is empty
        self.Output_X.append("\nSigning with Alice...")
        sign_RSA(plain_text, person)
        self.Output_X.append("\nSigned with Alice.")
        self.Output_X.append("\nSigned Text generated named Alice_signed_text.txt")
        self.last_signer = "Alice"

    def verify_with_alice(self):
        if self.last_encryption_mode == "ECB":
            signature_file = "ECB_AES_Decrypted.txt"
        elif self.last_encryption_mode == "CBC":
            signature_file = "CBC_AES_Decrypted.txt"
        else:
            # Show an error message box
            msg_box = QMessageBox()
            msg_box.setIcon(QMessageBox.Warning)
            msg_box.setWindowTitle("Sign First")
            msg_box.setText("\nPlease Enc file with AES before Verifying.")
            msg_box.setWindowIcon(QIcon("msgbox.png"))  # Set the window icon
            msg_box.setStandardButtons(QMessageBox.Ok)
            msg_box.exec_()
            return

        if not os.path.exists(signature_file):
            # Show a message box to inform the user that the signature file is not found
            msg_box = QMessageBox()
            msg_box.setIcon(QMessageBox.Critical)
            msg_box.setWindowTitle("File Not Found")
            msg_box.setText(f"\nThe required signature file '{signature_file}' was not found in the current directory.")
            msg_box.setWindowIcon(QIcon("msgbox.png"))  # Set the window icon
            msg_box.setStandardButtons(QMessageBox.Ok)
            msg_box.exec_()
            return

        try:
            # Retrieve the message and signature
            message = self.Input_X.toPlainText()

            # Load the signature from the file
            with open(signature_file, 'rb') as file:
                signature = file.read()

            # Verify the signature
            verify_RSA(signature, message, 'Alice')

            # Read the first line from Alice_verified_text.txt
            with open('Alice_verified_text.txt', 'r') as verified_file:
                first_line = verified_file.readline().strip()
            self.Output_X.append(f"\nAlice's signature verification complete: {first_line}")
        except Exception as e:
            print(f"\nError in verifying with Alice: {e}")
            self.Output_X.append(f"\nError in verifying with Alice: {e}")

    def sign_with_bob_MAIN(self):
        person = "Bob"
        plain_text = self.Input_X.toPlainText()
        if not plain_text.strip():  # Check if plain_text is empty or contains only whitespace
            # Show a message box to inform the user to enter or load a message
            msg_box = QMessageBox()
            msg_box.setIcon(QMessageBox.Warning)
            msg_box.setWindowTitle("Message Required")
            msg_box.setText("Please write or load a message before signing.")
            msg_box.setWindowIcon(QIcon("msgbox.png"))  # Set the window icon
            msg_box.exec_()
            return  # Exit the function if plain_text is empty
        self.Output_X.append("\nSigning with Bob...")
        sign_RSA(plain_text, person)
        self.Output_X.append("\nSigned with Bob.")
        self.Output_X.append("\nSigned Text generated named Bob_signed_text.txt")
        self.last_signer = "Bob"

    def verify_with_bob(self):
        if self.last_encryption_mode == "ECB":
            signature_file = "ECB_AES_Decrypted.txt"
        elif self.last_encryption_mode == "CBC":
            signature_file = "CBC_AES_Decrypted.txt"
        else:
            # Show an error message box
            msg_box = QMessageBox()
            msg_box.setIcon(QMessageBox.Warning)
            msg_box.setWindowTitle("Sign First")
            msg_box.setText("\nPlease Enc file with AES before Verifying.")
            msg_box.setWindowIcon(QIcon("msgbox.png"))  # Set the window icon
            msg_box.setStandardButtons(QMessageBox.Ok)
            msg_box.exec_()
            return

        if not os.path.exists(signature_file):
            # Show a message box to inform the user that the signature file is not found
            msg_box = QMessageBox()
            msg_box.setIcon(QMessageBox.Critical)
            msg_box.setWindowTitle("File Not Found")
            msg_box.setText(f"\nThe required signature file '{signature_file}' was not found in the current directory.")
            msg_box.setWindowIcon(QIcon("msgbox.png"))  # Set the window icon
            msg_box.setStandardButtons(QMessageBox.Ok)
            msg_box.exec_()
            return

        try:
            # Retrieve the message and signature
            message = self.Input_X.toPlainText()

            # Load the signature from the file
            with open(signature_file, 'rb') as file:
                signature = file.read()

            # Verify the signature
            verify_RSA(signature, message, 'Bob')

            # Read the first line from Alice_verified_text.txt
            with open('Bob_verified_text.txt', 'r') as verified_file:
                first_line = verified_file.readline().strip()
            self.Output_X.append(f"\nBob's signature verification complete: {first_line}")
        except Exception as e:
            print(f"Error in verifying with Bob: {e}")
            self.Output_X.append(f"\nError in verifying with Bob: {e}")

    def ecb_aes_encryption_MAIN(self):
        if self.last_signer == "Alice":
            file_path = "Alice_signed_text.txt"
        elif self.last_signer == "Bob":
            file_path = "Bob_signed_text.txt"
        else:
            # Show an error message box
            msg_box = QMessageBox()
            msg_box.setIcon(QMessageBox.Warning)
            msg_box.setWindowTitle("Sign First")
            msg_box.setText("Please sign the file with Alice or Bob before encrypting.")
            msg_box.setWindowIcon(QIcon("msgbox.png"))  # Set the window icon
            msg_box.setStandardButtons(QMessageBox.Ok)
            msg_box.exec_()
            return

        ecb_aes_key = self.AES_Key_In_X.toPlainText()
        if not ecb_aes_key.strip():  # Check if plain_text is empty or contains only whitespace
            # Show a message box to inform the user to enter or load a message
            msg_box = QMessageBox()
            msg_box.setIcon(QMessageBox.Warning)
            msg_box.setWindowTitle("\nkey is Required")
            msg_box.setText("\nPlease write a key before Encrypting.")
            msg_box.setWindowIcon(QIcon("msgbox.png"))  # Set the window icon
            msg_box.exec_()
            return  # Exit the function if plain_text is empty
        for i in ecb_aes_key:
            if i not in "0123456789ABCDEFabcdef":
                error_message = "Error: The input string must be a hexadecimal string."
                self.Output_X.append(error_message)
        if len(ecb_aes_key) != 32:
            error_message = "Error: The input string must be exactly 32 characters long."
            self.Output_X.append(error_message)  # Append the error message to the Output_X text area
        else:
            self.Output_X.append("\nThe input string is of correct length (32 characters).")
            self.Output_X.append("\nPerforming ECB AES Encryption...")
            encrypt_file_ECB(file_path, "ECB_AES_Encrypted.txt", ecb_aes_key)
            self.Output_X.append("\nECB AES Encryption Complete.")
            self.Output_X.append("\nEncrypted Text generated named ECB_AES_Encrypted.txt")
            self.last_encryption_mode = "ECB"

    def cbc_aes_encryption_MAIN(self):
        if self.last_signer == "Alice":
            file_path = "Alice_signed_text.txt"
        elif self.last_signer == "Bob":
            file_path = "Bob_signed_text.txt"
        else:
            # Show an error message box
            msg_box = QMessageBox()
            msg_box.setIcon(QMessageBox.Warning)
            msg_box.setWindowTitle("Sign First")
            msg_box.setText("Please sign the file with Alice or Bob before encrypting.")
            msg_box.setWindowIcon(QIcon("msgbox.png"))  # Set the window icon
            msg_box.setStandardButtons(QMessageBox.Ok)
            msg_box.exec_()
            return

        cbc_aes_key = self.AES_Key_In_X.toPlainText()
        if not cbc_aes_key.strip():  # Check if plain_text is empty or contains only whitespace
            # Show a message box to inform the user to enter or load a message
            msg_box = QMessageBox()
            msg_box.setIcon(QMessageBox.Warning)
            msg_box.setWindowTitle("\nkey is Required")
            msg_box.setText("\nPlease write a key before Encrypting.")
            msg_box.setWindowIcon(QIcon("msgbox.png"))  # Set the window icon
            msg_box.exec_()
            return  # Exit the function if plain_text is empty
        for i in cbc_aes_key:
            if i not in "0123456789ABCDEFabcdef":
                error_message = "Error: The input string must be a hexadecimal string."
                self.Output_X.append(error_message)
        if len(cbc_aes_key) != 32:
            error_message = "Error: The input string must be exactly 32 characters long."
            self.Output_X.append(error_message)  # Append the error message to the Output_X text area
        else:
            self.Output_X.append("\nThe input string is of correct length (32 characters).")
            self.Output_X.append("\nPerforming CBC AES Encryption...")
            iv = b'abcdefghijklmnop'
            encrypt_file_CBC(file_path, "CBC_AES_Encrypted.txt", cbc_aes_key, iv)
            self.Output_X.append("\nCBC AES Encryption Complete.")
            self.Output_X.append("\nEncrypted Text generated named CBC_AES_Encrypted.txt")
            self.last_encryption_mode = "CBC"

    def ecb_aes_decryption_MAIN(self):
        if self.last_encryption_mode != "ECB":
            # Show an error message that the decryption mode is incorrect
            msg_box = QMessageBox()
            msg_box.setIcon(QMessageBox.Warning)
            msg_box.setWindowTitle("\nWrong Mode")
            msg_box.setText("\nInvalid Mode: Decrypting ECB AES with CBC mode is not allowed.")
            msg_box.setWindowIcon(QIcon("msgbox.png"))  # Set the window icon
            msg_box.exec_()
            return
        ecb_aes_key = self.AES_Key_In_X.toPlainText()
        if not ecb_aes_key.strip():  # Check if plain_text is empty or contains only whitespace
            # Show a message box to inform the user to enter or load a message
            msg_box = QMessageBox()
            msg_box.setIcon(QMessageBox.Warning)
            msg_box.setWindowTitle("\nkey is Required")
            msg_box.setText("\nPlease write a key before Decrypting.")
            msg_box.setWindowIcon(QIcon("msgbox.png"))  # Set the window icon
            msg_box.exec_()
            return  # Exit the function if plain_text is empty
        for i in ecb_aes_key:
            if i not in "0123456789ABCDEFabcdef":
                error_message = "Error: The input string must be a hexadecimal string."
                self.Output_X.append(error_message)
        if len(ecb_aes_key) != 32:
            error_message = "Error: The input string must be exactly 32 characters long."
            self.Output_X.append(error_message)  # Append the error message to the Output_X text area
        else:
            file_path = "ECB_AES_Encrypted.txt"
            if not os.path.exists(file_path):
                # Show a message box to inform the user that the file is not found
                msg_box = QMessageBox()
                msg_box.setIcon(QMessageBox.Critical)
                msg_box.setWindowTitle("File Not Found")
                msg_box.setText("The required file 'ECB_AES_Encrypted.txt' was not found in the current directory.")
                msg_box.setWindowIcon(QIcon("msgbox.png"))  # Set the window icon
                msg_box.exec_()
                return  # Exit the function
            try:
                self.Output_X.append("\nThe input string is of correct length (32 characters).")
                self.Output_X.append("\nPerforming ECB AES Decryption...")
                decrypt_file_ECB(file_path, "ECB_AES_Decrypted.txt", ecb_aes_key)
                self.Output_X.append("\nECB AES Decryption Complete.")
                self.Output_X.append("\nEncrypted Text generated named ECB_AES_Decrypted.txt")
            except Exception as e:
                error_message = f"Error during ECB AES Decryption: {str(e)}"
                self.Output_X.append(error_message)

    def cbc_aes_decryption_MAIN(self):
        if self.last_encryption_mode != "CBC":
            # Show an error message that the decryption mode is incorrect
            msg_box = QMessageBox()
            msg_box.setIcon(QMessageBox.Warning)
            msg_box.setWindowTitle("\nWrong Mode")
            msg_box.setText("\nInvalid Mode: Decrypting CBC AES with ECB mode is not allowed.")
            msg_box.setWindowIcon(QIcon("msgbox.png"))  # Set the window icon
            msg_box.exec_()
            return
        cbc_aes_key = self.AES_Key_In_X.toPlainText()
        if not cbc_aes_key.strip():  # Check if plain_text is empty or contains only whitespace
            # Show a message box to inform the user to enter or load a message
            msg_box = QMessageBox()
            msg_box.setIcon(QMessageBox.Warning)
            msg_box.setWindowTitle("\nkey is Required")
            msg_box.setText("\nPlease write a key before Decrypting.")
            msg_box.setWindowIcon(QIcon("msgbox.png"))  # Set the window icon
            msg_box.exec_()
            return  # Exit the function if plain_text is empty
        for i in cbc_aes_key:
            if i not in "0123456789ABCDEFabcdef":
                error_message = "Error: The input string must be a hexadecimal string."
                self.Output_X.append(error_message)
        if len(cbc_aes_key) != 32:
            error_message = "Error: The input string must be exactly 32 characters long."
            self.Output_X.append(error_message)  # Append the error message to the Output_X text area
        else:
            file_path = "CBC_AES_Encrypted.txt"
            if not os.path.exists(file_path):
                # Show a message box to inform the user that the file is not found
                msg_box = QMessageBox()
                msg_box.setIcon(QMessageBox.Critical)
                msg_box.setWindowTitle("File Not Found")
                msg_box.setText("The required file 'CBC_AES_Encrypted.txt' was not found in the current directory.")
                msg_box.setWindowIcon(QIcon("msgbox.png"))  # Set the window icon
                msg_box.exec_()
                return  # Exit the function
            self.Output_X.append("\nThe input string is of correct length (32 characters).")
            self.Output_X.append("\nPerforming CBC AES Decryption...")
            decrypt_file_CBC(file_path, "CBC_AES_Decrypted.txt", cbc_aes_key)
            self.Output_X.append("\nCBC AES Decryption Complete.")
            self.Output_X.append("\nEncrypted Text generated named CBC_AES_Decrypted.txt")

    def aes_key_changed_MAIN(self):
        print("AES Key changed:", self.AES_Key_In_X.toPlainText())

    def input_message_changed_MAIN(self):
        print("Input message changed:", self.Input_X.toPlainText())

    def output_changed_MAIN(self):
        print("Output changed:", self.Output_X.toPlainText())

    def clear_all(self):
        # Clearing the text editors
        self.Input_X.setPlainText("")  # Assuming 'Input_X' is an input text editor
        self.Output_X.setPlainText("")  # Clearing the output text editor
        self.AES_Key_In_X.setPlainText("")  # Clear the AES key text editor, if applicable

    #     ===============================================================================================================
    # AES TAB CODE
    def load_msg_AES(self):
        options = QFileDialog.Options()
        file_name, _ = QFileDialog.getOpenFileName(
            self, "Open File", "", "Text Files (*.txt);;All Files (*)", options=options
        )

        if file_name:
            self.AES_current_file_path = file_name  # Store the current file path
            try:
                with open(file_name, "r", encoding='utf-8') as file:
                    self.InputMsg_AES.append(file.read())
                    self.Output_AES.append("\nLoaded Message.")
            except Exception as e:
                print(f"Error loading file: {e}")

    def ecb_aes_encryption_AES(self):
        file_path = self.AES_current_file_path
        if not file_path:  # If no file is loaded
            # Show an error message box
            msg_box = QMessageBox()
            msg_box.setIcon(QMessageBox.Warning)
            msg_box.setWindowTitle("Msg Path not found")
            msg_box.setText("Please Load a msg before encrypting.")
            msg_box.setWindowIcon(QIcon("msgbox.png"))  # Set the window icon
            msg_box.setStandardButtons(QMessageBox.Ok)
            msg_box.exec_()
            return

        AES_ECB_key = self.AES_Key_In_X.toPlainText()
        if not AES_ECB_key.strip():  # Check if plain_text is empty or contains only whitespace
            # Show a message box to inform the user to enter or load a message
            msg_box = QMessageBox()
            msg_box.setIcon(QMessageBox.Warning)
            msg_box.setWindowTitle("\nkey is Required")
            msg_box.setText("\nPlease write a key before Encrypting.")
            msg_box.setWindowIcon(QIcon("msgbox.png"))  # Set the window icon
            msg_box.exec_()
            return  # Exit the function if plain_text is empty

        for i in AES_ECB_key:
            if i not in "0123456789ABCDEFabcdef":
                error_message = "Error: The input string must be a hexadecimal string."
                self.Output_X.append(error_message)

        if len(AES_ECB_key) != 32:
            error_message = "Error: The input string must be exactly 32 characters long."
            self.Output_X.append(error_message)  # Append the error message to the Output_X text area
        else:
            self.Output_X.append("\nThe input string is of correct length (32 characters).")
            self.Output_X.append("\nPerforming ECB AES Encryption...")
            encrypt_file_ECB(file_path, "ECB_AES_Encrypted.txt", AES_ECB_key)
            self.Output_X.append("\nECB AES Encryption Complete.")
            self.Output_X.append("\nEncrypted Text generated named ECB_AES_Encrypted.txt")
            self.last_encryption_mode = "ECB"

    def cbc_aes_encryption_AES(self):
        file_path = self.AES_current_file_path
        if not file_path:  # If no file is loaded
            # Show an error message box
            msg_box = QMessageBox()
            msg_box.setIcon(QMessageBox.Warning)
            msg_box.setWindowTitle("Msg Path not found")
            msg_box.setText("Please Load a msg before encrypting.")
            msg_box.setWindowIcon(QIcon("msgbox.png"))  # Set the window icon
            msg_box.setStandardButtons(QMessageBox.Ok)
            msg_box.exec_()
            return

        AES_CBC_key = self.InKeyAES_AES.toPlainText()
        if not AES_CBC_key.strip():  # Check if plain_text is empty or contains only whitespace
            # Show a message box to inform the user to enter or load a message
            msg_box = QMessageBox()
            msg_box.setIcon(QMessageBox.Warning)
            msg_box.setWindowTitle("\nkey is Required")
            msg_box.setText("\nPlease write a key before Encrypting.")
            msg_box.setWindowIcon(QIcon("msgbox.png"))  # Set the window icon
            msg_box.exec_()
            return  # Exit the function if plain_text is empty
        for i in AES_CBC_key:
            if i not in "0123456789ABCDEFabcdef":
                error_message = "Error: The input string must be a hexadecimal string."
                self.Output_X.append(error_message)
        if len(AES_CBC_key) != 32:
            error_message = "Error: The input string must be exactly 32 characters long."
            self.Output_X.append(error_message)  # Append the error message to the Output_X text area
        else:
            self.Output_X.append("\nThe input string is of correct length (32 characters).")
            self.Output_X.append("\nPerforming CBC AES Encryption...")
            iv = b'abcdefghijklmnop'
            encrypt_file_CBC(file_path, "CBC_AES_Encrypted.txt", AES_CBC_key, iv)
            self.Output_X.append("\nCBC AES Encryption Complete.")
            self.Output_X.append("\nEncrypted Text generated named CBC_AES_Encrypted.txt")
            self.last_encryption_mode = "CBC"

    def ecb_aes_decryption_AES(self):
        AES_ECB_key = self.AES_Key_In_X.toPlainText()
        if not AES_ECB_key.strip():  # Check if plain_text is empty or contains only whitespace
            # Show a message box to inform the user to enter or load a message
            msg_box = QMessageBox()
            msg_box.setIcon(QMessageBox.Warning)
            msg_box.setWindowTitle("\nkey is Required")
            msg_box.setText("\nPlease write a key before Decrypting.")
            msg_box.setWindowIcon(QIcon("msgbox.png"))  # Set the window icon
            msg_box.exec_()
            return  # Exit the function if plain_text is empty

        for i in AES_ECB_key:
            if i not in "0123456789ABCDEFabcdef":
                error_message = "Error: The input string must be a hexadecimal string."
                self.Output_X.append(error_message)
        if len(AES_ECB_key) != 32:
            error_message = "Error: The input string must be exactly 32 characters long."
            self.Output_X.append(error_message)  # Append the error message to the Output_X text area
        else:
            file_path = self.AES_current_file_path
            if not os.path.exists(file_path):
                # Show a message box to inform the user that the file is not found
                msg_box = QMessageBox()
                msg_box.setIcon(QMessageBox.Critical)
                msg_box.setWindowTitle("File Not Found")
                msg_box.setText("The required file 'ECB_AES_Encrypted.txt' was not found in the current directory.")
                msg_box.setWindowIcon(QIcon("msgbox.png"))  # Set the window icon
                msg_box.exec_()
                return  # Exit the function
            try:
                self.Output_X.append("\nThe input string is of correct length (32 characters).")
                self.Output_X.append("\nPerforming ECB AES Decryption...")
                decrypt_file_ECB(file_path, "ECB_AES_Decrypted.txt", AES_ECB_key)
                self.Output_X.append("\nECB AES Decryption Complete.")
                self.Output_X.append("\nEncrypted Text generated named ECB_AES_Decrypted.txt")
            except Exception as e:
                error_message = f"Error during ECB AES Decryption: {str(e)}"
                self.Output_X.append(error_message)

    def cbc_aes_decryption_AES(self):
        if self.last_encryption_mode != "CBC":
            # Show an error message that the decryption mode is incorrect
            msg_box = QMessageBox()
            msg_box.setIcon(QMessageBox.Warning)
            msg_box.setWindowTitle("\nWrong Mode")
            msg_box.setText("\nInvalid Mode: Decrypting CBC AES with ECB mode is not allowed.")
            msg_box.setWindowIcon(QIcon("msgbox.png"))  # Set the window icon
            msg_box.exec_()
            return
        cbc_aes_key = self.AES_Key_In_X.toPlainText()
        if not cbc_aes_key.strip():  # Check if plain_text is empty or contains only whitespace
            # Show a message box to inform the user to enter or load a message
            msg_box = QMessageBox()
            msg_box.setIcon(QMessageBox.Warning)
            msg_box.setWindowTitle("\nkey is Required")
            msg_box.setText("\nPlease write a key before Decrypting.")
            msg_box.setWindowIcon(QIcon("msgbox.png"))  # Set the window icon
            msg_box.exec_()
            return  # Exit the function if plain_text is empty
        for i in cbc_aes_key:
            if i not in "0123456789ABCDEFabcdef":
                error_message = "Error: The input string must be a hexadecimal string."
                self.Output_X.append(error_message)
        if len(cbc_aes_key) != 32:
            error_message = "Error: The input string must be exactly 32 characters long."
            self.Output_X.append(error_message)  # Append the error message to the Output_X text area
        else:
            file_path = "CBC_AES_Encrypted.txt"
            if not os.path.exists(file_path):
                # Show a message box to inform the user that the file is not found
                msg_box = QMessageBox()
                msg_box.setIcon(QMessageBox.Critical)
                msg_box.setWindowTitle("File Not Found")
                msg_box.setText("The required file 'CBC_AES_Encrypted.txt' was not found in the current directory.")
                msg_box.setWindowIcon(QIcon("msgbox.png"))  # Set the window icon
                msg_box.exec_()
                return  # Exit the function
            self.Output_X.append("\nThe input string is of correct length (32 characters).")
            self.Output_X.append("\nPerforming CBC AES Decryption...")
            decrypt_file_CBC(file_path, "CBC_AES_Decrypted.txt", cbc_aes_key)
            self.Output_X.append("\nCBC AES Decryption Complete.")
            self.Output_X.append("\nEncrypted Text generated named CBC_AES_Decrypted.txt")

    def input_message_changed_AES(self):
        if not self.AES_current_file_path:  # If no file is loaded
            self.AES_current_file_path = "MSG.txt"  # Set the file name to MSG.txt

            # Save the current text to the file
        try:
            with open(self.AES_current_file_path, "w", encoding='utf-8') as file:
                file.write(self.Input_X.toPlainText())
        except Exception as e:
            print(f"Error updating file: {e}")
    def output_changed_AES(self):
        print("Output changed:", self.Output_X.toPlainText())


class OverlayWidget(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Quick User Guide")
        icon = QIcon("GuideIcon.png")  # Replace with your icon file path
        self.setWindowIcon(icon)
        # Make the overlay modal
        self.setWindowModality(Qt.ApplicationModal)
        # Create the overlay widget
        self.init_ui()

    def init_ui(self):
        # Create layout for overlay
        layout = QVBoxLayout()

        # Add instructions label
        instructions_label = QLabel(
            "User Guide!\n\nInstructions: *Follow the button order from top to bottom* \nYou can write directly into the input boxes \n1.Firstly, Load Message, RSA Key and Write AES Key in the txt box (16 byte Hex format)! \n2. Sign ==> ENC_AES ==> Send \n3. DEC_AES ==> Verify \n4. Clear for resetting. ")
        layout.addWidget(instructions_label)

        # Add close button
        close_button = QPushButton("Close")
        close_button.clicked.connect(self.close_overlay)
        layout.addWidget(close_button)

        self.setLayout(layout)

    def close_overlay(self):
        self.hide()


if __name__ == "__main__":
    app = QApplication([])
    window = MyGUI()
    window.show()
    app.exec()
