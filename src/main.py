from PyQt5.QtCore import Qt
from PyQt5.QtGui import QIcon
from PyQt5.QtWidgets import *
from PyQt5.uic import loadUiType
# from AES import *
# Load the .ui file and generate the corresponding class dynamically
from RSA import *

Ui_MainWindow, _ = loadUiType("./GUI.ui")
terminals = ["IDENTIFIER", "NUMBER", "OP"]


class MyGUI(QMainWindow, Ui_MainWindow):
    MSG_Contents = ""

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
        icon = QIcon("icon.png")
        self.setWindowIcon(icon)

        # Load the css
        self.setStyleSheet(open("css.css").read())
        # ========================================================================================================================
        # Tab 1 Code

        # Connect buttons to functions directly
        self.LOAD_MSG_X.clicked.connect(self.load_file)
        self.Load_RSA_Key_E_X.clicked.connect(self.load_rsa_key)
        self.Sign_Alice_RSA_X.clicked.connect(self.sign_with_alice)
        self.Sign_Bob_RSA_X.clicked.connect(self.sign_with_bob)

        self.ECB_AES_E_X.clicked.connect(self.ecb_aes_encryption)
        self.ECB_AES_D_X.clicked.connect(self.ecb_aes_decryption)
        self.Send_Cypher_X.clicked.connect(self.send_cypher)
        self.CBC_AES_E_X.clicked.connect(self.cbc_aes_encryption)
        self.CBC_AES_D_X.clicked.connect(self.cbc_aes_decryption)
        self.Clear_All_X.clicked.connect(self.clear_all)

        self.Load_RSA_Key_D_X.clicked.connect(self.load_rsa_key)
        self.AES_Key_In_X.textChanged.connect(self.aes_key_changed)
        self.Input_X.textChanged.connect(self.input_message_changed)
        self.Output_X.textChanged.connect(self.output_changed)
        self.Verify_Alice_X.clicked.connect(self.verify_with_alice)
        self.Verfy_Bob_X.clicked.connect(self.verify_with_bob)

        # Define your functions here

    def load_file(self):
        options = QFileDialog.Options()
        file_name, _ = QFileDialog.getOpenFileName(
            self, "Open File", "", "Text Files (*.txt);;All Files (*)", options=options
        )

        if file_name:
            try:
                with open(file_name, "r", encoding='utf-8') as file:
                    MyGUI.MSG_Contents = file.read()
                    self.Input_X.setPlainText(MyGUI.MSG_Contents)
                    self.Output_X.setPlainText("Loaded Message.")
            except Exception as e:
                print(f"Error loading file: {e}")

        # loaded_message = "Message Loaded."
        # # Update the content of the output text box
        # self.update_output(loaded_message)

    def choose_file(self):
        options = QFileDialog.Options()
        file_name, _ = QFileDialog.getOpenFileName(
            self, "Choose File", "", "All Files (*)", options=options
        )

        return file_name

    def ecb_aes_encryption(self):
        print("Performing ECB AES Encryption...")

    def ecb_aes_decryption(self):
        print("Performing ECB AES Decryption...")

    def send_cypher(self):
        print("Sending Cypher...")

    def cbc_aes_encryption(self):
        print("Performing CBC AES Encryption...")

    def cbc_aes_decryption(self):
        print("Performing CBC AES Decryption...")

    def clear_all(self):
        print("Clearing All Fields...")

    # Load RSA Private Key button action listener

    # def load_file_and_process(self):
    #     options = QFileDialog.Options()
    #     file_name, _ = QFileDialog.getOpenFileName(
    #         self, "Open File", "", "Text Files (*.txt);;All Files (*)", options=options
    #     )
    #
    #     if file_name:
    #         try:
    #             with open(file_name, "r", encoding='utf-8') as file:
    #                 file_contents = file.read()
    #                 self.Input_X.setPlainText(file_contents)
    #
    #                 # Convert the file contents to a dictionary
    #                 loaded_dict = self.import_txt_to_dict(file_contents)
    #
    #                 # Send the dictionary to the RSA file
    #                 process_dictionary(loaded_dict)
    #         except Exception as e:
    #             print(f"Error loading and processing file: {e}")

    # def import_txt_to_dict(self, file_contents):
    #     """
    #     Import a text file contents to a dictionary.
    #
    #     Args:
    #     - file_contents: The contents of the file.
    #
    #     Returns:
    #     - A dictionary containing the data from the file.
    #     - None if there's an error.
    #     """
    #     try:
    #         lines = file_contents.splitlines()
    #
    #         # Assuming each line in the file is in the format "key: value"
    #         my_dict = {}
    #         for line in lines:
    #             key, value = map(str.strip, line.split(':', 1))
    #             my_dict[key] = value
    #
    #         return my_dict
    #     except Exception as e:
    #         print(f"Error importing dictionary from file contents: {e}")
    #         return None

    def aes_key_changed(self):
        print("AES Key changed:", self.AES_Key_In_X.toPlainText())

    def input_message_changed(self):
        print("Input message changed:", self.Input_X.toPlainText())

    def output_changed(self):
        print("Output changed:", self.Output_X.toPlainText())

    def verify_with_alice(self):
        try:
            # Retrieve the message and signature
            message = self.Input_X.toPlainText()
            signature_file = 'Alice_signed_text.txt'

            # Load the signature from the file
            with open(signature_file, 'rb') as file:
                signature = file.read()

            # Verify the signature
            verify_RSA(signature, message, 'Alice')
            self.Output_X.setPlainText("Alice's signature verification complete.")
        except Exception as e:
            print(f"Error in verifying with Alice: {e}")
            self.Output_X.setPlainText(f"Error in verifying with Alice: {e}")

    def verify_with_bob(self):
        try:
            # Retrieve the message and signature
            message = self.Input_X.toPlainText()
            signature_file = 'Bob_signed_text.txt'

            # Load the signature from the file
            with open(signature_file, 'rb') as file:
                signature = file.read()

            # Verify the signature
            verify_RSA(signature, message, 'Bob')
            self.Output_X.setPlainText("Bob's signature verification complete.")
        except Exception as e:
            print(f"Error in verifying with Bob: {e}")
            self.Output_X.setPlainText(f"Error in verifying with Bob: {e}")

    def load_rsa_key(self):
        file_path = self.choose_file()
        print("Loading RSA Key from:", file_path)
        load_private_keys(file_path)
        # self.Output_X.toPlainText(file_path)
        # load_private_keys(file_path)

    def sign_with_alice(self):
        person = "Alice"
        print(MyGUI.MSG_Contents)
        plain_text = MyGUI.MSG_Contents
        sign_RSA(plain_text, person)

        print("Signing with Alice...")

    def sign_with_bob(self):
        print("Signing with Bob...")

    def update_output(self, new_content):
        # Clear existing content and set new content
        self.Output_X.clear()
        self.Output_X.append(new_content)

    # ========================================================================================================================

    # # Text box for code input
    # self.code_editor = self.textEdit1
    # self.code_editor = self.textEdit2
    # self.code_editor = self.textEdit3
    # self.code_editor = self.textEdit4
    # self.code_editor = self.textEdit5
    #
    # # X action listeners
    # # Load File button action listener
    # self.Load_File_AES.clicked.connect(self.loadFile)
    #
    # self.Encrypt_AES.clicked.connect(self.encryptAES)
    # self.Decrypt_AES.clicked.connect(self.decryptAES)
    #
    # # Connect the currentIndexChanged signal to the slot
    # # self.EncryptionMode_AES.currentIndexChanged.connect(self.on_combo_box_current_index_changed)
    #
    # # Export button action listener
    # # self.Export_File_AES.clicked.connect(self.exportFile)
    #
    # # Clear button action listener
    # self.Clear_AES.clicked.connect(self.clear_all)
    # # ===============================================================================================
    # # AES Encryption action listeners
    # # Load File button action listener
    # self.Load_File_AES.clicked.connect(self.loadFile)
    #
    # self.EncryptAES.clicked.connect(self.encryptAES)
    # self.DecryptAES.clicked.connect(self.decryptAES)
    #
    # # Clear button action listener
    # self.Clear_AES.clicked.connect(self.clear_all)
    # # ===============================================================================================
    # # RSA Encryption action listener
    # # Load File button action listener
    # self.Load_File_RSA.clicked.connect(self.loadFile)
    #
    # # Encrypt/Decrypt buttons action listeners
    # self.EncryptRSA.clicked.connect(self.encryptRSA)
    # self.DecryptRSA.clicked.connect(self.decryptRSA)
    #
    # # Export button action listener
    # self.Export_File_RSA.clicked.connect(self.exportFile)
    #
    # # Clear button action listener
    # self.Clear_RSA.clicked.connect(self.clear_all)
    # # ===============================================================================================
    # # RSA Verification action listener
    # # Load File button action listener
    # self.Load_File_Certificate.clicked.connect(self.loadFile)
    #
    # # Encrypt/Decrypt buttons action listeners
    # self.SignRSA.clicked.connect(self.signRSA)
    # self.VerifyRSA.clicked.connect(self.verifyRSA)
    #
    # # Export button action listener
    # self.Export_File_Certificate.clicked.connect(self.exportFile)
    #
    # # Clear button action listener
    # self.Clear_Certificate.clicked.connect(self.clear_all)
    # # ===============================================================================================
    # # Sha-512 Hashing action listener
    # # Load File button action listener
    # self.Load_File_SHA.clicked.connect(self.loadFile)
    #
    # # Encrypt/Decrypt buttons action listeners
    # self.CalcSHA.clicked.connect(self.encryptSHA512)
    # self.VerifySHA.clicked.connect(self.decryptSHA512)
    #
    # # Export button action listener
    # self.Export_File_SHA.clicked.connect(self.exportFile)
    #
    # # Clear button action listener
    # self.Clear_SHA.clicked.connect(self.clear_all)

    def loadFile(self):
        options = QFileDialog.Options()
        file_name, _ = QFileDialog.getOpenFileName(
            self, "Open File", "", "Text Files (*.txt)", options=options
        )

        if file_name:
            with open(file_name, "r", encoding='utf-8') as file:
                file_contents = file.read()
                self.code_editor.setPlainText(file_contents)

    def encryptAES(self):
        pass

    def decryptAES(self):
        pass

    def on_combo_box_activated(self, index):
        pass

    def encryptRSA(self):
        pass

    def decryptRSA(self):
        pass

    def signRSA(self):
        pass

    def verifyRSA(self):
        pass

    def encryptSHA512(self):
        pass

    def decryptSHA512(self):
        pass

    def exportFile(self):
        options = QFileDialog.Options()
        file_name, _ = QFileDialog.getSaveFileName(
            self, "Save File", "", "Text Files (*.txt);;All Files (*)", options=options
        )

        if file_name:
            try:
                with open(file_name, "w", encoding='utf-8') as file:
                    file.write(self.code_editor.toPlainText())
            except Exception as e:
                print(f"Error exporting file: {e}")

    def clear_all(self):
        self.code_editor.setPlainText("")


if __name__ == "__main__":
    app = QApplication([])
    window = MyGUI()
    window.show()
    app.exec()
