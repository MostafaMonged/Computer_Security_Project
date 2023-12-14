from PyQt5.QtCore import Qt
from PyQt5.QtGui import QIcon
from PyQt5.QtWidgets import *
from PyQt5.uic import loadUiType

# Load the .ui file and generate the corresponding class dynamically
Ui_MainWindow, _ = loadUiType("./GUI.ui")
terminals = ["IDENTIFIER", "NUMBER", "OP"]


class MyGUI(QMainWindow, Ui_MainWindow):
    def __init__(self):
        super(MyGUI, self).__init__()

        # Set up the user interface
        self.setupUi(self)

        # Creating the main window
        self.setGeometry(100, 100, 850, 600)
        self.setWindowTitle("Scanner Application")

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

        # Text box for code input
        self.code_editor = self.textEdit1
        self.code_editor = self.textEdit2
        self.code_editor = self.textEdit3
        self.code_editor = self.textEdit4

        # AES Encryption action listeners
        # Load File button action listener
        self.Load_File_AES.clicked.connect(self.loadFile)

        self.EncryptAES.clicked.connect(self.encryptAES)
        self.DecryptAES.clicked.connect(self.decryptAES)

        # Export button action listener
        self.Export_File_AES.clicked.connect(self.exportFile)

        # Clear button action listener
        self.Clear_AES.clicked.connect(self.clear_all)
        # ===============================================================================================
        # RSA Encryption action listener
        # Load File button action listener
        self.Load_File_RSA.clicked.connect(self.loadFile)

        # Encrypt/Decrypt buttons action listeners
        self.EncryptRSA.clicked.connect(self.encryptRSA)
        self.DecryptRSA.clicked.connect(self.decryptRSA)

        # Export button action listener
        self.Export_File_RSA.clicked.connect(self.exportFile)

        # Clear button action listener
        self.Clear_RSA.clicked.connect(self.clear_all)
        # ===============================================================================================
        # RSA Verification action listener
        # Load File button action listener
        self.Load_File_Certificate.clicked.connect(self.loadFile)

        # Encrypt/Decrypt buttons action listeners
        self.SignRSA.clicked.connect(self.signRSA)
        self.VerifyRSA.clicked.connect(self.verifyRSA)

        # Export button action listener
        self.Export_File_Certificate.clicked.connect(self.exportFile)

        # Clear button action listener
        self.Clear_Certificate.clicked.connect(self.clear_all)
        # ===============================================================================================
        # Sha-512 Hashing action listener
        # Load File button action listener
        self.Load_File_SHA.clicked.connect(self.loadFile)

        # Encrypt/Decrypt buttons action listeners
        self.CalcSHA.clicked.connect(self.encryptSHA512)
        self.VerifySHA.clicked.connect(self.decryptSHA512)

        # Export button action listener
        self.Export_File_SHA.clicked.connect(self.exportFile)

        # Clear button action listener
        self.Clear_SHA.clicked.connect(self.clear_all)

        # # Table for output display
        # self.output_table = self.tableWidget1
        # self.output_table.setColumnCount(2)  # Two columns for the tuple elements
        # self.output_table.setHorizontalHeaderLabels(["Token", "Type"])  # Column headers
        # self.output_table.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        # self.output_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)

        # # Table for output display
        # self.output_table = self.tableWidget2
        # self.output_table.setColumnCount(2)  # Two columns for the tuple elements
        # self.output_table.setHorizontalHeaderLabels(["Token", "Type"])  # Column headers
        # self.output_table.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        # self.output_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        #
        # # Table for output display
        # self.output_table = self.tableWidget3
        # self.output_table.setColumnCount(2)  # Two columns for the tuple elements
        # self.output_table.setHorizontalHeaderLabels(["Token", "Type"])  # Column headers
        # self.output_table.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        # self.output_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        #
        # # Table for output display
        # self.output_table = self.tableWidget4
        # self.output_table.setColumnCount(2)  # Two columns for the tuple elements
        # self.output_table.setHorizontalHeaderLabels(["Token", "Type"])  # Column headers
        # self.output_table.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        # self.output_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)

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
            self, "Save File", "", "Text Files (*.txt)", options=options
        )

    def clear_all(self):
        self.code_editor.setPlainText("")


if __name__ == "__main__":
    app = QApplication([])
    window = MyGUI()
    window.show()
    app.exec()
