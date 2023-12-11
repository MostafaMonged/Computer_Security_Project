
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
        self.code_editor = self.textEdit

        # Load File button action listener
        self.Load_File.clicked.connect(self.loadFile)

        # Scan button action listener
        self.Scan.clicked.connect(self.scanCode)

        # Parse button action listener
        self.Parse.clicked.connect(self.parseCode)

        # Export button action listener
        self.Export_File.clicked.connect(self.exportFile)

        # Clear button action listener
        self.Clear.clicked.connect(self.clear_all)

        # Table for output display
        self.output_table = self.tableWidget
        self.output_table.setColumnCount(2)  # Two columns for the tuple elements
        self.output_table.setHorizontalHeaderLabels(["Token", "Type"])  # Column headers
        self.output_table.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.output_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)

    def loadFile(self):
        options = QFileDialog.Options()
        file_name, _ = QFileDialog.getOpenFileName(
            self, "Open File", "", "Text Files (*.txt)", options=options
        )

        if file_name:
            with open(file_name, "r", encoding='utf-8') as file:
                file_contents = file.read()
                self.code_editor.setPlainText(file_contents)

    def scanCode(self):

        # Clear the table before adding new data
        self.output_table.setRowCount(0)

        # Add a new row to the table
        rowPosition = self.output_table.rowCount()
        self.output_table.insertRow(rowPosition)

        # Set the values from the tuple into the columns
        self.output_table.setItem(rowPosition, 0, QTableWidgetItem(str()))
        self.output_table.setItem(rowPosition, 1, QTableWidgetItem(str()))

    def parseCode(self):
        pass

    def exportFile(self):
        options = QFileDialog.Options()
        file_name, _ = QFileDialog.getSaveFileName(
            self, "Save File", "", "Text Files (*.txt)", options=options
        )

        if file_name:
            with open(file_name, "w") as file:
                # Export the table data
                for row in range(self.output_table.rowCount()):
                    column1 = self.output_table.item(row, 0).text()
                    column2 = self.output_table.item(row, 1).text()
                    file.write(f"{column1}\t\t{column2}\n")

    def clear_all(self):
        self.output_table.setRowCount(0)
        self.code_editor.setPlainText("")


if __name__ == "__main__":
    app = QApplication([])
    window = MyGUI()
    window.show()
    app.exec()
