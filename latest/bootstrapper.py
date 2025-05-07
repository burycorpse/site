import sys
from PyQt5.QtWidgets import QApplication
import main 

def run_app():
    app = QApplication(sys.argv)
    window = main.FileManagerApp()
    window.show()
    sys.exit(app.exec_())

if __name__ == '__main__':
    run_app()
