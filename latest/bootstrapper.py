import sys
import os
from PyQt6.QtWidgets import QApplication
from PyQt6.QtCore import Qt
import main

def run_app():
    QApplication.setHighDpiScaleFactorRoundingPolicy(Qt.HighDpiScaleFactorRoundingPolicy.PassThrough)
    
    app = QApplication(sys.argv)
    window = main.FileManagerApp()
    
    window.show_login_and_fade_in()
    
    sys.exit(app.exec())

if __name__ == '__main__':
    run_app()
