import sys
import os
import time

# Add the project root to the Python path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from PyQt6.QtWidgets import QApplication, QSplashScreen
from PyQt6.QtGui import QPixmap, QIcon
from PyQt6.QtCore import Qt
from secureguard.gui.main_window import MainWindow

def main():
    app = QApplication(sys.argv)
    
    # Application Branding
    app.setWindowIcon(QIcon(os.path.join(os.path.dirname(__file__), "assets", "logo.png")))
    app.setApplicationName("SecureGuard")
    
    # Splash Screen
    splash_pixmap = QPixmap(os.path.join(os.path.dirname(__file__), "assets", "splash.png"))
    splash_pixmap = splash_pixmap.scaledToWidth(800, Qt.TransformationMode.SmoothTransformation)
    splash = QSplashScreen(splash_pixmap, Qt.WindowType.WindowStaysOnTopHint)
    splash.show()
    
    # Simulate loading process
    app.processEvents()
    splash.showMessage("Loading core modules...", Qt.AlignmentFlag.AlignBottom | Qt.AlignmentFlag.AlignCenter, Qt.GlobalColor.white)
    time.sleep(0.5)
    app.processEvents()
    splash.showMessage("Initializing knowledge base...", Qt.AlignmentFlag.AlignBottom | Qt.AlignmentFlag.AlignCenter, Qt.GlobalColor.white)
    time.sleep(0.5)
    app.processEvents()
    splash.showMessage("Starting SecureGuard...", Qt.AlignmentFlag.AlignBottom | Qt.AlignmentFlag.AlignCenter, Qt.GlobalColor.white)
    time.sleep(0.5)
    app.processEvents()
    
    # Initialize main window
    window = MainWindow()
    window.showMaximized()
    
    splash.finish(window)
    
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
