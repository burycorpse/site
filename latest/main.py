import sys, os, json, base64, requests, threading, http.server, socketserver, webbrowser, time, uuid, shutil
from datetime import datetime
from urllib.parse import parse_qs, urlparse
from cryptography.fernet import Fernet
from PyQt5.QtWidgets import QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QLineEdit, QScrollArea, QFrame, QFileDialog, QMessageBox, QComboBox, QGridLayout, QPlainTextEdit
from PyQt5.QtCore import Qt, QPoint, QEvent, pyqtSignal
from PyQt5.QtGui import QFont, QPixmap

os.chdir(os.path.dirname(os.path.abspath(sys.argv[0])))

COLORS = {
    'background': '#0d0f12',
    'surface': '#16181d',
    'primary': '#1d2025',
    'secondary': '#25282e',
    'accent': '#ac3464',
    'text': '#c5c8d9',
    'text_secondary': '#707580',
    'border': '#2a2d34',
    'highlight': '#3c404a'
}
FONT_FAMILY = "Consolas"
STYLE_SHEET = f"""
    QMainWindow, QWidget {{
        background-color: {COLORS['background']};
        color: {COLORS['text']};
        font-family: {FONT_FAMILY};
    }}
    QFrame#main_panel {{
        background-color: {COLORS['surface']};
        border: 1px solid {COLORS['border']};
        border-radius: 2px;
    }}
    QPushButton {{
        background-color: {COLORS['primary']};
        color: {COLORS['text']};
        border: 1px solid {COLORS['border']};
        padding: 8px 16px;
        min-width: 120px;
        text-transform: uppercase;
        font-weight: bold;
    }}
    QPushButton:hover {{
        background-color: {COLORS['accent']};
        color: {COLORS['background']};
        border: 1px solid {COLORS['accent']};
    }}
    QPushButton:pressed {{
        background-color: {COLORS['secondary']};
    }}
    QLineEdit, QComboBox {{
        background-color: {COLORS['primary']};
        color: {COLORS['text']};
        border: 1px solid {COLORS['border']};
        padding: 6px;
    }}
    QScrollArea {{
        border: none;
        background: transparent;
    }}
"""


class OAuth2Handler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, format, *args):
        pass  

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        
        base_html = """
        <html>
          <head>
            <title>{title}</title>
            <style>
              body {{
            background-color: BG_COLOR;
            color: TEXT_COLOR;
            font-family: FONT_FAMILY;
            text-align: center;
            padding-top: 50px;
              }}
              .container {{
            max-width: 400px;
            margin: auto;
            padding: 20px;
            background-color: SURFACE_COLOR;
            border: 1px solid BORDER_COLOR;
            border-radius: 4px;
              }}
              h2 {{
            font-size: 22px;
            margin-bottom: 10px;
            color: ACCENT_COLOR;
              }}
              p {{
            font-size: 14px;
              }}
              .button {{
            display: inline-block;
            padding: 10px 20px;
            background-color: PRIMARY_COLOR;
            color: TEXT_COLOR;
            text-decoration: none;
            border-radius: 4px;
            margin-top: 15px;
              }}
              .button:hover {{
            background-color: SECONDARY_COLOR;
              }}
            </style>
            <meta http-equiv="refresh" content="5;url=https://badassfuckingkid.website">
          </head>
          <body>
            <div class="container">
              <h2>{header}</h2>
              <p>{message}</p>
            </div>
          </body>
        </html>
        """
        
        base_html = base_html.replace("BG_COLOR", COLORS['background'])
        base_html = base_html.replace("TEXT_COLOR", COLORS['text'])
        base_html = base_html.replace("FONT_FAMILY", FONT_FAMILY)
        base_html = base_html.replace("SURFACE_COLOR", COLORS['surface'])
        base_html = base_html.replace("BORDER_COLOR", COLORS['border'])
        base_html = base_html.replace("ACCENT_COLOR", COLORS['accent'])
        base_html = base_html.replace("PRIMARY_COLOR", COLORS['primary'])
        base_html = base_html.replace("SECONDARY_COLOR", COLORS['secondary'])

        parsed = urlparse(self.path)
        query = parse_qs(parsed.query)
        
        if "code" in query:
            success_html = base_html.format(
                title="Authentication Successful",
                header="Authentication Successful!",
                message="You may now close this window."
            )
            self.server.oauth_code = query["code"][0]
            self.wfile.write(success_html.encode())
        else:
            error_html = base_html.format(
                title="Authentication Failed",
                header="Authentication Failed",
                message="Missing authentication code."
            )
            self.wfile.write(error_html.encode())


class ModernTitleBar(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedHeight(32)
        self._dragPos = None
        layout = QHBoxLayout(self)
        layout.setContentsMargins(8, 0, 8, 0)
        
        self.title = QLabel("MY DEADLY INTELLECT")
        self.title.setStyleSheet(f"color: {COLORS['accent']}; font-weight: bold;")
        layout.addWidget(self.title)
        layout.addStretch()
        self.close_btn = QPushButton("✕")
        self.close_btn.setFixedSize(24, 24)
        self.close_btn.clicked.connect(lambda: self.window().close())
        self.close_btn.setStyleSheet(f"""
            QPushButton {{
                background: transparent;
                color: {COLORS['text_secondary']};
                font-size: 18px;
            }}
            QPushButton:hover {{
                color: {COLORS['accent']};
            }}
        """)
        layout.addWidget(self.close_btn)

    def mousePressEvent(self, event):
        if event.button() == Qt.LeftButton:
            self._dragPos = event.globalPos() - self.window().frameGeometry().topLeft()
            event.accept()

    def mouseMoveEvent(self, event):
        if event.buttons() == Qt.LeftButton and self._dragPos:
            self.window().move(event.globalPos() - self._dragPos)
            event.accept()

    def mouseReleaseEvent(self, event):
        self._dragPos = None






class LoginScreen(QWidget):
    def __init__(self):
        super().__init__()
        layout = QVBoxLayout(self)
        layout.setAlignment(Qt.AlignCenter)
        
        title = QLabel("MDI LAUNCHER")
        title.setFont(QFont(FONT_FAMILY, 24, QFont.Bold))
        title.setStyleSheet(f"color: {COLORS['accent']};")
        
        self.login_btn = QPushButton("INITIALIZE")
        self.login_btn.setFixedSize(200, 40)
        
        version = QLabel("v3.1BETA")
        version.setStyleSheet(f"color: {COLORS['text_secondary']};")
        
        layout.addSpacing(100)
        layout.addWidget(title, alignment=Qt.AlignCenter)
        layout.addSpacing(40)
        layout.addWidget(self.login_btn, alignment=Qt.AlignCenter)
        layout.addSpacing(100)
        layout.addWidget(version, alignment=Qt.AlignCenter)


class FileItem(QFrame):
    clicked = pyqtSignal(str)
    def __init__(self, file_id, data, parent=None):
        super().__init__(parent)
        self.file_id = file_id
        self.data = data
        self.setFixedHeight(48)
        self.setStyleSheet(f"""
            QFrame {{
                background-color: {COLORS['primary']};
                border: 1px solid {COLORS['border']};
            }}
            QFrame:hover {{
                border: 1px solid {COLORS['accent']};
            }}
        """)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(12, 0, 12, 0)
        
        self.name_label = QLabel(data.get("game_name", "Unknown"))
        self.name_label.setStyleSheet("color: " + COLORS['text'] + ";")
        self.category_label = QLabel(data.get("category", "Unknown"))
        self.category_label.setStyleSheet("color: " + COLORS['accent'] + "; font-weight: bold;")
        try:
            dt = datetime.fromisoformat(data.get("upload_time", "1970-01-01T00:00:00"))
            date_str = dt.strftime("%Y-%m-%d")
        except Exception:
            date_str = "Unknown"
        self.date_label = QLabel(date_str)
        self.date_label.setStyleSheet("color: " + COLORS['text_secondary'] + ";")
        
        layout.addWidget(self.name_label)
        layout.addWidget(self.category_label)
        layout.addWidget(self.date_label)

    def mousePressEvent(self, event):
        self.clicked.emit(self.file_id)
        self.setStyleSheet(f"border: 2px solid {COLORS['accent']};")

class MainScreen(QWidget):
    def __init__(self):
        super().__init__()
        layout = QGridLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setHorizontalSpacing(16)
        self.selected_item = None

        left_panel = QFrame()
        left_panel.setFixedWidth(240)
        left_panel.setStyleSheet(f"background-color: {COLORS['primary']}; border: 1px solid {COLORS['border']};")
        left_layout = QVBoxLayout(left_panel)
        left_layout.setAlignment(Qt.AlignTop)

        self.announcements_label = QLabel("Announcements:")
        self.announcements_label.setStyleSheet("color: white; font-size: 14px; font-weight: bold;")
        self.announcements_textbox = QPlainTextEdit()
        self.announcements_textbox.setReadOnly(True)
        self.announcements_textbox.setFixedHeight(100)

        self.avatar_label = QLabel()
        self.avatar_label.setFixedSize(64, 64)
        self.avatar_label.setStyleSheet("border: 1px solid " + COLORS['border'] + ";")
        left_layout.addWidget(self.avatar_label, alignment=Qt.AlignCenter)

        self.user_label = QLabel("Not logged in")
        self.user_label.setStyleSheet(f"color: {COLORS['accent']}; font-size: 14px;")
        left_layout.addWidget(self.user_label, alignment=Qt.AlignCenter)
        left_layout.addSpacing(16)

        self.load_vault_btn = QPushButton("load vault data") 
        left_layout.addWidget(self.load_vault_btn)

        self.upload_btn = QPushButton("UPLOAD")
        self.upload_btn.setVisible(False)
        left_layout.addWidget(self.upload_btn)

        self.download_btn = QPushButton("DOWNLOAD")
        left_layout.addWidget(self.download_btn)
        left_layout.addSpacing(8)



        left_layout.addWidget(self.announcements_label)
        left_layout.addWidget(self.announcements_textbox)

        self.category_combo = QComboBox()
        self.category_combo.addItems(["ALL", "MATRIX/CELEX", "MATRIX", "MATCHA"])
        left_layout.addWidget(self.category_combo)
        left_layout.addStretch()

        right_panel = QFrame()
        right_layout = QVBoxLayout(right_panel)
        right_layout.setAlignment(Qt.AlignTop)

        search_layout = QHBoxLayout()
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("SEARCH...")
        self.search_btn = QPushButton("FILTER")
        search_layout.addWidget(self.search_input)
        search_layout.addWidget(self.search_btn)
        right_layout.addLayout(search_layout)
        right_layout.addSpacing(8)

        self.file_scroll = QScrollArea()
        self.file_scroll.setWidgetResizable(True)
        self.file_container = QWidget()
        self.file_layout = QVBoxLayout(self.file_container)
        self.file_layout.setAlignment(Qt.AlignTop)
        self.file_scroll.setWidget(self.file_container)
        right_layout.addWidget(self.file_scroll)

        layout.addWidget(left_panel, 0, 0)
        layout.addWidget(right_panel, 0, 1)

        self.select_callback = None

    def set_select_callback(self, callback):
        """Fix: Allow FileManagerApp to set the file selection callback."""
        self.select_callback = callback

    def clear_file_list(self):
        """Removes all items from the file list."""
        while self.file_layout.count():
            child = self.file_layout.takeAt(0)
            if child.widget():
                child.widget().deleteLater()

    def populate_file_list(self, metadata):
        """Populates the file list with metadata."""
        self.clear_file_list()
        for fid, data in sorted(metadata.items(), key=lambda x: x[1].get("upload_time", ""), reverse=True):
            item = FileItem(fid, data, parent=self.file_container)
            item.clicked.connect(self.file_item_clicked)
            self.file_layout.addWidget(item)

    def file_item_clicked(self, file_id):
        if self.select_callback:
            self.select_callback(file_id)
            
        sender = self.sender()
        if not sender:
            return

        if self.selected_item and self.selected_item is not sender:
            try:
                self.selected_item.setStyleSheet(f"""
                    QFrame {{
                        background-color: {COLORS['primary']};
                        border: 1px solid {COLORS['border']};
                    }}
                    QFrame:hover {{
                        border: 1px solid {COLORS['accent']};
                    }}
                """)
            except Exception as e:
                print("Previous item may have been deleted:", e)

        try:
            sender.setStyleSheet(f"border: 2px solid {COLORS['accent']};")
            self.selected_item = sender
        except Exception as e:
            print("Error updating sender style:", e)

class _FuncEvent(QEvent):
    def __init__(self, func):
        super().__init__(QEvent.User)
        self.func = func
    def exec_(self):
        self.func()


class FileManagerApp(QMainWindow):
    def __init__(self):
        super().__init__()

        
        self.setWindowFlags(Qt.FramelessWindowHint)
        self.setAttribute(Qt.WA_TranslucentBackground, False)
        self.setWindowTitle("My Deadly Intellect")
        self.resize(1200, 800)
        self.setStyleSheet(STYLE_SHEET)
        self.setFont(QFont(FONT_FAMILY, 9))
        self.check_for_updates()
        self.title_bar = ModernTitleBar(self)

        self.app_dir = os.path.dirname(os.path.abspath(__file__))
        self.data_dir = os.path.join(self.app_dir, "data")
        os.makedirs(self.data_dir, exist_ok=True)
        self.metadata_file = os.path.join(self.data_dir, "vault_data.enc")
        self.key_file = os.path.join(self.data_dir, "key.bin")
        self.metadata = {}
        self.initialize_encryption()

        self.DISCORD_CLIENT_ID = "1295557084380794971"
        self.DISCORD_CLIENT_SECRET = "TfZg4LATcoZXn7rjq3rle7bSgdcvlM9J"
        self.REDIRECT_URI = "http://127.0.0.1:5000/callback"
        self.SCOPES = "identify guilds"
        self.DISCORD_WEBHOOK_URL = "https://canary.discord.com/api/webhooks/1336153655618965575/rUTWZAx6-nV5zyB4KrTn8tZfactvmKnWHWbBCPHqW2z5aFs4KoQ7uNuzrPlVuQGN70Xl"
        self.DEV_USER_IDS = ["1158085809400975411"]
        self.GUILD_ID = "1281345667868004493"
        self.REQUIRED_ROLE_ID = "1314788615481462795"

        self.current_user = None
        self.selected_file_id = None

        self.panel_id = str(uuid.uuid4())
        self.is_blacklisted = False
        self.leak_detected = False
        self.download_timestamps = []

        # Screens
        self.login_screen = LoginScreen()
        self.main_screen = MainScreen()
        self.main_screen.hide()
        self.main_screen.set_select_callback(self.select_file)
        self.main_screen.load_vault_btn.clicked.connect(self.load_vault_data)
        self.check_blacklist()

        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(self.title_bar)
        layout.addWidget(self.login_screen)
        layout.addWidget(self.main_screen)
        self.setCentralWidget(container)

        # Connect buttons
        self.login_screen.login_btn.clicked.connect(self.start_oauth)
        self.main_screen.search_btn.clicked.connect(self.refresh_file_list)
        self.main_screen.download_btn.clicked.connect(self.download_file)
        self.main_screen.upload_btn.clicked.connect(self.upload_file)
        self.main_screen.category_combo.currentTextChanged.connect(self.refresh_file_list)
        self.main_screen.load_vault_btn.clicked.connect(self.load_vault_data)
        

    def check_user_authorization(self):
        allowed_users = self.fetch_allowed_users()
        if not self.current_user:
            return False
        if self.current_user["id"] not in allowed_users and self.current_user["id"] not in self.DEV_USER_IDS:
            QMessageBox.critical(self, "Access Denied", "You are not authorized to use this program.")
            self.self_destruct()
            return False
        return True      

    def fetch_allowed_users(self):
        auth_url = "https://badassfuckingkid.website/users.json" 
        try:
            response = requests.get(auth_url)
            if response.status_code == 200:
                data = response.json()
                return data.get("allowed_users", [])
            else:
                print("Failed to fetch user list from the server.")
                return []
        except Exception as e:
            print(f"Error fetching user list: {e}")
            return []


    def check_for_updates(self):
        """Checks for updates and auto-downloads the latest version if available."""
        update_url = "https://badassfuckingkid.website/updater.json"
        try:
            response = requests.get(update_url)
            if response.status_code == 200:
                data = response.json()
                latest_version = data.get("version")
                download_url = data.get("download_url")

                if latest_version and latest_version != "3.7":
                    print(f"Update Available: v{latest_version}")
                    self.download_latest_version(download_url)
                else:
                    print("You are running the latest version.")
            else:
                print("Failed to check for updates.")
        except Exception as e:
            print(f"Update check failed: {e}")

    def download_latest_version(self, url):
        """Downloads and replaces main.py with the latest version."""
        try:
            response = requests.get(url, stream=True)
            if response.status_code == 200:
                with open("main.py.new", "wb") as f:
                    shutil.copyfileobj(response.raw, f)
                shutil.move("main.py.new", "main.py")
                print("Update complete. Restart the application.")
                sys.exit(0)
            else:
                print("Failed to download the latest update.")
        except Exception as e:
            print(f"Update download failed: {e}")

    def check_for_vault_update(self):
        """Checks if a new vault_data.enc is available on the server."""
        vault_update_url = "https://badassfuckingkid.website/data.json" 
        try:
            response = requests.get(vault_update_url)
            if response.status_code == 200:
                data = response.json()
                remote_version = data.get("version")
                download_url = data.get("download_url")
                local_version_file = os.path.join(self.data_dir, "vault_version.txt")
                local_version = None
                if os.path.exists(local_version_file):
                    with open(local_version_file, "r") as f:
                        local_version = f.read().strip()
                if remote_version != local_version:
                    print(f"New vault data available: {remote_version}")
                    self.download_latest_vault(download_url, remote_version)
                else:
                    print("Vault data is up-to-date.")
            else:
                print("Failed to check for vault update. HTTP", response.status_code)
        except Exception as e:
            print("Vault update check error:", e)

    def download_latest_vault(self, download_url, remote_version):
        try:
            response = requests.get(download_url, stream=True)
            if response.status_code == 200:
                temp_path = os.path.join(self.data_dir, "vault_data.enc.new")
                with open(temp_path, "wb") as f:
                    for chunk in response.iter_content(chunk_size=8192):
                        if chunk:
                            f.write(chunk)
                os.replace(temp_path, self.metadata_file)
                local_version_file = os.path.join(self.data_dir, "vault_version.txt")
                with open(local_version_file, "w") as f:
                    f.write(remote_version)
                print("Vault data updated successfully.")
                self.load_metadata()
                self.refresh_file_list()
            else:
                print("Failed to download new vault data. HTTP", response.status_code)
        except Exception as e:
            print("Error downloading vault data:", e)


    def load_vault_data(self):
        options = QFileDialog.Options()
        file_path, _ = QFileDialog.getOpenFileName(self, "Select Vault Data File", "", "Encrypted Files (*.enc);;All Files (*)", options=options)
        if file_path:
            self.metadata_file = file_path  # update metadata file path
            try:
                self.load_metadata()
                self.refresh_file_list()
                QMessageBox.information(self, "Vault Data", "Vault data loaded successfully!")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to load vault data:\n{str(e)}")


    def initialize_encryption(self):
        """Ensures encryption key remains consistent even after PyArmor obfuscation."""
        try:
            FIXED_KEY = b'GeGPpWqxdczIPT9-TJd1XCaT27v3lFthP0QTe4bnm9s='  # Replace this with your actual key (must be 44 bytes long)
            
            # Validate key format
            if len(FIXED_KEY) != 44:
                raise ValueError("Invalid fixed encryption key length! Must be 44 characters.")
            
            self.key = FIXED_KEY
            self.cipher_suite = Fernet(self.key)
            print("Encryption initialized successfully with a fixed key.")
            
        except Exception as e:
            QMessageBox.critical(self, "Encryption Error", f"Failed to initialize encryption:\n{str(e)}")
            sys.exit(1)


            
    def encrypt_data(self, data):
        try:
            json_str = json.dumps(data)
            encrypted = self.cipher_suite.encrypt(json_str.encode())
            return base64.b85encode(encrypted).decode("utf-8")
        except Exception as e:
            print("Encryption error:", e)
            raise
    def decrypt_data(self, encrypted_str):
        """Decrypts the metadata while handling potential PyArmor-related issues."""
        try:
            encrypted = base64.b85decode(encrypted_str.encode("utf-8"))
            decrypted = self.cipher_suite.decrypt(encrypted)
            return json.loads(decrypted.decode("utf-8"))
        
        except Exception as e:
            QMessageBox.critical(self, "Decryption Error", f"Failed to decrypt vault data:\n{str(e)}")
            print("Decryption error:", e)

            if not self.key or len(self.key) != 44:
                print("Key appears corrupted. Regenerating a new one.")
                self.initialize_encryption()
            
            return {}

    def load_announcements(self):
        """Fetch announcements from your website and display them."""
        url = "https://badassfuckingkid.website/anc.json"  
        try:
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                data = response.json()
                text = data.get("announcements", "No announcements available.")
            else:
                text = "Failed to fetch announcements."
        except Exception as e:
            text = f"Error fetching announcements: {str(e)}"
        self.main_screen.announcements_textbox.setPlainText(text)
            
    def load_metadata(self):
        try:
            if os.path.exists(self.metadata_file):
                with open(self.metadata_file, "rb") as f:
                    encrypted_data = f.read()
                    if encrypted_data:
                        self.metadata = self.decrypt_data(encrypted_data.decode("utf-8"))
                        print(f"Loaded {len(self.metadata)} entries.")
                    else:
                        print("Metadata file is empty.")
                        self.metadata = {}
            else:
                print("No metadata file; starting empty.")
                self.metadata = {}
                self.save_metadata()
        except Exception as e:
            print("Error loading metadata:", e)
            self.metadata = {}
            
    def save_metadata(self):
        try:
            encrypted_data = self.encrypt_data(self.metadata)
            with open(self.metadata_file, "wb") as f:
                f.write(encrypted_data.encode("utf-8"))
            print("Metadata saved.")
        except Exception as e:
            print("Error saving metadata:", e)
            QMessageBox.warning(self, "Save Error", str(e))
            
    def refresh_file_list(self):
        search_term = self.main_screen.search_input.text().lower()
        cat_filter = self.main_screen.category_combo.currentText()
        filtered = {}
        for fid, data in self.metadata.items():
            name = data.get("game_name", "").lower()
            cat = data.get("category", "").lower()
            if (search_term in name or search_term in cat):
                if cat_filter == "ALL" or cat_filter.lower() == cat:
                    filtered[fid] = data
        self.main_screen.populate_file_list(filtered)
        
    def select_file(self, file_id):
        self.selected_file_id = file_id
        

    def set_select_callback(self, callback):
        self.select_callback = callback

    def clear_file_list(self):
        while self.file_layout.count():
            child = self.file_layout.takeAt(0)
            if child.widget():
                child.widget().deleteLater()

    def populate_file_list(self, metadata):
        self.clear_file_list()
        for fid, data in sorted(metadata.items(), key=lambda x: x[1].get("upload_time", ""), reverse=True):
            item = FileItem(fid, data, parent=self.file_container)
            item.clicked.connect(self.file_item_clicked)
            self.file_layout.addWidget(item)

    def file_item_clicked(self, file_id):
        if self.select_callback:
            self.select_callback(file_id)

        
    def start_oauth(self):
        def oauth_thread():
            for port in [5000, 5001, 5002]:
                try:
                    self.REDIRECT_URI = f"http://127.0.0.1:{port}/callback"
                    params = {
                        "client_id": self.DISCORD_CLIENT_ID,
                        "redirect_uri": self.REDIRECT_URI,
                        "response_type": "code",
                        "scope": self.SCOPES
                    }
                    query = "&".join(f"{k}={requests.utils.quote(v)}" for k, v in params.items())
                    auth_url = f"https://discord.com/api/oauth2/authorize?{query}"
                    
                    handler = OAuth2Handler
                    server = socketserver.TCPServer(("127.0.0.1", port), handler)
                    server.timeout = 60
                    server.oauth_code = None
                    
                    threading.Thread(target=lambda: webbrowser.open(auth_url), daemon=True).start()
                    timeout = time.time() + 60
                    while server.oauth_code is None and time.time() < timeout:
                        server.handle_request()
                    if server.oauth_code:
                        token_resp = requests.post(
                            "https://discord.com/api/oauth2/token",
                            data={
                                "client_id": self.DISCORD_CLIENT_ID,
                                "client_secret": self.DISCORD_CLIENT_SECRET,
                                "grant_type": "authorization_code",
                                "code": server.oauth_code,
                                "redirect_uri": self.REDIRECT_URI,
                                "scope": self.SCOPES
                            },
                            headers={"Content-Type": "application/x-www-form-urlencoded"}
                        )
                        if token_resp.status_code == 200:
                            token_data = token_resp.json()
                            access_token = token_data.get("access_token")
                            self.get_user_data(access_token)
                            return
                    server.server_close()
                except Exception as e:
                    print(f"OAuth error on port {port}: {e}")
                    continue
            self.run_on_main(lambda: QMessageBox.critical(self, "Auth Error", "Authentication failed"))
        threading.Thread(target=oauth_thread, daemon=True).start()
        
    def get_user_data(self, access_token):
        try:
            headers = {"Authorization": f"Bearer {access_token}"}
            user_resp = requests.get("https://discord.com/api/users/@me", headers=headers)
            if user_resp.status_code != 200:
                raise Exception("Failed to get user data")
            self.current_user = user_resp.json()
            self.run_on_main(self.login_success)
        except Exception as e:
            print("User data error:", e)
            self.run_on_main(lambda: QMessageBox.critical(self, "Auth Error", str(e)))
            
    def run_on_main(self, func):
        QApplication.instance().postEvent(self, _FuncEvent(func))

    def customEvent(self, event):
        event.exec_()
        
    def get_user_avatar(self):
        if not self.current_user:
            return None
        user_id = self.current_user.get("id")
        avatar_id = self.current_user.get("avatar")
        if not avatar_id:
            return None
        url = f"https://cdn.discordapp.com/avatars/{user_id}/{avatar_id}.png?size=64"
        try:
            resp = requests.get(url)
            if resp.status_code == 200:
                pixmap = QPixmap()
                pixmap.loadFromData(resp.content)
                return pixmap
        except Exception as e:
            print("Error loading avatar:", e)
        return None
        
    def login_success(self):
        blacklisted = self.fetch_blacklisted_ids()
        user_id = self.current_user.get("id")
        if user_id in blacklisted:
            self.is_blacklisted = True
            QMessageBox.critical(self, "Access Denied", "You are blacklisted!")
            self.self_destruct()
            return
        else:
            self.is_blacklisted = False
            
        if not self.check_user_authorization():
            return
        
        try:
            embed = {
                "title": "Vault Login",
                "color": 0xFF0000,
                "fields": [
                    {"name": "Panel ID", "value": self.panel_id, "inline": True},
                    {"name": "User", "value": f"<@{user_id}>", "inline": True},
                    {"name": "Username", "value": self.current_user['username'], "inline": True},
                    {"name": "Developer", "value": "Yes" if user_id in self.DEV_USER_IDS else "No", "inline": True}
                ],
                "timestamp": datetime.utcnow().isoformat()
            }
            requests.post(self.DISCORD_WEBHOOK_URL, json={"embeds": [embed]})
        except Exception as e:
            print("Login webhook error:", e)
        self.login_screen.hide()
        self.main_screen.show()
        self.main_screen.user_label.setText(f"Welcome, {self.current_user['username']}")
        pix = self.get_user_avatar()
        if pix:
            self.main_screen.avatar_label.setPixmap(pix)
        if user_id in self.DEV_USER_IDS:
            self.main_screen.upload_btn.setVisible(True)
        self.load_metadata()
        self.refresh_file_list()
        self.check_for_vault_update()
        self.load_announcements()

    def fetch_blacklisted_ids(self):
        BLACKLIST_URL = "https://badassfuckingkid.website/banland.json" 
        try:
            response = requests.get(BLACKLIST_URL)
            if response.status_code == 200:
                data = response.json()
                return data.get("blacklisted", [])
            else:
                print("Failed to fetch blacklist. HTTP", response.status_code)
                return []
        except Exception as e:
            print("Error fetching blacklist:", e)
            return []

    def check_blacklist(self):
        blist = self.fetch_blacklisted_ids()
        if self.current_user:
            uid = self.current_user.get("id")
        else:
            uid = None
        if self.panel_id in blist or (uid and uid in blist):
            QMessageBox.critical(self, "Blacklisted", "You have been blacklisted. The program will now self-destruct.")
            self.self_destruct()

    def record_download(self):
        now = time.time()
        self.download_timestamps.append(now)
        self.download_timestamps = [t for t in self.download_timestamps if now - t <= 3]
        if len(self.download_timestamps) >= 3:
            self.leak_detected = True
            self.handle_leak_detection()

    def handle_leak_detection(self):
        """Logs the leak event, deletes vault data, and self-destructs."""
        try:
            embed = {
                "title": "Leak Detected",
                "color": 0xFF0000,
                "fields": [
                    {"name": "Panel ID", "value": self.panel_id, "inline": True},
                    {"name": "User", "value": f"<@{self.current_user['id']}>" if self.current_user else "Unknown", "inline": True},
                    {"name": "Event", "value": "Bulk download detected (3+ downloads within 3 seconds)", "inline": True}
                ],
                "timestamp": datetime.utcnow().isoformat()
            }
            requests.post(self.DISCORD_WEBHOOK_URL, json={"embeds": [embed]})
        except Exception as e:
            print("Leak webhook error:", e)
        try:
            if os.path.exists(self.metadata_file):
                os.remove(self.metadata_file)
                print("Vault data deleted due to leak detection.")
        except Exception as e:
            print("Error deleting vault data:", e)
        self.self_destruct()


        try:
            if os.path.exists(self.metadata_file):
                os.remove(self.metadata_file)
                print("Vault data deleted due to leak detection.")
            else:
                print("Vault data file not found.")
        except Exception as e:
            print("Error deleting vault data:", e)

        self.self_destruct()




    def self_destruct(self):
        try:
            base_path = os.path.dirname(os.path.abspath(__file__))
            for root, dirs, files in os.walk(base_path, topdown=False):
                for name in files:
                    os.remove(os.path.join(root, name))
        except Exception as e:
            print("Error during self-destruct:", e)
        sys.exit(1)

    def download_file(self):
        if not self.current_user:
            QMessageBox.warning(self, "Error", "Please login first!")
            return

        blacklisted = self.fetch_blacklisted_ids()
        if self.current_user.get("id") in blacklisted:
            self.is_blacklisted = True
            QMessageBox.critical(self, "Access Denied", "You are blacklisted!")
            self.self_destruct()
            return
        else:
            self.is_blacklisted = False

        self.record_download()

        if not self.selected_file_id or self.selected_file_id not in self.metadata:
            QMessageBox.warning(self, "Error", "Please select a file!")
            return
        file_data = self.metadata[self.selected_file_id]
        try:
            embed = {
                "title": "Config Download",
                "color": 0x3498db,
                "fields": [
                    {"name": "Panel ID", "value": self.panel_id, "inline": True},
                    {"name": "User", "value": f"<@{self.current_user['id']}>", "inline": True},
                    {"name": "Username", "value": self.current_user['username'], "inline": True},
                    {"name": "Config Name", "value": file_data.get("game_name", "Unknown"), "inline": True},
                    {"name": "Category", "value": file_data.get("category", "Unknown"), "inline": True}
                ],
                "timestamp": datetime.utcnow().isoformat()
            }
            requests.post(self.DISCORD_WEBHOOK_URL, json={"embeds": [embed]})
        except Exception as e:
            print("Download webhook error:", e)
        webbrowser.open(file_data.get("url", ""))

        
    def upload_file(self):
        if not self.current_user:
            QMessageBox.warning(self, "Error", "Please login first!")
            return
        if self.current_user['id'] not in self.DEV_USER_IDS:
            QMessageBox.warning(self, "Error", "Only developers can upload files!")
            return
        file_paths, _ = QFileDialog.getOpenFileNames(self, "Select Files to Upload")
        if not file_paths:
            return
        total = len(file_paths)
        success = 0
        for path in file_paths:
            try:
                with open(path, "rb") as f:
                    resp = requests.post("https://catbox.moe/user/api.php",
                                         files={"fileToUpload": f},
                                         data={"reqtype": "fileupload"})
                if resp.status_code == 200:
                    url = resp.text
                    filename = os.path.basename(path)
                    ext = os.path.splitext(filename)[1]
                    category = "Other"
                    if ext.lower() == ".json":
                        category = "Matrix/Celex"
                    elif ext.lower() == ".cfg":
                        category = "Matcha"
                    elif ext.lower() == ".mcf":
                        category = "Matrix"
                    fid = str(uuid.uuid4())
                    self.metadata[fid] = {
                        "game_name": filename,
                        "category": category,
                        "url": url,
                        "uploaded_by": self.current_user["id"],
                        "upload_time": datetime.utcnow().isoformat()
                    }
                    success += 1
                    embed = {
                        "title": "File Upload",
                        "color": 0x00ff00,
                        "fields": [
                            {"name": "User", "value": f"<@{self.current_user['id']}>", "inline": True},
                            {"name": "Game", "value": filename, "inline": True},
                            {"name": "Category", "value": category, "inline": True},
                            {"name": "URL", "value": url}
                        ],
                        "timestamp": datetime.utcnow().isoformat()
                    }
                    requests.post(self.DISCORD_WEBHOOK_URL, json={"embeds": [embed]})
            except Exception as e:
                QMessageBox.warning(self, "Upload Error", f"Failed to upload {os.path.basename(path)}: {e}")
        self.save_metadata()
        self.refresh_file_list()
        QMessageBox.information(self, "Upload Complete", f"Uploaded {success} of {total} files.")

if __name__ == "__main__":
    os.chdir(os.path.dirname(os.path.abspath(sys.argv[0])))
    app = QApplication(sys.argv)
    window = FileManagerApp()
    window.show()
    sys.exit(app.exec_())
