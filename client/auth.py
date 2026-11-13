import hashlib
import platform
import socket
import uuid

import requests

from PySide6.QtWidgets import (
    QDialog, QVBoxLayout, QTabWidget, QWidget, QLabel,
    QLineEdit, QPushButton, QMessageBox, QFormLayout
)

SERVER_URL = "http://127.0.0.1:5000"


def get_device_id():
    """Создаёт идентификатор устройства из базовых характеристик компьютера."""
    device_info = "|".join([
        socket.gethostname(),
        platform.system(),
        platform.release(),
        platform.machine(),
        str(uuid.getnode()),
    ])
    return hashlib.sha256(device_info.encode("utf-8")).hexdigest()


class AuthDialog(QDialog):
    def __init__(self):
        super().__init__()

        self.token = None
        self.login = None
        self.device_id = get_device_id()

        self.setWindowTitle("Blade — авторизация")
        self.setFixedSize(460, 365)

        root = QVBoxLayout(self)
        root.setContentsMargins(16, 14, 16, 16)
        root.setSpacing(10)

        title = QLabel("🔒 Blade v1.0")
        title.setObjectName("appTitle")
        root.addWidget(title)

        subtitle = QLabel("Войдите в систему или создайте учётную запись")
        subtitle.setObjectName("subtitle")
        subtitle.setWordWrap(True)
        root.addWidget(subtitle)

        self.tabs = QTabWidget()
        root.addWidget(self.tabs)

        # Вкладка входа
        self.login_page = QWidget()
        login_layout = QVBoxLayout(self.login_page)
        login_layout.setContentsMargins(12, 12, 12, 12)

        login_form = QFormLayout()
        login_form.setHorizontalSpacing(12)
        login_form.setVerticalSpacing(12)

        self.login_name = QLineEdit()
        self.login_name.setPlaceholderText("Введите логин")
        self.login_name.setMinimumHeight(38)

        self.login_password = QLineEdit()
        self.login_password.setPlaceholderText("Введите пароль")
        self.login_password.setEchoMode(QLineEdit.EchoMode.Password)
        self.login_password.setMinimumHeight(38)

        login_form.addRow("Логин:", self.login_name)
        login_form.addRow("Пароль:", self.login_password)
        login_layout.addLayout(login_form)

        login_button = QPushButton("Войти")
        login_button.setMinimumHeight(42)
        login_button.setDefault(True)
        login_button.clicked.connect(self.login_user)
        login_layout.addStretch()
        login_layout.addWidget(login_button)

        self.tabs.addTab(self.login_page, "Вход")

        # Вкладка регистрации
        self.register_page = QWidget()
        register_layout = QVBoxLayout(self.register_page)
        register_layout.setContentsMargins(12, 12, 12, 12)

        register_form = QFormLayout()
        register_form.setHorizontalSpacing(12)
        register_form.setVerticalSpacing(10)

        self.register_name = QLineEdit()
        self.register_name.setPlaceholderText("От 3 до 64 символов")
        self.register_name.setMinimumHeight(38)

        self.register_password = QLineEdit()
        self.register_password.setPlaceholderText("Требования загрузятся с сервера")
        self.register_password.setEchoMode(QLineEdit.EchoMode.Password)
        self.register_password.setMinimumHeight(38)

        self.confirm_password = QLineEdit()
        self.confirm_password.setPlaceholderText("Повторите пароль")
        self.confirm_password.setEchoMode(QLineEdit.EchoMode.Password)
        self.confirm_password.setMinimumHeight(38)

        register_form.addRow("Логин:", self.register_name)
        register_form.addRow("Пароль:", self.register_password)
        register_form.addRow("Повтор пароля:", self.confirm_password)
        self.password_policy_label = QLabel("Проверка требований пароля выполняется сервером")
        self.password_policy_label.setWordWrap(True)
        register_form.addRow("Требования:", self.password_policy_label)
        register_layout.addLayout(register_form)

        register_button = QPushButton("Зарегистрироваться")
        register_button.setMinimumHeight(42)
        register_button.clicked.connect(self.register_user)
        register_layout.addStretch()
        register_layout.addWidget(register_button)

        self.tabs.addTab(self.register_page, "Регистрация")
        self.load_password_policy()

        # Локальная тёмная тема окна авторизации.
        # Явные селекторы устраняют конфликт с глобальной темой приложения.
        self.setStyleSheet("""
            QDialog, QDialog QWidget {
                background-color: #111827;
                color: #e5edf8;
                font-size: 13px;
            }
            QDialog QLabel {
                background: transparent;
                color: #dce6f5;
            }
            QDialog QLabel#appTitle {
                color: #60a5fa;
                font-size: 22px;
                font-weight: 700;
            }
            QDialog QLabel#subtitle { color: #9fb0c8; }
            QDialog QTabWidget::pane {
                background: #172235;
                border: 1px solid #33445f;
                border-radius: 7px;
                top: -1px;
            }
            QDialog QTabBar::tab {
                background: #202d43;
                color: #bacbe1;
                border: 1px solid #33445f;
                padding: 10px 18px;
                margin-right: 3px;
                border-top-left-radius: 6px;
                border-top-right-radius: 6px;
            }
            QDialog QTabBar::tab:selected {
                background: #172235;
                color: #79b6ff;
                border-bottom-color: #172235;
                font-weight: 700;
            }
            QDialog QTabBar::tab:hover:!selected {
                background: #293c59;
            }
            QDialog QLineEdit {
                background: #0d1727;
                color: #f2f6fd;
                border: 1px solid #425571;
                border-radius: 7px;
                padding: 8px 11px;
                selection-background-color: #2563eb;
            }
            QDialog QLineEdit:focus { border: 1px solid #60a5fa; }
            QDialog QLineEdit:disabled { color: #718096; }
            QDialog QPushButton {
                background: #2563eb;
                color: #ffffff;
                border: 1px solid #3577f5;
                border-radius: 7px;
                padding: 10px;
                font-weight: 700;
            }
            QDialog QPushButton:hover { background: #3478f6; }
            QDialog QPushButton:pressed { background: #1d4ed8; }
        """)

    def login_user(self):
        login = self.login_name.text().strip()
        password = self.login_password.text()

        if not login or not password:
            QMessageBox.warning(
                self, "Не заполнены поля", "Введите логин и пароль."
            )
            return

        try:
            response = requests.post(
                f"{SERVER_URL}/login",
                json={
                    "login": login,
                    "password": password,
                    "device_id": self.device_id,
                },
                timeout=10,
            )

            try:
                data = response.json()
            except ValueError:
                data = {}

            if response.status_code != 200 or not data.get("success"):
                QMessageBox.warning(
                    self,
                    "Ошибка входа",
                    data.get("error", f"Сервер вернул HTTP {response.status_code}."),
                )
                return

            token = data.get("token")
            if not token:
                QMessageBox.critical(
                    self,
                    "Ошибка сервера",
                    "Сервер не вернул токен авторизации.",
                )
                return

            self.token = token
            self.login = login
            self.accept()

        except requests.RequestException as exc:
            QMessageBox.critical(
                self, "Нет соединения",
                f"Не удалось связаться с сервером:\n{exc}",
            )

    def load_password_policy(self):
        try:
            response = requests.get(f"{SERVER_URL}/auth-policy", timeout=3)
            response.raise_for_status()
            policy = response.json().get("policy", {})
            required = [f"От {policy.get('min_password_length', 10)} символов"]
            for key, label in (("require_uppercase", "заглавная буква"),
                               ("require_lowercase", "строчная буква"),
                               ("require_digit", "цифра"),
                               ("require_special", "спецсимвол")):
                if policy.get(key):required.append(label)
            self.password_policy_label.setText(", ".join(required))
            self.register_password.setPlaceholderText(required[0])
        except (requests.RequestException, ValueError):
            self.password_policy_label.setText("Требования проверит сервер при регистрации")

    def register_user(self):
        login = self.register_name.text().strip()
        password = self.register_password.text()
        confirmation = self.confirm_password.text()

        if not login or not password or not confirmation:
            QMessageBox.warning(
                self, "Не заполнены поля",
                "Заполните все поля регистрации.",
            )
            return

        if password != confirmation:
            QMessageBox.warning(
                self, "Пароли не совпадают",
                "Повторный пароль отличается от первого.",
            )
            return

        try:
            response = requests.post(
                f"{SERVER_URL}/register",
                json={
                    "login": login,
                    "password": password,
                    "device_id": self.device_id,
                },
                timeout=10,
            )

            try:
                data = response.json()
            except ValueError:
                data = {}

            if response.status_code not in (200, 201) or not data.get("success"):
                QMessageBox.warning(
                    self,
                    "Ошибка регистрации",
                    data.get("error", f"Сервер вернул HTTP {response.status_code}."),
                )
                return

            QMessageBox.information(
                self,
                "Регистрация завершена",
                "Учётная запись создана. Теперь войдите в систему.",
            )

            self.login_name.setText(login)
            self.login_password.clear()
            self.tabs.setCurrentIndex(0)
            self.login_password.setFocus()

        except requests.RequestException as exc:
            QMessageBox.critical(
                self, "Нет соединения",
                f"Не удалось связаться с сервером:\n{exc}",
            )
