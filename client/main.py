import sys
import json
import os
import threading
from pathlib import Path
import base64
from datetime import datetime

import requests
from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QTabWidget, QLabel, QPushButton, QLineEdit, QTextEdit,
    QMessageBox, QFrame, QDialog, QListWidget, QListWidgetItem,
    QScrollArea, QTableWidget, QTableWidgetItem, QHeaderView
)

from encryption import AESService
from auth import AuthDialog

from settings import SERVER_URL, APP_VERSION, BUILD_DATE, REQUEST_TIMEOUT, STATUS_TIMEOUT
from update_ui import UpdateTab


DARK_THEME = """
QWidget { background-color: #111827; color: #e5edf8; font-size: 13px; }
QMainWindow, QDialog { background-color: #111827; }
QFrame#panel { background-color: #1c283b; border: 1px solid #35445d; border-radius: 10px; }
QTabWidget::pane { background-color: #182335; border: 1px solid #35445d; border-radius: 8px; }
QTabBar::tab { background-color: #202d40; color: #b9c7db; padding: 11px 15px; border: 1px solid #35445d; border-bottom: none; margin-right: 2px; }
QTabBar::tab:selected { background-color: #345f9b; color: #ffffff; }
QLineEdit, QTextEdit, QPlainTextEdit, QListWidget, QTableWidget, QComboBox, QSpinBox {
    background-color: #0d1625; color: #e5edf8; border: 1px solid #42536d; border-radius: 6px;
    padding: 7px; selection-background-color: #345f9b; selection-color: white;
}
QLineEdit:focus, QTextEdit:focus, QListWidget:focus { border-color: #72a6f5; }
QListWidget::item:selected, QTableWidget::item:selected { background-color: #345f9b; color: white; }
QTableWidget { gridline-color: #35445d; alternate-background-color: #19263a; }
QHeaderView::section { background-color: #25344b; color: #e5edf8; padding: 7px; border: 1px solid #35445d; }
QPushButton { background-color: #293a53; color: #e5edf8; border: 1px solid #435875; border-radius: 6px; padding: 9px 12px; }
QPushButton:hover { background-color: #385478; }
QPushButton:pressed { background-color: #21334c; }
QPushButton#primary { background-color: #2866ba; color: white; border: none; font-weight: 600; padding: 12px; }
QPushButton#primary:hover { background-color: #367bd5; }
QPushButton#success { background-color: #187b52; color: white; border: none; font-weight: 600; padding: 12px; }
QPushButton#success:hover { background-color: #229765; }
QLabel#sectionTitle { font-size: 17px; font-weight: 600; color: #9ec7ff; }
QLabel#fieldLabel { color: #cbd7e8; }
QScrollArea { border: none; }
QScrollBar:vertical { background: #162237; width: 12px; }
QScrollBar::handle:vertical { background: #425875; border-radius: 5px; min-height: 25px; }
QToolTip { background: #263650; color: white; border: 1px solid #5374a1; }
"""

class BladeApp(QMainWindow):
    def __init__(self, token, login):
        super().__init__()
        self.crypto = AESService()
        self.encrypted_data = None
        self.received_data = None
        self.logs = []
        self.token = token
        self.login = login
        self.auth_headers = {"Authorization": f"Bearer {self.token}"}

        self.setWindowTitle("Средство предварительного шифрования текста — Blade")
        self.resize(1120, 780)
        self.setMinimumSize(950, 680)
        self.setup_ui()
        from updater import flush_installed_reports
        threading.Thread(target=flush_installed_reports, args=(self.token,), daemon=True).start()
        self.log(f"Blade v{APP_VERSION} запущен. Пользователь: {self.login}")

    def setup_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        root = QVBoxLayout(central)
        root.setContentsMargins(16, 12, 16, 14)
        root.setSpacing(10)

        header = QHBoxLayout()
        app_title = QLabel("🔒  Средство предварительного шифрования текста")
        app_title.setStyleSheet("font-size: 18px; font-weight: 600; color: #e8edf7;")
        version = QLabel(f"Blade v{APP_VERSION}")
        version.setStyleSheet(
            "font-size: 13px; font-weight: bold; color: #91baff;"
            "padding: 5px 10px; background: #243957; border-radius: 6px;"
        )
        header.addWidget(app_title)
        header.addStretch()
        header.addWidget(QLabel(f"Пользователь: {self.login}"))
        logout_button = QPushButton("Выйти")
        logout_button.setToolTip("Завершить текущую сессию и вернуться к авторизации")
        logout_button.clicked.connect(self.logout_user)
        header.addWidget(logout_button)
        about_button = QPushButton("О программе")
        about_button.clicked.connect(self.show_about_dialog)
        header.addWidget(about_button)
        header.addWidget(version)
        version.setToolTip(f"Дата сборки: {BUILD_DATE}")
        root.addLayout(header)

        self.tabs = QTabWidget()
        root.addWidget(self.tabs, 1)
        self.tabs.addTab(self.create_main_tab(), "✎  Шифрование")
        self.tabs.addTab(self.create_decryption_tab(), "↓  Получение и расшифрование")
        self.tabs.addTab(self.create_server_tab(), "▤  Статус сервера")
        self.tabs.addTab(self.create_log_tab(), "▤  Журнал")
        self.tabs.addTab(self.create_security_tab(), "🛡  Безопасность")
        self.update_tab = UpdateTab(lambda: self.token, self.log, self)
        self.update_tab.session_expired.connect(self._update_auth_expired)
        self.update_tab.install_started.connect(self._shutdown_for_update)
        self.tabs.addTab(self.update_tab, "⟳  Обновление ПО")

        self.setStyleSheet(DARK_THEME)


    def create_security_tab(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(12)
        title = QLabel("Проверка целостности и подлинности Blade")
        title.setObjectName("sectionTitle")
        layout.addWidget(title)
        info = QLabel("SHA-256 проверяет файлы по подписанному манифесту. ECDSA P-256 подтверждает подпись манифеста доверенным ключом разработчика.")
        info.setWordWrap(True)
        layout.addWidget(info)
        self.integrity_summary = QLabel("Проверка ещё не выполнялась")
        layout.addWidget(self.integrity_summary)
        self.integrity_table = QTableWidget(0, 3)
        self.integrity_table.setHorizontalHeaderLabels(["Файл", "Результат", "SHA-256 (фактический)"])
        self.integrity_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.integrity_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.integrity_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self.integrity_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        layout.addWidget(self.integrity_table)
        button = QPushButton("Проверить целостность и подпись")
        button.setObjectName("primary")
        button.clicked.connect(self.check_integrity)
        layout.addWidget(button)
        return page

    def check_integrity(self):
        from integrity import verify_installation
        report = verify_installation()
        self.integrity_table.setRowCount(0)
        for entry in report["files"]:
            row = self.integrity_table.rowCount()
            self.integrity_table.insertRow(row)
            for col, val in enumerate((entry["path"], entry["status"], entry["actual_hash"])):
                item = QTableWidgetItem(val)
                if entry["status"] == "OK":
                    item.setForeground(QColor("#63dba3"))
                else:
                    item.setForeground(QColor("#ff8585"))
                self.integrity_table.setItem(row, col, item)
        self.integrity_summary.setText(report["message"])
        self.integrity_summary.setStyleSheet("color: #63dba3; font-weight: bold;" if report["ok"] else "color: #ff8585; font-weight: bold;")
        self.log("Проверка целостности: " + report["message"])

    def make_panel(self, title):
        panel = QFrame()
        panel.setObjectName("panel")
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(14, 14, 14, 14)
        layout.setSpacing(9)
        heading = QLabel(title)
        heading.setObjectName("sectionTitle")
        layout.addWidget(heading)
        return panel, layout

    def field_label(self, text):
        label = QLabel(text)
        label.setObjectName("fieldLabel")
        return label

    def make_password_row(self, placeholder):
        row = QHBoxLayout()
        edit = QLineEdit()
        edit.setEchoMode(QLineEdit.EchoMode.Password)
        edit.setPlaceholderText(placeholder)
        toggle = QPushButton("◉")
        toggle.setFixedWidth(46)
        toggle.setToolTip("Показать или скрыть пароль")
        toggle.setCheckable(True)
        toggle.toggled.connect(
            lambda visible, field=edit, button=toggle:
            self.toggle_password(field, button, visible)
        )
        row.addWidget(edit, 1)
        row.addWidget(toggle)
        return edit, row

    def make_copy_row(self, edit):
        row = QHBoxLayout()
        edit.setReadOnly(True)
        button = QPushButton("▢")
        button.setFixedWidth(46)
        button.setToolTip("Копировать")
        button.clicked.connect(
            lambda checked=False, field=edit:
            self.copy_text(field.toPlainText())
        )
        row.addWidget(edit, 1)
        row.addWidget(button)
        return row

    def create_main_tab(self):
        page = QWidget()
        outer = QVBoxLayout(page)
        outer.setContentsMargins(12, 12, 12, 12)
        outer.setSpacing(10)
        top = QHBoxLayout()

        input_panel, left = self.make_panel("Ввод данных")
        left.addWidget(self.field_label("Текст для шифрования:"))
        self.message_input = QTextEdit()
        self.message_input.setPlaceholderText("Введите текст сообщения...")
        self.message_input.setMinimumHeight(145)
        left.addWidget(self.message_input)
        left.addWidget(self.field_label("Пароль шифрования:"))
        self.encrypt_password, password_row = self.make_password_row("Введите пароль")
        left.addLayout(password_row)
        encrypt_button = QPushButton("🔒  Зашифровать текст")
        encrypt_button.setObjectName("primary")
        encrypt_button.clicked.connect(self.encrypt_message)
        left.addWidget(encrypt_button)

        result_panel, right = self.make_panel("Результат шифрования")
        right.addWidget(self.field_label("Зашифрованный текст (Base64):"))
        self.ciphertext_output = QTextEdit()
        self.ciphertext_output.setPlaceholderText("Здесь появится шифротекст...")
        self.ciphertext_output.setFixedHeight(78)
        right.addLayout(self.make_copy_row(self.ciphertext_output))
        right.addWidget(self.field_label("Соль (Base64):"))
        self.salt_output = QTextEdit()
        self.salt_output.setFixedHeight(42)
        right.addLayout(self.make_copy_row(self.salt_output))
        right.addWidget(self.field_label("Nonce (Base64):"))
        self.nonce_output = QTextEdit()
        self.nonce_output.setFixedHeight(42)
        right.addLayout(self.make_copy_row(self.nonce_output))
        right.addWidget(self.field_label("Тег (Base64):"))
        self.tag_output = QTextEdit()
        self.tag_output.setFixedHeight(42)
        right.addLayout(self.make_copy_row(self.tag_output))
        send_button = QPushButton("☁  Отправить на сервер")
        send_button.setObjectName("success")
        send_button.clicked.connect(self.send_encrypted_data)
        right.addWidget(send_button)

        top.addWidget(input_panel, 1)
        top.addWidget(result_panel, 1)
        outer.addLayout(top, 4)

        bottom = QHBoxLayout()
        status_panel, status_layout = self.make_panel("Статус сервера")
        status_row = QHBoxLayout()
        self.status_indicator = QLabel("●")
        self.status_indicator.setStyleSheet("font-size: 24px; color: #8a99ad;")
        self.server_status = QLabel("Сервер ещё не проверен")
        status_text = QVBoxLayout()
        status_text.addWidget(self.server_status)
        status_text.addWidget(QLabel(SERVER_URL))
        check_button = QPushButton("⟳  Проверить")
        check_button.clicked.connect(self.check_server)
        status_row.addWidget(self.status_indicator)
        status_row.addLayout(status_text, 1)
        status_row.addWidget(check_button)
        status_layout.addLayout(status_row)

        log_panel, log_layout = self.make_panel("Последние действия")
        self.log_output = QTextEdit()
        self.log_output.setReadOnly(True)
        self.log_output.setMinimumHeight(100)
        self.log_output.setMaximumHeight(140)
        log_layout.addWidget(self.log_output)
        bottom.addWidget(status_panel, 1)
        bottom.addWidget(log_panel, 1)
        outer.addLayout(bottom, 1)
        return page

    def create_decryption_tab(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(18, 18, 18, 18)

        # Прокрутка нужна, чтобы новые элементы не обрезались на небольших экранах.
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        content = QWidget()
        content_layout = QVBoxLayout(content)
        content_layout.setContentsMargins(0, 0, 0, 0)

        panel, box = self.make_panel("Получение и расшифрование данных")
        box.addWidget(self.field_label("История сообщений (дата и время отправки):"))
        history_controls = QHBoxLayout()
        refresh = QPushButton("⟳  Обновить историю")
        refresh.clicked.connect(self.load_message_history)
        history_controls.addWidget(refresh)
        selected = QPushButton("↓  Получить выбранное сообщение")
        selected.clicked.connect(self.receive_selected_message)
        history_controls.addWidget(selected)
        box.addLayout(history_controls)

        self.message_list = QListWidget()
        self.message_list.setMinimumHeight(135)
        self.message_list.setToolTip("Выберите сообщение по номеру и времени отправки")
        self.message_list.itemDoubleClicked.connect(
            lambda item: self.receive_selected_message()
        )
        box.addWidget(self.message_list)

        receive_latest = QPushButton("Получить последнее сообщение")
        receive_latest.clicked.connect(self.receive_encrypted_data)
        box.addWidget(receive_latest)
        box.addWidget(self.field_label("Зашифрованные данные (JSON):"))
        self.received_output = QTextEdit()
        self.received_output.setReadOnly(True)
        self.received_output.setMinimumHeight(135)
        box.addWidget(self.received_output)

        box.addWidget(self.field_label("Пароль для расшифрования:"))
        self.decrypt_password, password_row = self.make_password_row(
            "Введите пароль, использованный при шифровании"
        )
        box.addLayout(password_row)
        decrypt = QPushButton("🔓  Расшифровать текст")
        decrypt.setObjectName("primary")
        decrypt.clicked.connect(self.decrypt_message)
        box.addWidget(decrypt)
        box.addWidget(self.field_label("Результат расшифрования:"))
        self.decrypted_output = QTextEdit()
        self.decrypted_output.setReadOnly(True)
        self.decrypted_output.setMinimumHeight(110)
        box.addWidget(self.decrypted_output)

        content_layout.addWidget(panel)
        scroll.setWidget(content)
        layout.addWidget(scroll)
        return page

    def create_server_tab(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(18, 18, 18, 18)
        panel, box = self.make_panel("Проверка доступности серверной части")
        box.addWidget(QLabel(f"Адрес сервера: {SERVER_URL}"))
        box.addWidget(QLabel(f"Версия Blade: {APP_VERSION}"))
        box.addWidget(QLabel(f"Дата сборки: {BUILD_DATE}"))
        self.server_tab_status = QLabel("Статус ещё не проверен.")
        box.addWidget(self.server_tab_status)
        button = QPushButton("Проверить соединение")
        button.clicked.connect(self.check_server)
        box.addWidget(button)
        box.addStretch()
        layout.addWidget(panel)
        return page

    def create_log_tab(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(18, 18, 18, 18)
        tabs = QTabWidget()
        layout.addWidget(tabs)

        local_page = QWidget()
        local_layout = QVBoxLayout(local_page)
        self.full_log_output = QTextEdit()
        self.full_log_output.setReadOnly(True)
        local_layout.addWidget(self.full_log_output)
        clear = QPushButton("Очистить локальный журнал")
        clear.clicked.connect(self.clear_log)
        local_layout.addWidget(clear)
        tabs.addTab(local_page, "События клиента")

        server_page = QWidget()
        server_layout = QVBoxLayout(server_page)
        description = QLabel("События безопасности текущего пользователя из JSON-файла сервера")
        server_layout.addWidget(description)
        refresh = QPushButton("⟳  Загрузить журнал безопасности")
        refresh.clicked.connect(self.load_security_logs)
        server_layout.addWidget(refresh)
        self.security_table = QTableWidget(0, 7)
        self.security_table.setHorizontalHeaderLabels([
            "Дата и время", "Источник", "Пользователь", "IP источника",
            "Статус", "Действие", "Описание"
        ])
        self.security_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.security_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.security_table.setAlternatingRowColors(True)
        self.security_table.horizontalHeader().setSectionResizeMode(
            QHeaderView.ResizeMode.ResizeToContents
        )
        self.security_table.horizontalHeader().setSectionResizeMode(
            6, QHeaderView.ResizeMode.Stretch
        )
        server_layout.addWidget(self.security_table)
        self.security_details = QTextEdit()
        self.security_details.setReadOnly(True)
        self.security_details.setMaximumHeight(135)
        self.security_details.setPlaceholderText("Выберите запись для просмотра всех полей")
        server_layout.addWidget(self.security_details)
        self.security_table.itemSelectionChanged.connect(self.show_security_details)
        tabs.addTab(server_page, "Журнал безопасности сервера")
        return page

    def load_security_logs(self):
        try:
            response = requests.get(
                f"{SERVER_URL}/security-logs", headers=self.auth_headers,
                params={"limit": 200}, timeout=REQUEST_TIMEOUT
            )
            if self.handle_auth_error(response):
                return
            response.raise_for_status()
            payload = response.json()
            if not isinstance(payload, dict) or not isinstance(payload.get("events"), list):
                raise ValueError("Сервер вернул неверный формат журнала")
            events = payload["events"]
            self.security_events = events
            self.security_table.setRowCount(len(events))
            for row, event in enumerate(events):
                values = [
                    event.get("event_datetime", ""), event.get("source_name", ""),
                    event.get("user_account", ""), event.get("source_ip", ""),
                    event.get("status", ""), event.get("action", ""),
                    event.get("description", "")
                ]
                status = str(event.get("status", "")).lower()
                action = str(event.get("action", "")).lower()
                level = str(event.get("level", "")).lower()
                if level == "critical":
                    color = QColor("#ffd5d5")
                elif status == "failure":
                    color = QColor("#ffe2e2")
                elif action == "delete":
                    color = QColor("#ffe3c2")
                elif action == "modify":
                    color = QColor("#fff3b8")
                elif status == "success":
                    color = QColor("#d9f5e2")
                else:
                    color = QColor("#dcecff")
                for col, value in enumerate(values):
                    cell = QTableWidgetItem(str(value or ""))
                    cell.setBackground(color)
                    # Цвет текста должен контрастировать со светлой заливкой.
                    # Цвет выделения строки задаётся общей тёмной темой.
                    cell.setForeground(QColor("#17243a"))
                    self.security_table.setItem(row, col, cell)
            self.security_details.clear()
            self.log(f"Загружено событий безопасности: {len(events)}")
        except (requests.RequestException, ValueError, TypeError) as exc:
            self.log(f"Ошибка чтения журнала безопасности: {exc}")
            QMessageBox.warning(self, "Ошибка журнала", str(exc))

    def show_security_details(self):
        row = self.security_table.currentRow()
        events = getattr(self, "security_events", [])
        if 0 <= row < len(events):
            self.security_details.setPlainText(
                json.dumps(events[row], ensure_ascii=False, indent=2)
            )

    def toggle_password(self, field, button, visible):
        field.setEchoMode(
            QLineEdit.EchoMode.Normal if visible else QLineEdit.EchoMode.Password
        )

    def copy_text(self, text):
        QApplication.clipboard().setText(text)
        self.log("Данные скопированы в буфер обмена.")

    def log(self, message):
        entry = f"{datetime.now().strftime('%H:%M:%S')}   {message}"
        self.logs.append(entry)
        if hasattr(self, "log_output"):
            self.log_output.append(entry)
        if hasattr(self, "full_log_output"):
            self.full_log_output.append(entry)

    def clear_log(self):
        self.logs.clear()
        if hasattr(self, "log_output"):
            self.log_output.clear()
        if hasattr(self, "full_log_output"):
            self.full_log_output.clear()
        self.log("Журнал интерфейса очищен.")

    def show_about_dialog(self):
        dlg = QDialog(self)
        dlg.setWindowTitle("О программе — Blade")
        dlg.setMinimumWidth(490)
        layout = QVBoxLayout(dlg)
        heading = QLabel(f"🔐  Blade v{APP_VERSION}")
        heading.setStyleSheet("font-size: 22px; font-weight: 700; color: #8fbcff;")
        layout.addWidget(heading)
        info = QLabel(
            "Средство предварительного шифрования текста\n\n"
            f"Версия: {APP_VERSION}\n"
            f"Дата сборки: {BUILD_DATE}\n\n"
            "Шифрование: AES-256-GCM\n"
            "Хеширование паролей: PBKDF2-HMAC-SHA256\n"
            "Контроль целостности: SHA-256\n"
            "Цифровая подпись: ECDSA P-256\n"
            "Авторизация: JWT HS256\n\n"
            "Учебный клиент-серверный проект по защите информации.\n"
            "Разработчик: указывается в документации проекта."
        )
        info.setWordWrap(True)
        layout.addWidget(info)
        close_button = QPushButton("Закрыть")
        close_button.clicked.connect(dlg.accept)
        layout.addWidget(close_button)
        dlg.exec()

    def _shutdown_for_update(self):
        """Close the GUI after handing control to the independent updater.

        The updater waits for this process to exit before renaming app/.
        This method does not revoke JWT or trigger the login dialog.
        """
        app = QApplication.instance()
        if app is None:
            return
        self.log("Передача установки внешнему процессу; завершение Blade.")
        app.setQuitOnLastWindowClosed(True)
        self.close()
        # Request Qt event-loop exit after the current button-click handler.
        QTimer.singleShot(0, app.quit)

    def closeEvent(self, event):
        if getattr(self, "update_tab", None) is not None and self.update_tab._busy:
            QMessageBox.information(self, "Проверка обновления",
                                    "Сначала дождитесь завершения проверки обновления.")
            event.ignore()
            return
        super().closeEvent(event)

    def _update_auth_expired(self):
        QMessageBox.warning(self, "Сессия завершена",
                            "Сессия истекла во время проверки обновлений. Войдите повторно.")
        self._return_to_login()

    def logout_user(self):
        """Отзывает токен на сервере и открывает форму входа."""
        if getattr(self, "update_tab", None) is not None and self.update_tab._busy:
            QMessageBox.information(self, "Проверка обновления",
                                    "Для выхода сначала дождитесь завершения проверки.")
            return
        if not self.token:
            return
        try:
            response = requests.post(
                f"{SERVER_URL}/logout", headers=self.auth_headers, timeout=REQUEST_TIMEOUT
            )
            if response.status_code not in (200, 401, 403):
                QMessageBox.warning(self, "Выход", "Сервер не подтвердил завершение сессии.")
                return
        except requests.RequestException:
            choice = QMessageBox.question(
                self, "Сервер недоступен",
                "Не удалось отозвать токен на сервере. Закрыть локальную сессию? "
                "Токен на сервере может оставаться действительным до истечения срока.",
            )
            if choice != QMessageBox.StandardButton.Yes:
                return
        self._return_to_login()

    def _return_to_login(self):
        if not self.token:
            return
        self.token = None
        self.auth_headers = {}
        self.encrypted_data = None
        self.received_data = None
        self.hide()
        self.close()
        # Открываем форму после завершения текущего обработчика Qt.
        QTimer.singleShot(0, show_login_window)

    def handle_auth_error(self, response):
        if response.status_code in (401, 403):
            self.log("Авторизация недействительна; требуется повторный вход.")
            QMessageBox.warning(
                self, "Сессия завершена",
                "Сессия истекла или сервер отклонил авторизацию. Войдите повторно."
            )
            self._return_to_login()
            return True
        return False

    @staticmethod
    def format_message_date(created_at):
        if not created_at:
            return "Время неизвестно"
        try:
            dt = datetime.fromisoformat(str(created_at).replace("Z", "+00:00"))
            return dt.astimezone().strftime("%d.%m.%Y %H:%M:%S")
        except (ValueError, TypeError):
            return str(created_at)

    def load_message_history(self):
        try:
            response = requests.get(
                f"{SERVER_URL}/messages",
                headers=self.auth_headers,
                timeout=REQUEST_TIMEOUT
            )
            if self.handle_auth_error(response):
                return
            response.raise_for_status()
            payload = response.json()
            if not isinstance(payload, dict):
                raise ValueError("Некорректный ответ сервера.")
            if payload.get("success") is False:
                raise ValueError(payload.get("error", "Не удалось загрузить историю."))
            messages = payload.get("messages", [])
            if not isinstance(messages, list):
                raise ValueError("Поле messages должно быть списком.")

            self.message_list.clear()
            for message in messages:
                if not isinstance(message, dict) or message.get("id") is None:
                    continue
                message_id = message["id"]
                date = self.format_message_date(message.get("created_at"))
                item = QListWidgetItem(f"Сообщение №{message_id}  |  {date}")
                item.setData(Qt.ItemDataRole.UserRole, message_id)
                self.message_list.addItem(item)

            if self.message_list.count() == 0:
                self.message_list.addItem("История сообщений пуста")

            self.log(f"История загружена: {self.message_list.count() if messages else 0} записей.")

        except (requests.RequestException, ValueError, TypeError) as exc:
            self.log(f"Ошибка загрузки истории: {exc}")
            QMessageBox.warning(self, "Ошибка загрузки истории", str(exc))

    def show_received_data(self, data):
        required = {"salt", "nonce", "ciphertext"}
        if not isinstance(data, dict) or not required.issubset(data):
            raise ValueError("Ответ сервера не содержит salt, nonce и ciphertext.")
        combined = base64.b64decode(data["ciphertext"], validate=True)
        if len(combined) < 16:
            raise ValueError("Полученный шифротекст слишком короткий.")

        # Для расшифрования используем отдельные данные, не подменяя
        # локально зашифрованный текст, который можно отправить на сервер.
        self.received_data = data
        self.received_output.setPlainText(
            json.dumps(data, indent=2, ensure_ascii=False)
        )
        self.decrypted_output.clear()

    def receive_selected_message(self):
        item = self.message_list.currentItem()
        if item is None:
            QMessageBox.warning(self, "Выбор сообщения", "Сначала выбери сообщение из истории.")
            return
        message_id = item.data(Qt.ItemDataRole.UserRole)
        if message_id is None:
            QMessageBox.warning(self, "Выбор сообщения", "Выбери сообщение с номером.")
            return

        try:
            response = requests.get(
                f"{SERVER_URL}/decrypt",
                params={"message_id": message_id},
                headers=self.auth_headers,
                timeout=REQUEST_TIMEOUT
            )
            if self.handle_auth_error(response):
                return
            response.raise_for_status()
            payload = response.json()
            if not isinstance(payload, dict):
                raise ValueError("Некорректный ответ сервера.")
            if payload.get("success") is False:
                raise ValueError(payload.get("error", "Не удалось получить сообщение."))
            self.show_received_data(payload.get("data", payload))
            self.log(f"Получено сообщение №{message_id}.")
        except (requests.RequestException, ValueError, KeyError, TypeError) as exc:
            self.log(f"Ошибка получения сообщения: {exc}")
            QMessageBox.critical(self, "Ошибка получения", str(exc))

    def encrypt_message(self):
        text = self.message_input.toPlainText()
        password = self.encrypt_password.text()
        if not text.strip():
            QMessageBox.warning(self, "Нет текста", "Введите текст для шифрования.")
            return
        if not password:
            QMessageBox.warning(self, "Нет пароля", "Введите пароль.")
            return

        try:
            data = self.crypto.encrypt(text, password)
            combined = base64.b64decode(data["ciphertext"], validate=True)
            if len(combined) < 16:
                raise ValueError("Результат AES-GCM слишком короткий.")
            ciphertext, tag = combined[:-16], combined[-16:]
            self.encrypted_data = data
            self.ciphertext_output.setPlainText(
                base64.b64encode(ciphertext).decode("ascii")
            )
            self.salt_output.setPlainText(data["salt"])
            self.nonce_output.setPlainText(data["nonce"])
            self.tag_output.setPlainText(base64.b64encode(tag).decode("ascii"))
            self.log("Текст успешно зашифрован.")
        except Exception as exc:
            self.log(f"Ошибка шифрования: {exc}")
            QMessageBox.critical(self, "Ошибка шифрования", str(exc))

    def send_encrypted_data(self):
        if not self.encrypted_data:
            QMessageBox.warning(self, "Нет данных", "Сначала зашифруйте текст.")
            return
        try:
            response = requests.post(
                f"{SERVER_URL}/encrypt",
                json=self.encrypted_data,
                headers=self.auth_headers,
                timeout=REQUEST_TIMEOUT
            )
            if response.status_code in (200, 201):
                self.log("Данные успешно отправлены на сервер.")
                QMessageBox.information(
                    self, "Успешно",
                    "Данные отправлены на сервер. Обнови историю сообщений."
                )
            else:
                if self.handle_auth_error(response):
                    return
                message = f"HTTP {response.status_code}: {response.text}"
                self.log(f"Ошибка отправки: {message}")
                QMessageBox.warning(self, "Ошибка сервера", message)
        except requests.RequestException as exc:
            self.log(f"Сервер недоступен: {exc}")
            QMessageBox.critical(self, "Ошибка соединения", str(exc))

    def receive_encrypted_data(self):
        try:
            response = requests.get(
                f"{SERVER_URL}/decrypt",
                headers=self.auth_headers,
                timeout=REQUEST_TIMEOUT
            )
            if self.handle_auth_error(response):
                return
            response.raise_for_status()
            payload = response.json()
            if not isinstance(payload, dict):
                raise ValueError("Некорректный ответ сервера.")
            if payload.get("success") is False:
                raise ValueError(payload.get("error", "Не удалось получить данные."))
            self.show_received_data(payload.get("data", payload))
            self.log("Последнее сообщение получено с сервера.")
        except (requests.RequestException, ValueError, KeyError, TypeError) as exc:
            self.log(f"Ошибка получения данных: {exc}")
            QMessageBox.critical(self, "Ошибка получения", str(exc))

    def decrypt_message(self):
        data = self.received_data
        if not data:
            QMessageBox.warning(
                self, "Нет данных",
                "Сначала получите сообщение с сервера."
            )
            return
        password = self.decrypt_password.text()
        if not password:
            QMessageBox.warning(self, "Нет пароля", "Введите пароль для расшифрования.")
            return
        try:
            plaintext = self.crypto.decrypt(data, password)
            self.decrypted_output.setPlainText(plaintext)
            self.log("Данные успешно расшифрованы.")
        except Exception:
            self.decrypted_output.clear()
            self.log("Ошибка расшифрования: неверный пароль или повреждённые данные.")
            QMessageBox.warning(
                self, "Ошибка расшифрования",
                "Проверьте пароль и целостность зашифрованных данных."
            )

    def check_server(self):
        try:
            response = requests.get(f"{SERVER_URL}/status", timeout=STATUS_TIMEOUT)
            response.raise_for_status()
            text = f"Сервер доступен (HTTP {response.status_code})"
            self.server_status.setText("Сервер доступен")
            self.status_indicator.setStyleSheet("font-size: 24px; color: #1e9b52;")
            if hasattr(self, "server_tab_status"):
                self.server_tab_status.setText(text + "\n" + response.text)
            self.log("Сервер доступен.")
        except requests.RequestException as exc:
            self.server_status.setText("Сервер недоступен")
            self.status_indicator.setStyleSheet("font-size: 24px; color: #d94343;")
            if hasattr(self, "server_tab_status"):
                self.server_tab_status.setText(f"Сервер недоступен: {exc}")
            self.log(f"Сервер недоступен: {exc}")


def show_login_window():
    app = QApplication.instance()
    auth_dialog = AuthDialog()
    if auth_dialog.exec() != QDialog.DialogCode.Accepted:
        app.quit()
        return
    window = BladeApp(token=auth_dialog.token, login=auth_dialog.login)
    app.blade_window = window  # сохраняем ссылку, чтобы Qt не удалил окно
    window.show()


def _schedule_update_health_check():
    """Tell the independent updater this build reached the Qt event loop.

    Does not claim the user has logged in, nor guarantee long-term stability.
    """
    flag = "--update-health-check"
    if flag not in sys.argv:
        return
    i = sys.argv.index(flag)
    if i + 2 >= len(sys.argv):
        return
    marker, nonce = Path(sys.argv[i + 1]), sys.argv[i + 2]
    from updater import APP_DATA_DIR
    allowed = (APP_DATA_DIR / "health").resolve()
    if not marker.resolve().is_relative_to(allowed) or marker.suffix != ".ready" or len(nonce) != 32:
        return
    def signal_ready():
        try:
            marker.parent.mkdir(parents=True, exist_ok=True)
            marker.write_text(json.dumps({"nonce": nonce, "status": "ready"}), encoding="utf-8")
        except OSError:
            pass
    QTimer.singleShot(1500, signal_ready)


def main():
    app = QApplication(sys.argv)
    app.setQuitOnLastWindowClosed(False)
    app.setStyleSheet(DARK_THEME)
    _schedule_update_health_check()
    show_login_window()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
