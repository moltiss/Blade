"""Qt UI for signed updates and controlled external installation."""

from pathlib import Path
import sys
import os
import subprocess
import zipfile

from PySide6.QtCore import QObject, QThread, Signal, Slot
from PySide6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel,
                               QPushButton, QTextEdit, QFileDialog, QFrame, QMessageBox, QApplication)

from updater import UpdateCore, UpdateError
from settings import APP_VERSION


class UpdateWorker(QObject):
    progress = Signal(str)
    finished = Signal(str, object)
    failed = Signal(str, str, bool)

    def __init__(self, action, token, manifest_path=None):
        super().__init__()
        self.action = action
        self.token = token
        self.manifest_path = manifest_path

    @Slot()
    def run(self):
        core = UpdateCore()
        try:
            if self.action == "check":
                result = core.check_online(self.token)
            elif self.action == "download":
                result = core.prepare_online(self.token, progress=self.progress.emit)
            elif self.action == "offline":
                result = core.prepare_offline(self.manifest_path, progress=self.progress.emit)
            else:
                raise UpdateError("Неизвестная операция")
            self.finished.emit(self.action, result)
        except UpdateError as exc:
            self.failed.emit(self.action, str(exc), exc.auth_expired)
        except Exception as exc:
            # Do not expose full traceback, JWT, or server response to the UI.
            self.failed.emit(self.action, f"Непредвиденная ошибка: {exc}", False)


class UpdateTab(QWidget):
    session_expired = Signal()
    install_started = Signal()

    def __init__(self, token_provider, log_callback=None, parent=None):
        super().__init__(parent)
        self._get_token = token_provider
        self._log = log_callback
        self._thread = None
        self._worker = None
        self._busy = False
        self._pending_relogin = False
        self._verified_release = None
        self._can_install = False
        self._build_ui()

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(18, 18, 18, 18)
        layout.setSpacing(12)

        title = QLabel("Безопасное обновление Blade")
        title.setObjectName("sectionTitle")
        layout.addWidget(title)
        help_text = QLabel(
            "Проверка цифровой подписи Ed25519, контроль SHA-256 пакета и SBOM, "
            "сверка состава зависимостей и установка через отдельный процесс с откатом."
        )
        help_text.setWordWrap(True)
        layout.addWidget(help_text)

        summary = QFrame()
        summary.setObjectName("panel")
        box = QVBoxLayout(summary)
        self.current = QLabel(f"Установленная версия: Blade v{APP_VERSION}")
        box.addWidget(self.current)
        self.available = QLabel("Доступная версия: проверка ещё не выполнялась")
        box.addWidget(self.available)
        self.status = QLabel("Статус: готов к проверке")
        self.status.setWordWrap(True)
        box.addWidget(self.status)
        layout.addWidget(summary)

        online = QFrame()
        online.setObjectName("panel")
        online_box = QVBoxLayout(online)
        online_title = QLabel("🌐  Онлайн-обновление")
        online_title.setObjectName("sectionTitle")
        online_box.addWidget(online_title)
        online_row = QHBoxLayout()
        self.check_button = QPushButton("⟳  Проверить на сервере")
        self.check_button.clicked.connect(self.check_updates)
        self.download_button = QPushButton("↓  Скачать и проверить")
        self.download_button.setObjectName("primary")
        self.download_button.setEnabled(False)
        self.download_button.clicked.connect(self.download_update)
        online_row.addWidget(self.check_button)
        online_row.addWidget(self.download_button)
        online_box.addLayout(online_row)
        layout.addWidget(online)

        offline = QFrame()
        offline.setObjectName("panel")
        offline_box = QVBoxLayout(offline)
        offline_title = QLabel("📁  Офлайн-обновление")
        offline_title.setObjectName("sectionTitle")
        offline_box.addWidget(offline_title)
        offline_desc = QLabel(
            "В папке должны быть подписанный manifest.json, sbom.json и ZIP-пакет "
            "с именем, указанным в манифесте."
        )
        offline_desc.setWordWrap(True)
        offline_box.addWidget(offline_desc)
        self.offline_button = QPushButton("Выбрать manifest.json и проверить")
        self.offline_button.clicked.connect(self.select_offline_manifest)
        offline_box.addWidget(self.offline_button)
        layout.addWidget(offline)

        layout.addWidget(QLabel("Ход проверки и результат:"))
        self.detail = QTextEdit()
        self.detail.setReadOnly(True)
        self.detail.setPlaceholderText("Действия и результаты проверки появятся здесь…")
        layout.addWidget(self.detail, 1)
        self.install_button = QPushButton("Установить проверенное обновление и перезапустить")
        self.install_button.setObjectName("success")
        self.install_button.setEnabled(False)
        self.install_button.clicked.connect(self.install_verified)
        layout.addWidget(self.install_button)
        self.note = QLabel(
            "Установка доступна только в собранном Blade.exe (режим PyInstaller --onedir), "
            "если рядом с app/ находится BladeUpdater.exe. Исходники и демо ZIP не заменяются."
        )
        self.note.setWordWrap(True)
        self.note.setStyleSheet("color: #9db1cf;")
        layout.addWidget(self.note)

    def _append(self, message):
        self.detail.append(message)
        if self._log:
            self._log("Обновление ПО: " + message)

    def _set_busy(self, busy):
        self._busy = busy
        self.check_button.setEnabled(not busy)
        self.offline_button.setEnabled(not busy)
        self.download_button.setEnabled(not busy and getattr(self, "_can_download", False))
        self.install_button.setEnabled(not busy and self._can_install)

    def closeEvent(self, event):
        # Never destroy a live QThread along with the widget.
        if self._busy:
            event.ignore()
            return
        super().closeEvent(event)

    def _start(self, action, manifest_path=None):
        if self._busy:
            return
        self._verified_release = None
        self._can_install = False
        self.install_button.setEnabled(False)
        self._set_busy(True)
        if action != "download":
            self._can_download = False
            self.download_button.setEnabled(False)
        self.status.setText("Статус: выполняется проверка…")
        self._append(f"Начата операция: {action}")
        self._thread = QThread(self)
        self._worker = UpdateWorker(action, self._get_token(), manifest_path)
        self._worker.moveToThread(self._thread)
        self._thread.started.connect(self._worker.run)
        self._worker.progress.connect(self._append)
        self._worker.finished.connect(self._success)
        self._worker.failed.connect(self._failure)
        self._worker.finished.connect(self._thread.quit)
        self._worker.failed.connect(self._thread.quit)
        self._thread.finished.connect(self._worker.deleteLater)
        self._thread.finished.connect(self._thread.deleteLater)
        self._thread.finished.connect(self._thread_done)
        self._thread.start()

    def _thread_done(self):
        self._set_busy(False)
        self._worker = None
        self._thread = None
        if self._pending_relogin:
            self._pending_relogin = False
            self.session_expired.emit()

    def check_updates(self):
        self._start("check")

    def download_update(self):
        self._start("download")

    def select_offline_manifest(self):
        path, _ = QFileDialog.getOpenFileName(self, "Выберите подписанный manifest.json",
                                              str(Path.home()), "Манифест обновления (manifest.json)")
        if path:
            self._start("offline", path)

    def _success(self, action, result):
        self.status.setStyleSheet("color: #78e0b0; font-weight: 600;")
        if action == "check":
            if not result.get("update_available"):
                self.available.setText("Доступная версия: новых обновлений нет")
                self.status.setText("Статус: установлена актуальная опубликованная версия")
                self._can_download = False
                self.download_button.setEnabled(False)
                self._append("Сервер не предлагает новую версию.")
                return
            version = result["version"]
            self.available.setText(f"Доступная версия: Blade v{version}")
            if result.get("manual_install_required"):
                self.status.setStyleSheet("color: #ffb878; font-weight: 600;")
                self.status.setText("Статус: требуется ручная установка с нуля (min_supported)")
                self._can_download = False
                self.download_button.setEnabled(False)
                self._append("Автоматическое обновление запрещено из-за min_supported.")
            else:
                self.status.setText("Статус: обновление найдено; можно скачать и проверить")
                self._can_download = True
                self.download_button.setEnabled(True)
                self._append(f"Найдена версия {version}. Подлинность ещё не проверена.")
        else:
            self._can_download = False
            self.download_button.setEnabled(False)
            self.available.setText(f"Проверена версия: Blade v{result['version']}")
            self.status.setText("Статус: ✓ подпись, SHA-256 и состав SBOM проверены")
            self._append(
                f"УСПЕШНАЯ ПРОВЕРКА: v{result['version']}\n"
                f"ZIP: {result['package']}\n"
                f"Размер: {result['size']} байт; файлов: {result['files']}\n"
                f"SBOM: {result['sbom_components']} библиотек; ключевые: "
                + ", ".join(f"{k}=={v}" for k, v in result['key_dependencies'].items())
                + "\nПроверка завершена."
            )
            self._verified_release = result
            self._can_install = self._installation_prerequisites(result)
            self.install_button.setEnabled(self._can_install)
            if self._can_install:
                self._append("Пакет является установочным; доступна безопасная установка.")
            else:
                self._append("Установка недоступна: нужен собранный Blade.exe, BladeUpdater.exe и полный установочный ZIP.")

    def _failure(self, action, message, auth_expired):
        self.status.setStyleSheet("color: #ff8585; font-weight: 600;")
        self.status.setText("Статус: проверка не пройдена")
        self._can_download = False
        self._can_install = False
        self.install_button.setEnabled(False)
        self.download_button.setEnabled(False)
        self._append("ОШИБКА: " + message)
        if auth_expired:
            self._pending_relogin = True

    @staticmethod
    def _installation_prerequisites(result):
        if not getattr(sys, "frozen", False):
            return False
        exe = Path(sys.executable).resolve()
        root = exe.parent.parent
        if exe.name.lower() != "blade.exe" or exe.parent.name.lower() != "app":
            return False
        if not (root / "BladeUpdater.exe").is_file():
            return False
        try:
            with zipfile.ZipFile(result["package"]) as archive:
                names = set(archive.namelist())
                return "Blade.exe" in names and any(n.startswith("_internal/") for n in names)
        except (OSError, KeyError, zipfile.BadZipFile):
            return False

    def install_verified(self):
        release = self._verified_release
        if self._busy or release is None or not self._can_install:
            return
        if not self._installation_prerequisites(release):
            QMessageBox.warning(self, "Установка", "Не найдено установленного Blade.exe или внешнего установщика.")
            return
        yes = QMessageBox.question(
            self, "Установить обновление Blade?",
            f"Установить Blade v{release['version']}? Текущий Blade закроется, "
            "внешний установщик создаст backup/, заменит app/ и проверит запуск. "
            "При ошибке новая версия будет заменена предыдущей. "
            "Сначала сохраните важные данные и резервную копию приложения.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if yes != QMessageBox.StandardButton.Yes:
            return
        exe = Path(sys.executable).resolve()
        root = exe.parent.parent
        command = [str(root / "BladeUpdater.exe"),
                   "--install-root", str(root),
                   "--manifest", str(release["manifest_path"]),
                   "--sbom", str(release["sbom_path"]),
                   "--package", str(release["package"]),
                   "--from-version", APP_VERSION,
                   "--source", release.get("source", "offline"),
                   "--parent-pid", str(os.getpid())]
        try:
            subprocess.Popen(command, cwd=str(root), close_fds=True)
        except OSError as exc:
            QMessageBox.critical(self, "Установщик не запущен", str(exc))
            return
        self._append("Запущен внешний установщик. Blade закрывается…")
        self.install_started.emit()
