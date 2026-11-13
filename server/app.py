import re
import sqlite3
from pathlib import Path

from flask import Flask, jsonify, request
from update_service import updates_bp, init_update_tables

from auth import (
    hash_password, verify_password, create_session, get_session,
    delete_session, current_time
)
from database import init_database, get_connection
from security_policy import (init_login_limits, password_error, public_policy,
                             remaining_lock, record_failed_login, reset_failed_logins)
from logging_config import (
    setup_logging, log_event, load_config, cleanup_old_logs, read_security_events
)

app = Flask(__name__)
BASE_DIR = Path(__file__).resolve().parent
STORAGE_DIR = BASE_DIR.parent / "storage"
STORAGE_DIR.mkdir(parents=True, exist_ok=True)

SERVER_CONFIG = load_config()
security_logger = setup_logging()
init_database()
init_login_limits()
init_update_tables()
app.register_blueprint(updates_bp)


def get_device_id(data):
    device_id = data.get("device_id")
    if device_id is not None:
        if not isinstance(device_id, str) or not device_id.strip() or len(device_id) > 256:
            return None, False
    return device_id, True


def get_bearer_token():
    parts = request.headers.get("Authorization", "").split()
    if len(parts) == 2 and parts[0].lower() == "bearer":
        return parts[1]
    return None


def log_security_event(description, *, user_account="anonymous", status="info",
                       action="none", level="info", operation_start=None):
    log_event(
        security_logger, description,
        user_account=user_account,
        source_ip=request.remote_addr or "unknown",
        status=status, action=action, level=level,
        operation_start=operation_start,
    )


def require_session():
    session = get_session(get_bearer_token())
    if session is None:
        return None, (jsonify({
            "success": False,
            "error": "Требуется действующая авторизация",
        }), 401)
    return session, None


def validate_encrypted_payload(data):
    if not isinstance(data, dict):
        return "Ожидается JSON-объект"
    required = ("salt", "nonce", "ciphertext")
    if not all(field in data for field in required):
        return "Отсутствуют обязательные поля: salt, nonce, ciphertext"
    if not all(isinstance(data[field], str) and data[field] for field in required):
        return "Поля salt, nonce и ciphertext должны быть непустыми строками"
    # Avoid storing arbitrarily large request bodies in the database.
    if any(len(data[field]) > 2_000_000 for field in required):
        return "Размер зашифрованных данных превышает допустимый предел"
    return None


def message_to_dict(row):
    return {
        "id": row["id"],
        "salt": row["salt"],
        "nonce": row["nonce"],
        "ciphertext": row["ciphertext"],
        "created_at": row["created_at"],
    }


@app.route("/status", methods=["GET"])
def get_status():
    return jsonify({
        "success": True,
        "message": "Сервер работает",
        "version": SERVER_CONFIG.get("server", "version", fallback="1.0.0"),
    }), 200


@app.route("/auth-policy", methods=["GET"])
def get_auth_policy():
    return jsonify({"success": True, "policy": public_policy()}), 200


@app.route("/register", methods=["POST"])
def register():
    started = current_time()
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        log_security_event("Неудачная регистрация: некорректный JSON",
                          status="failure", action="register", level="warning",
                          operation_start=started)
        return jsonify({"success": False, "error": "Ожидается JSON-объект"}), 400

    login = data.get("login")
    password = data.get("password")
    device_id, valid_device = get_device_id(data)
    if not isinstance(login, str) or not isinstance(password, str) or not valid_device:
        return jsonify({"success": False, "error": "Некорректные данные регистрации"}), 400

    login = login.strip()
    if not re.fullmatch(r"[A-Za-z0-9_.-]{3,64}", login):
        return jsonify({"success": False, "error": (
            "Логин должен содержать 3–64 символа: латинские буквы, цифры, точку, "
            "дефис или подчёркивание"
        )}), 400
    error = password_error(password)
    if error:
        return jsonify({"success": False, "error": error}), 400

    password_hash, salt = hash_password(password)
    created = current_time()
    try:
        with get_connection() as connection:
            connection.execute("""
                INSERT INTO users (login, password_hash, salt, device_id, created_at, last_seen)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (login, password_hash, salt, device_id, created, created))
        log_security_event("Пользователь успешно зарегистрирован", user_account=login,
                          status="success", action="register", operation_start=started)
        return jsonify({"success": True, "message": "Регистрация успешно завершена"}), 201
    except sqlite3.IntegrityError:
        log_security_event("Неудачная регистрация: логин уже существует", user_account=login,
                          status="failure", action="register", level="warning",
                          operation_start=started)
        return jsonify({"success": False, "error": "Этот логин уже занят"}), 409
    except sqlite3.Error:
        app.logger.exception("Ошибка базы данных при регистрации")
        return jsonify({"success": False, "error": "Ошибка базы данных"}), 500


@app.route("/login", methods=["POST"])
def login():
    started = current_time()
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"success": False, "error": "Ожидается JSON-объект"}), 400

    login_name = data.get("login")
    password = data.get("password")
    device_id, valid_device = get_device_id(data)
    if not isinstance(login_name, str) or not isinstance(password, str) or not valid_device:
        return jsonify({"success": False, "error": "Некорректные данные входа"}), 400
    login_name = login_name.strip()
    # Ограничение выполняется до PBKDF2, в том числе для неизвестного логина.
    retry_after = remaining_lock(login_name)
    if retry_after:
        log_security_event('Вход заблокирован: превышено число попыток',
                           user_account=login_name, status='failure', action='login',
                           level='warning', operation_start=started)
        response = jsonify({'success': False, 'error':
            f'Слишком много попыток. Повторите через {retry_after} сек.',
            'retry_after': retry_after})
        response.headers['Retry-After'] = str(retry_after)
        return response, 429

    try:
        with get_connection() as connection:
            user = connection.execute("""
                SELECT id, login, password_hash, salt, device_id
                FROM users WHERE login = ?
            """, (login_name,)).fetchone()

            if user is None or not verify_password(password, user["password_hash"], user["salt"]):
                retry_after = record_failed_login(login_name)
                log_security_event("Неудачная аутентификация: неверные учётные данные",
                                  user_account=login_name, status="failure", action="login",
                                  level="warning", operation_start=started)
                if retry_after:
                    response = jsonify({'success': False, 'error':
                        f'Превышено число попыток. Вход заблокирован на {retry_after // 60} мин.',
                        'retry_after': retry_after})
                    response.headers['Retry-After'] = str(retry_after)
                    return response, 429
                return jsonify({"success": False, "error": "Неверный логин или пароль"}), 401

            saved_device = user["device_id"]
            if saved_device and saved_device != device_id:
                log_security_event("Вход отклонён: незнакомое устройство",
                                  user_account=login_name, status="failure", action="login",
                                  level="warning", operation_start=started)
                return jsonify({"success": False, "error": "Вход с незнакомого устройства"}), 403

            if not saved_device and device_id:
                connection.execute("UPDATE users SET device_id = ? WHERE id = ?",
                                  (device_id, user["id"]))
            connection.execute("UPDATE users SET last_seen = ? WHERE id = ?",
                              (current_time(), user["id"]))
            user_id, authenticated_login = user["id"], user["login"]

        reset_failed_logins(login_name)
        token = create_session(user_id, device_id)
        log_security_event("Пользователь успешно вошёл в систему",
                          user_account=authenticated_login, status="success",
                          action="login", operation_start=started)
        return jsonify({
            "success": True, "message": "Вход выполнен", "token": token,
            "expires_in": 1800, "user": {"id": user_id, "login": authenticated_login},
        }), 200
    except sqlite3.Error:
        app.logger.exception("Ошибка базы данных при входе")
        return jsonify({"success": False, "error": "Ошибка базы данных"}), 500


@app.route("/me", methods=["GET"])
def me():
    started = current_time()
    session, error = require_session()
    if error:
        log_security_event("Запрос профиля отклонён: отсутствующая или недействительная сессия",
                          status="failure", action="session_check", level="warning",
                          operation_start=started)
        return error
    return jsonify({
        "success": True,
        "user": {"id": session["user_id"], "login": session["login"]},
        "expires_at": session["expires_at"],
    }), 200


@app.route("/logout", methods=["POST"])
def logout():
    started = current_time()
    token = get_bearer_token()
    session = get_session(token)
    if session is None:
        return jsonify({"success": False, "error": "Сессия не найдена или уже завершена"}), 401
    delete_session(token)
    log_security_event("Пользователь вышел из системы", user_account=session["login"],
                       status="success", action="logout", operation_start=started)
    return jsonify({"success": True, "message": "Сессия завершена"}), 200


@app.route("/encrypt", methods=["POST"])
def save_encrypted_data():
    started = current_time()
    session, error = require_session()
    if error:
        log_security_event("Запись зашифрованных данных отклонена: нет авторизации",
                          status="failure", action="write", level="warning",
                          operation_start=started)
        return error

    data = request.get_json(silent=True)
    validation_error = validate_encrypted_payload(data)
    if validation_error:
        return jsonify({"success": False, "error": validation_error}), 400

    created_at = current_time()
    try:
        with get_connection() as connection:
            cursor = connection.execute("""
                INSERT INTO encrypted_messages
                    (user_id, salt, nonce, ciphertext, created_at)
                VALUES (?, ?, ?, ?, ?)
            """, (
                session["user_id"], data["salt"], data["nonce"],
                data["ciphertext"], created_at,
            ))
            message_id = cursor.lastrowid

        log_security_event(
            f"Зашифрованное сообщение сохранено (ID {message_id})",
            user_account=session["login"], status="success",
            action="write", operation_start=started,
        )
        return jsonify({
            "success": True,
            "message": "Зашифрованное сообщение сохранено",
            "message_id": message_id,
            "created_at": created_at,
        }), 201
    except sqlite3.Error:
        app.logger.exception("Не удалось сохранить зашифрованное сообщение")
        log_security_event("Ошибка сохранения зашифрованного сообщения",
                          user_account=session["login"], status="failure",
                          action="write", level="critical", operation_start=started)
        return jsonify({"success": False, "error": "Ошибка сохранения данных в базе"}), 500


@app.route("/messages", methods=["GET"])
def get_message_history():
    """Возвращает историю только текущего авторизованного пользователя."""
    started = current_time()
    session, error = require_session()
    if error:
        log_security_event("Чтение истории отклонено: нет авторизации",
                          status="failure", action="read", level="warning",
                          operation_start=started)
        return error

    try:
        limit_arg = request.args.get("limit", "100")
        try:
            limit = int(limit_arg)
        except (TypeError, ValueError):
            return jsonify({"success": False, "error": "limit должен быть числом"}), 400
        if limit < 1 or limit > 500:
            return jsonify({"success": False, "error": "limit должен быть от 1 до 500"}), 400

        with get_connection() as connection:
            rows = connection.execute("""
                SELECT id, salt, nonce, ciphertext, created_at
                FROM encrypted_messages
                WHERE user_id = ?
                ORDER BY id DESC
                LIMIT ?
            """, (session["user_id"], limit)).fetchall()

        messages = [message_to_dict(row) for row in rows]
        log_security_event(
            f"Получена история сообщений: {len(messages)} записей",
            user_account=session["login"], status="success",
            action="read", operation_start=started,
        )
        return jsonify({
            "success": True,
            "count": len(messages),
            "messages": messages,
        }), 200
    except sqlite3.Error:
        app.logger.exception("Не удалось получить историю сообщений")
        return jsonify({"success": False, "error": "Ошибка чтения истории из базы"}), 500


@app.route("/decrypt", methods=["GET"])
def get_encrypted_data():
    """
    Возвращает выбранное сообщение по message_id.
    Без message_id возвращает последнее сообщение для совместимости со старым клиентом.
    """
    started = current_time()
    session, error = require_session()
    if error:
        log_security_event("Чтение сообщения отклонено: нет авторизации",
                          status="failure", action="read", level="warning",
                          operation_start=started)
        return error

    message_id_arg = request.args.get("message_id")
    try:
        with get_connection() as connection:
            if message_id_arg is None:
                row = connection.execute("""
                    SELECT id, salt, nonce, ciphertext, created_at
                    FROM encrypted_messages
                    WHERE user_id = ?
                    ORDER BY id DESC
                    LIMIT 1
                """, (session["user_id"],)).fetchone()
            else:
                try:
                    message_id = int(message_id_arg)
                except ValueError:
                    return jsonify({"success": False, "error": "message_id должен быть числом"}), 400
                row = connection.execute("""
                    SELECT id, salt, nonce, ciphertext, created_at
                    FROM encrypted_messages
                    WHERE id = ? AND user_id = ?
                """, (message_id, session["user_id"])).fetchone()

        if row is None:
            return jsonify({"success": False, "error": "Сообщение не найдено"}), 404

        log_security_event(
            f"Получено зашифрованное сообщение (ID {row['id']})",
            user_account=session["login"], status="success",
            action="read", operation_start=started,
        )
        return jsonify({"success": True, "data": message_to_dict(row)}), 200
    except sqlite3.Error:
        app.logger.exception("Не удалось прочитать сообщение")
        log_security_event("Ошибка чтения сообщения",
                          user_account=session["login"], status="failure",
                          action="read", level="critical", operation_start=started)
        return jsonify({"success": False, "error": "Ошибка чтения данных из базы"}), 500


@app.route("/security-logs", methods=["GET"])
def get_security_logs():
    session, error = require_session()
    if error:
        return error
    try:
        cleanup_old_logs()
        requested = request.args.get("limit", "200")
        limit = max(1, min(int(requested), 500))
        events = read_security_events(session["login"], limit)
        return jsonify({"success": True, "count": len(events), "events": events})
    except (ValueError, OSError) as exc:
        app.logger.exception("Ошибка чтения журнала")
        return jsonify({"success": False, "error": "Не удалось прочитать журнал"}), 500


if __name__ == "__main__":
    app.run(
        host=SERVER_CONFIG.get("server", "host", fallback="127.0.0.1"),
        port=SERVER_CONFIG.getint("server", "port", fallback=5000),
        debug=SERVER_CONFIG.getboolean("server", "debug", fallback=False),
    )
