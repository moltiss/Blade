
from auth import (
    hash_password,
    verify_password,
    create_session,
    get_session,
    delete_session
)
from database import init_database, get_connection


init_database()

# Генерируем хеш тестового пароля.
password_hash, salt = hash_password("Blade_Test_2026!")

print("Хеширование пароля:", "OK" if password_hash else "FAIL")
print("Проверка верного пароля:",
      verify_password("Blade_Test_2026!", password_hash, salt))
print("Проверка неверного пароля:",
      verify_password("WrongPassword!", password_hash, salt))

# Создаём временного тестового пользователя.
with get_connection() as connection:
    connection.execute(
        "DELETE FROM users WHERE login = ?",
        ("__blade_test__",)
    )

    cursor = connection.execute(
        """
        INSERT INTO users (
            login, password_hash, salt, created_at
        )
        VALUES (?, ?, ?, ?)
        """,
        (
            "__blade_test__",
            password_hash,
            salt,
            "2026-10-20T00:00:00+00:00"
        )
    )

    user_id = cursor.lastrowid

token = create_session(user_id, "test-device")
session = get_session(token)

print("Создание сессии:", session is not None)
print("Проверка токена:", session["login"] if session else "FAIL")
print("Завершение сессии:", delete_session(token))
print("Проверка удалённой сессии:", get_session(token) is None)

# Удаляем тестового пользователя после проверки.
with get_connection() as connection:
    connection.execute(
        "DELETE FROM users WHERE id = ?",
        (user_id,)
    )

print("Тестирование завершено.")
