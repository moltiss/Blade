
from datetime import datetime

from logging_config import setup_logging, log_event


logger = setup_logging()

start_time = datetime.now().astimezone().isoformat(
    timespec="milliseconds"
)

log_event(
    logger,
    "Тестовая запись журнала Blade",
    user_account="test_user",
    source_ip="127.0.0.1",
    status="success",
    action="read",
    level="info",
    operation_start=start_time
)

log_event(
    logger,
    "Тестовая неудачная аутентификация",
    user_account="test_user",
    source_ip="127.0.0.1",
    status="failure",
    action="login",
    level="warning",
    operation_start=start_time
)

log_event(
    logger,
    "Тестовое изменение данных",
    user_account="test_user",
    source_ip="127.0.0.1",
    status="success",
    action="modify",
    level="info",
    operation_start=start_time
)

print("Тестовые события записаны.")
