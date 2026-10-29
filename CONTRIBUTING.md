# Как участвовать

## Локальный запуск

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
DEMO_MODE=1 uvicorn app.main:app --reload --port 8080
```

`DEMO_MODE=1` поднимает приложение на синтетических данных — реальный Graylog не нужен.
Откройте http://127.0.0.1:8080 (в демо-режиме вход не требуется).

## Тесты

```bash
pip install pytest
pytest -q tests
```

## Сборка образа

```bash
podman build -t sigma2graylog .
podman run --rm -p 8080:8080 -e DEMO_MODE=1 sigma2graylog
```

## Правила

- Одна задача — один pull request, с описанием «что и зачем».
- Новое поведение конвертации сопровождается тестом в `tests/`.
- Не коммитить `.env`, `settings.json`, `users.json`, `secret.key`, дампы и скриншоты
  с реальными адресами.
- Стиль: PEP 8, без внешних зависимостей там, где хватает стандартной библиотеки.
