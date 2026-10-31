# Сторонние компоненты

Проект распространяется под GPL-3.0, но использует библиотеки других лицензий.
Ниже — что и на каких условиях.

| Компонент | Лицензия | Как используется |
|---|---|---|
| [pySigma](https://github.com/SigmaHQ/pySigma) | **LGPL-2.1-only** | библиотека, ставится через pip |
| [pySigma-backend-elasticsearch](https://github.com/SigmaHQ/pySigma-backend-elasticsearch) | **LGPL-3.0-only** | библиотека, ставится через pip |
| [FastAPI](https://github.com/fastapi/fastapi) | MIT | веб-фреймворк |
| [uvicorn](https://github.com/encode/uvicorn) | BSD-3-Clause | ASGI-сервер |
| [httpx](https://github.com/encode/httpx) | BSD-3-Clause | HTTP-клиент |
| [cryptography](https://github.com/pyca/cryptography) | Apache-2.0 / BSD-3-Clause | шифрование секретов |
| [PyYAML](https://github.com/yaml/pyyaml) | MIT | разбор YAML |
| [MITRE ATT&CK](https://attack.mitre.org/) | [условия использования MITRE](https://attack.mitre.org/resources/terms-of-use/) | названия тактик и техник v20 в `app/attack_v20.json` |
| [python-multipart](https://github.com/Kludex/python-multipart) | Apache-2.0 | загрузка файлов |

## Что это значит на практике

- Компоненты LGPL **не входят** в исходники проекта: они устанавливаются как зависимости
  из PyPI при сборке образа. Исходники pySigma доступны по ссылкам выше.
- Если вы распространяете собранный образ, приложите этот файл и ссылки на исходники
  LGPL-компонентов — этого достаточно для соблюдения LGPL при динамической линковке.
- Модифицировать код pySigma и при этом не публиковать изменения можно; если изменения
  касаются самой библиотеки и вы их распространяете — их нужно открыть под LGPL.
