"""Встроенная коллекция реальных Sigma-правил для кнопки «Пример».

Правила собраны из публичных рулсетов (SigmaHQ и производные) и приведены
к виду, который стабильно конвертируется нашим пайплайном.
"""
from __future__ import annotations

import random

SAMPLES: list[dict] = [
    {
        "source": "SigmaHQ / windows/process_creation",
        "yaml": r"""title: Suspicious PowerShell EncodedCommand
id: 2f5a1c3e-1b7d-4f2a-9d3e-8c1b0a7e5d44
status: test
description: PowerShell запущен с закодированной командой
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        Image|endswith:
            - '\\powershell.exe'
            - '\\pwsh.exe'
        CommandLine|contains:
            - ' -enc '
            - ' -encodedcommand '
            - ' -e '
    filter_main_generic:
        ParentImage|endswith: '\\explorer.exe'
    condition: selection and not filter_main_generic
falsepositives:
    - Легитимные скрипты администрирования
level: high"""
    },
    {
        "source": "SigmaHQ / windows/process_creation",
        "yaml": r"""title: Mimikatz Command Line
id: 0d894093-71bc-43c3-8c4d-ecfc28dcf5d9
status: test
description: Характерные аргументы mimikatz в командной строке
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        CommandLine|contains:
            - 'sekurlsa::logonpasswords'
            - 'sekurlsa::wdigest'
            - 'lsadump::sam'
            - 'kerberos::golden'
    condition: selection
falsepositives:
    - Тестирование пентеста
level: critical"""
    },
    {
        "source": "SigmaHQ / windows/process_creation",
        "yaml": r"""title: Certutil Download From URL
id: 2f6c1a8e-0d54-4b6a-9c8e-3f1a2b7c9d01
status: test
description: Загрузка файла через certutil (частый LOLBin-паттерн)
logsource:
    product: windows
    category: process_creation
detection:
    selection_img:
        Image|endswith: '\\certutil.exe'
    selection_cli:
        CommandLine|contains:
            - 'urlcache'
            - 'verifyctl'
    condition: all of selection*
falsepositives:
    - Корпоративные скрипты обновления
level: medium"""
    },
    {
        "source": "SigmaHQ / windows/process_creation",
        "yaml": r"""title: Suspicious Rundll32 Execution
id: 5f2c8a41-77ab-4d5e-9a13-6c0d1b8e4f22
status: experimental
description: rundll32 с подозрительными аргументами
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        Image|endswith: '\\rundll32.exe'
        CommandLine|contains:
            - 'javascript:'
            - 'shell32.dll,Control_RunDLL'
            - '\\AppData\\Local\\Temp\\'
    condition: selection
falsepositives:
    - Установщики приложений
level: medium"""
    },
    {
        "source": "SigmaHQ / windows/process_creation",
        "yaml": r"""title: Ntdsutil Export NTDS
id: 4b3f8c1d-2e9a-4c7b-8d5f-1a3b6c9e0f44
status: test
description: Попытка выгрузить базу домена через ntdsutil
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        Image|endswith: '\\ntdsutil.exe'
        CommandLine|contains: 'ntds'
    condition: selection
falsepositives:
    - Обслуживание контроллера домена
level: critical"""
    },
    {
        "source": "SigmaHQ / windows/process_creation",
        "yaml": r"""title: Suspicious Scheduler Task Creation
id: 7c1e4a2b-9d3f-4e8a-b6c1-2f5d8e0a3b77
status: experimental
description: Создание задачи планировщика через schtasks на выполнение из TEMP
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        Image|endswith: '\\schtasks.exe'
        CommandLine|contains:
            - '/create'
            - 'Temp\\'
    condition: selection
falsepositives:
    - Административные скрипты
level: medium"""
    },
    {
        "source": "SigmaHQ / linux/process_creation",
        "yaml": r"""title: Linux Reverse Shell Via Bash
id: 8e2b1f5c-3a7d-4b9e-8c1f-5d2a9b3e6c10
status: test
description: Признаки обратного шелла через bash
logsource:
    product: linux
    category: process_creation
detection:
    selection:
        CommandLine|contains:
            - 'bash -i >& /dev/tcp/'
            - 'sh -i >& /dev/tcp/'
            - 'nc -e /bin/sh'
            - 'socat exec:'
    condition: selection
falsepositives:
    - Скрипты резервного копирования
level: critical"""
    },
    {
        "source": "SigmaHQ / linux/file_event",
        "yaml": r"""title: Linux Sudoers File Modification
id: 9a4c7e21-6b8d-4f3a-9e2c-1d5b7a8c0f33
status: test
description: Изменение /etc/sudoers или файлов в sudoers.d
logsource:
    product: linux
    category: file_event
detection:
    selection:
        TargetFilename|startswith:
            - '/etc/sudoers'
            - '/etc/sudoers.d/'
    condition: selection
falsepositives:
    - Управление конфигурацией (Ansible/puppet)
level: high"""
    },
    {
        "source": "SigmaHQ / linux/auditd",
        "yaml": r"""title: Linux Suspicious Shell Execution via Auditd
id: 1b6d3f92-4c8e-4a7b-b5d1-3e9c2a6f8b55
status: experimental
description: Запуск шелла из нестандартного каталога (auditd execve)
logsource:
    product: linux
    service: auditd
detection:
    selection:
        type: 'EXECVE'
        a0|endswith:
            - '/sh'
            - '/bash'
    condition: selection
falsepositives:
    - Легитимные сервисы
level: medium"""
    },
    {
        "source": "SigmaHQ / windows/process_access",
        "yaml": r"""title: LSASS Memory Access By Uncommon Tool
id: 3d9b7a15-8e2c-4f6d-a1b4-7c5e9d0f2a88
status: experimental
description: Чтение памяти lsass процессом вне списка доверенных
logsource:
    product: windows
    category: process_access
detection:
    selection:
        TargetImage|endswith: '\\lsass.exe'
        GrantedAccess|contains: '0x1010'
    condition: selection
falsepositives:
    - Антивирусы и EDR
level: high"""
    },
    {
        "source": "SigmaHQ / windows/process_creation",
        "yaml": r"""title: Whoami Reconnaissance
id: 6f1a9d38-2c7b-4e5a-8b3d-9e0c4a1f7b66
status: experimental
description: Разведочные команды whoami/nltest в коротком интервале
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        Image|endswith:
            - '\\whoami.exe'
            - '\\nltest.exe'
    filter_system:
        User|endswith: '$'
    condition: selection and not filter_system
falsepositives:
    - Скрипты инвентаризации
level: low"""
    },
    {
        "source": "SigmaHQ / windows/process_creation",
        "yaml": r"""title: Suspicious WMI Execution
id: 2c8e5a47-1f3b-4d9a-8e6c-5b2a7f0d9c11
status: test
description: wmic используется для запуска процесса
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        Image|endswith: '\\wmic.exe'
        CommandLine|contains:
            - 'process call create'
            - 'node:'
    condition: selection
falsepositives:
    - Средства управления конфигурацией
level: medium"""
    },
]


def sample_at(index: int) -> dict:
    """Правило по индексу — нужен для воспроизводимых скриншотов и демонстраций."""
    return SAMPLES[index % len(SAMPLES)]



# --- второй блок примеров: Linux, macOS, сеть, облака, веб ---
SAMPLES += [
    {"source": "SigmaHQ / linux/process_creation", "yaml": """title: Base64 Encoded Shell Command
id: a1c4a8f2-1111-4b31-9e01-111111111111
status: test
description: Запуск команды, закодированной в base64, через shell
logsource:
    product: linux
    category: process_creation
detection:
    selection:
        Image|endswith:
            - '/bash'
            - '/sh'
        CommandLine|contains: 'base64 -d'
    condition: selection
level: high""" },
    {"source": "SigmaHQ / linux/process_creation", "yaml": """title: Curl Piped To Shell
id: a1c4a8f2-2222-4b31-9e01-222222222222
status: test
description: Скачивание и немедленное исполнение скрипта через curl
logsource:
    product: linux
    category: process_creation
detection:
    selection:
        CommandLine|contains:
            - 'curl '
            - 'wget '
        CommandLine|contains|all:
            - '|'
            - 'sh'
    condition: selection
level: critical""" },
    {"source": "SigmaHQ / linux/file_event", "yaml": """title: Cron File Modified
id: a1c4a8f2-3333-4b31-9e01-333333333333
status: test
description: Изменение файлов cron — типичный способ закрепления
logsource:
    product: linux
    category: file_event
detection:
    selection:
        TargetFilename|startswith:
            - '/etc/cron'
            - '/var/spool/cron'
    condition: selection
level: medium""" },
    {"source": "SigmaHQ / linux/auditd", "yaml": """title: Sudoers File Read
id: a1c4a8f2-4444-4b31-9e01-444444444444
status: test
description: Попытка чтения файла sudoers не-root пользователем
logsource:
    product: linux
    category: file_event
detection:
    selection:
        TargetFilename|startswith: '/etc/sudoers'
    condition: selection
level: low""" },
    {"source": "SigmaHQ / linux/process_creation", "yaml": """title: Suspicious Shell Spawn From Web Server
id: a1c4a8f2-5555-4b31-9e01-555555555555
status: test
description: Веб-сервер породил shell — признак веб-шелла
logsource:
    product: linux
    category: process_creation
detection:
    parent:
        ParentImage|endswith:
            - '/nginx'
            - '/httpd'
            - '/apache2'
    child:
        Image|endswith:
            - '/sh'
            - '/bash'
    condition: parent and child
level: critical""" },
    {"source": "SigmaHQ / linux/process_creation", "yaml": """title: Chmod SUID Bit Set
id: a1c4a8f2-6666-4b31-9e01-666666666666
status: test
description: Установка SUID-бита — повышение привилегий
logsource:
    product: linux
    category: process_creation
detection:
    selection:
        Image|endswith: '/chmod'
        CommandLine|contains|all:
            - '4755'
            - '/tmp/'
    condition: selection
level: high""" },
    {"source": "SigmaHQ / macos/process_creation", "yaml": """title: macOS Gatekeeper Bypass Via Xattr
id: a1c4a8f2-7777-4b31-9e01-777777777777
status: test
description: Снятие карантина с приложения — обход Gatekeeper
logsource:
    product: macos
    category: process_creation
detection:
    selection:
        Image|endswith: '/xattr'
        CommandLine|contains|all:
            - '-d'
            - 'com.apple.quarantine'
    condition: selection
level: high""" },
    {"source": "SigmaHQ / macos/process_creation", "yaml": """title: macOS LaunchAgent Persistence
id: a1c4a8f2-8888-4b31-9e01-888888888888
status: test
description: Создание агента автозапуска в LaunchAgents
logsource:
    product: macos
    category: file_event
detection:
    selection:
        TargetFilename|contains: '/Library/LaunchAgents/'
        TargetFilename|endswith: '.plist'
    condition: selection
level: medium""" },
    {"source": "SigmaHQ / windows/process_creation", "yaml": """title: Mshta Executing Remote Script
id: a1c4a8f2-9999-4b31-9e01-999999999999
status: test
description: Запуск удалённого сценария через mshta
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        Image|endswith: '\\mshta.exe'
        CommandLine|contains:
            - 'http://'
            - 'https://'
    condition: selection
level: high""" },
    {"source": "SigmaHQ / windows/process_creation", "yaml": """title: Suspicious WMIC Process Call
id: a1c4a8f2-aaaa-4b31-9e01-aaaaaaaaaaaa
status: test
description: Использование WMIC для запуска процесса — боковое перемещение
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        CommandLine|contains: 'process call create'
        Image|endswith: '\\wmic.exe'
    condition: selection
level: medium""" },
    {"source": "SigmaHQ / windows/process_creation", "yaml": """title: Credential Dump Via Comsvcs.dll
id: a1c4a8f2-bbbb-4b31-9e01-bbbbbbbbbbbb
status: test
description: Дамп памяти lsass через comsvcs.dll MiniDump
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        CommandLine|contains|all:
            - 'comsvcs'
            - 'MiniDump'
    condition: selection
level: critical""" },
    {"source": "SigmaHQ / windows/registry_set", "yaml": """title: Defender Exclusion Added
id: a1c4a8f2-cccc-4b31-9e01-cccccccccccc
status: test
description: Добавление исключения в Microsoft Defender
logsource:
    product: windows
    category: registry_set
detection:
    selection:
        TargetObject|contains: '\\Windows Defender\\Exclusions\\Paths\\'
    condition: selection
level: high""" },
    {"source": "SigmaHQ / windows/powershell", "yaml": """title: PowerShell Hidden Window
id: a1c4a8f2-dddd-4b31-9e01-dddddddddddd
status: test
description: Запуск PowerShell со скрытым окном
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        Image|endswith: '\\powershell.exe'
        CommandLine|contains:
            - ' -windowstyle hidden'
            - ' -w hidden'
    condition: selection
level: medium""" },
    {"source": "SigmaHQ / network", "yaml": """title: DNS Query To Suspicious TLD
id: a1c4a8f2-eeee-4b31-9e01-eeeeeeeeeeee
status: test
description: Обращение к домену в подозрительной зоне
logsource:
    category: dns_query
detection:
    selection:
        QueryName|endswith:
            - '.top'
            - '.xyz'
            - '.click'
    condition: selection
level: low""" },
    {"source": "SigmaHQ / network", "yaml": """title: Multiple Failed SSH Logins
id: a1c4a8f2-ffff-4b31-9e01-ffffffffffff
status: test
description: Серия неуспешных попыток входа по SSH
logsource:
    product: linux
    service: sshd
detection:
    selection:
        message|contains: 'Failed password'
    condition: selection
level: medium""" },
    {"source": "SigmaHQ / cloud", "yaml": """title: AWS Root Account Usage
id: a1c4a8f2-1010-4b31-9e01-101010101010
status: test
description: Использование root-учётной записи AWS
logsource:
    product: aws
    service: cloudtrail
detection:
    selection:
        userIdentity.type: Root
    condition: selection
level: high""" },
    {"source": "SigmaHQ / cloud", "yaml": """title: Azure MFA Disabled For User
id: a1c4a8f2-2020-4b31-9e01-202020202020
status: test
description: Отключение многофакторной аутентификации пользователю
logsource:
    product: azure
    service: auditlogs
detection:
    selection:
        operationName: 'Disable Strong Authentication'
    condition: selection
level: high""" },
    {"source": "SigmaHQ / web", "yaml": """title: Web Shell Access Path
id: a1c4a8f2-3030-4b31-9e01-303030303030
status: test
description: Обращение к типичному пути веб-шелла
logsource:
    category: webserver
detection:
    selection:
        cs-uri|contains:
            - '/shell.php'
            - '/cmd.jsp'
            - '/upload.aspx'
    condition: selection
level: high""" },
    {"source": "SigmaHQ / web", "yaml": """title: SQL Injection Attempt
id: a1c4a8f2-4040-4b31-9e01-404040404040
status: test
description: Признаки SQL-инъекции в строке запроса
logsource:
    category: webserver
detection:
    selection:
        cs-uri|contains:
            - 'union select'
            - "' or '1'='1"
            - 'information_schema'
    condition: selection
level: medium""" },
    {"source": "SigmaHQ / windows/process_creation", "yaml": """title: Remote Desktop To External Host
id: a1c4a8f2-5050-4b31-9e01-505050505050
status: test
description: Подключение по RDP на внешний адрес
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        Image|endswith: '\\mstsc.exe'
        CommandLine|contains: ' /v:'
    condition: selection
level: low""" },
]


def random_sample(exclude_titles: list[str] | None = None) -> dict:
    """Случайное правило, по возможности не из уже показанных."""
    exclude_titles = exclude_titles or []
    seen = {t.lower() for t in exclude_titles}
    fresh = [s for s in SAMPLES if _title(s).lower() not in seen]
    pool = fresh or SAMPLES
    choice = random.choice(pool)
    return {
        "yaml": choice["yaml"],
        "source": choice["source"],
        "title": _title(choice),
        "total": len(SAMPLES),
    }


def _title(sample: dict) -> str:
    for line in sample["yaml"].splitlines():
        if line.startswith("title:"):
            return line.split(":", 1)[1].strip()
    return "untitled"
