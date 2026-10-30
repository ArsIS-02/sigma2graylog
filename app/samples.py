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
