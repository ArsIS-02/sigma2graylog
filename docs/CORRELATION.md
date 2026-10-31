# Корреляционные правила Sigma → агрегация Graylog

Конвертер понимает [корреляционные правила Sigma](https://sigmahq.io/docs/guide/correlations.html)
и превращает их в определение события Graylog с группировкой, функцией и порогом
(`aggregation-v1`).

## Что поддерживается

| Тип Sigma | Что создаётся в Graylog |
|---|---|
| `event_count` | серия `count()`, условие `count() <оператор> <порог>` |
| `value_count` (с `field`) | серия `card(<поле>)` — число уникальных значений |

Остальные типы (`temporal`, `temporal_ordered`, `value_sum`, `value_avg`, …) конвертер
отклоняет с понятным предупреждением, а не падает.

Переносится всё, что есть в правиле:

- `group-by` → `group_by` и `key_spec` определения (событие создаётся на каждое значение группы);
- `timespan` → `search_within_ms` (окно); проверка идёт раз в минуту, а для окна короче минуты — раз в окно;
- `condition` (`gt`, `gte`, `lt`, `lte`, `eq`, `neq`) → оператор и порог;
- запрос берётся из исходного правила, поля сопоставляются так же, как в обычном правиле;
- теги `attack.*` берутся с самого корреляционного правила, а если их нет — с исходного.

## Пример

```yaml
title: Failed Logon
name: failed_logon
logsource: {product: windows, service: security}
detection:
    selection: {EventID: 4625}
    condition: selection
---
title: Windows Logon Brute Force
correlation:
    type: event_count
    rules: [failed_logon]
    group-by: [IpAddress]
    timespan: 5m
    condition: {gte: 10}
tags: [attack.credential-access, attack.t1110]
level: high
```

Оба правила должны быть в одном входном тексте или файле. Исходное правило тоже появится в
результате (с пометкой): само по себе оно срабатывает на каждое событие, обычно создают
только агрегирующий детект.

Карточка результата показывает пилюлю «агрегация», например `count() >= 10 · 300s · by ipaddress`.

## Ограничения

- Псевдонимы полей (`aliases`) не учитываются, группировка идёт по именам из `group-by`.
- Если у исходного правила несколько запросов, в агрегацию берётся первый.
- Несколько исходных правил объединяются через `OR`.
