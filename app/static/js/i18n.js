/* Локализация интерфейса: русский и английский.
   Ключ словаря — исходная русская строка, поэтому разметку не нужно размечать ключами:
   переводчик проходит по текстовым узлам и заменяет совпавшие строки. */
(function () {
  const EN = {
    // --- вкладки и шапка ---
    'Конвертер': 'Converter',
    'Стримы': 'Streams',
    'Детекты': 'Detections',
    'Настройки': 'Settings',
    'Руководство': 'Guide',
    'Обновить поля': 'Refresh fields',
    'Обновить': 'Refresh',
    'Выйти': 'Sign out',
    'Аккаунт': 'Account',
    'Сменить пароль': 'Change password',
    'Смена пароля': 'Password change',
    'Текущий пароль': 'Current password',
    'Новый пароль (минимум 8 символов)': 'New password (at least 8 characters)',
    'Повторите новый пароль': 'Repeat new password',
    'Сохранить': 'Save',
    'Отмена': 'Cancel',
    'Закрыть': 'Close',
    'Очистить': 'Clear',
    'Пример ↻': 'Sample ↻',
    'Файлы…': 'Files…',
    'Папка…': 'Folder…',
    'По ссылке': 'From URL',
    'Загрузить': 'Load',
    'Загружаю…': 'Loading…',
    'Конвертировать': 'Convert',
    'Проверить в Graylog': 'Check in Graylog',
    'период:': 'period:',
    '1 час': '1 hour',
    '1 день': '1 day',
    '7 дней': '7 days',
    '30 дней': '30 days',
    'Sigma-правило': 'Sigma rule',
    'известные источники…': 'known sources…',
    'авто по продукту': 'auto by product',
    'продукт': 'product',
    'уровень': 'level',
    'все': 'all',
    'Результат': 'Result',
    'Экспорт CSV': 'Export CSV',
    'Экспорт JSON': 'Export JSON',
    'Пока ничего не сконвертировано.': 'Nothing converted yet.',
    'Вставьте Sigma-правило.': 'Paste a Sigma rule.',
    'Загрузка правил…': 'Loading rules…',

    // --- стримы ---
    'Анализ стримов': 'Stream analysis',
    'Пересканировать': 'Rescan',
    'фильтр по названию': 'filter by name',
    'Покрытие типовых полей Sigma': 'Coverage of common Sigma fields',
    'Поля стрима': 'Stream fields',
    'поле Sigma': 'Sigma field',
    'поле стрима': 'stream field',
    'уверенность': 'confidence',
    'Сохранить маппинг для стрима': 'Save mapping for stream',
    'сделать экстрактор': 'create extractor',
    'поиск поля': 'search field',
    'встречается': 'seen',
    'нет': 'no',

    // --- детекты ---
    'Детекты в Graylog': 'Detections in Graylog',
    'поиск по названию или описанию': 'search by name or description',
    'Описание': 'Description',
    'Название': 'Title',
    'Имя нового поля': 'New field name',
    'Разделитель': 'Separator',
    'Собрать из полей (через запятую, порядок важен)': 'Build from fields (comma-separated, order matters)',
    'Приоритет (1 — высокий, 4 — низкий)': 'Priority (1 — high, 4 — low)',
    'Экстрактор для поля': 'Extractor for field',
    'Правило pipeline для Graylog': 'Graylog pipeline rule',
    'Копировать правило': 'Copy rule',
    'Создать в Graylog': 'Create in Graylog',
    'Создать Event Definition': 'Create Event Definition',
    'Запрос': 'Query',

    // --- настройки ---
    'Подключение к Graylog': 'Graylog connection',
    'Адрес, по которому приложение ходит в API.': 'Address the app uses for API calls.',
    'Публичный URL': 'Public URL',
    'не задан — будет использован URL выше': 'not set — the URL above is used',
    'Подставляется в ссылки «открыть в Graylog». Должен резолвиться с рабочих машин.':
      'Used in "open in Graylog" links. Must resolve from your workstations.',
    'Авторизация': 'Authentication',
    'логин и пароль': 'username and password',
    'API-токен': 'API token',
    'Пользователь': 'Username',
    'Пароль': 'Password',
    'оставьте пустым, чтобы не менять': 'leave empty to keep current',
    'Кэш полей, сек': 'Fields cache, sec',
    'Период по умолчанию': 'Default period',
    'Regex без учёта регистра': 'Case-insensitive regex',
    'раскрывать буквы в классы': 'expand letters into classes',
    '— как в Sigma': '— like in Sigma',
    'Проверять дубликаты': 'Check duplicates',
    'предупреждать, если похожий детект уже есть': 'warn when a similar detection exists',
    'Проверить соединение': 'Test connection',
    'пароль не задан': 'password not set',
    'пароль задан': 'password set',
    'токен не задан': 'token not set',
    'токен задан': 'token set',

    // --- динамические сообщения ---
    'Требуется вход': 'Sign-in required',
    'Ошибка': 'Error',
    'ошибка': 'error',
    'инфо': 'info',
    'ок': 'ok',
    'не удалось': 'failed',
    'Ничего не найдено': 'Nothing found',
    'Правил не найдено.': 'No rules found.',
    'Правила загружены. Нажмите «Конвертировать».': 'Rules loaded. Press "Convert".',
    'Сканирую стримы (выборка по 100 событий)…': 'Scanning streams (100 events each)…',
    'Проверяю…': 'Checking…',
    'считаю по дням…': 'counting by day…',
    'совпадений нет — примеров не будет': 'no matches — no samples',
    'примеры событий:': 'sample events:',
    'Выберите источник правил': 'Choose a rule source',
    'В наборе не найдено Sigma-правил': 'No Sigma rules found in the set',
    'набор обрезан по лимиту': 'set truncated by limit',
    'Заполните все поля': 'Fill in all fields',
    'Новые пароли не совпадают': 'New passwords do not match',
    'Пароль короче 8 символов': 'Password is shorter than 8 characters',
    'Ничего не выбрано': 'Nothing selected',
    'Создать выбранные': 'Create selected',
    'Создаю…': 'Creating…',
    'Скачиваю…': 'Downloading…',
    'скачиваю источник (первый раз ~5–15 секунд)…': 'downloading source (first run ~5–15 seconds)…',
    'Похожий детект уже существует: ': 'A similar detection already exists: ',
    'Не удалось создать: ': 'Failed to create: ',
    'Не удалось сохранить: ': 'Failed to save: ',
    'Не удалось удалить: ': 'Failed to delete: ',
    'Не удалось обновить поля: ': 'Failed to refresh fields: ',
    'Не удалось подключиться: ': 'Failed to connect: ',
    'Пароль изменён. Он понадобится при следующем входе.': 'Password changed. You will need it on next sign-in.',
    'Сохранено. Кэш полей сброшен.': 'Saved. Fields cache cleared.',
    'Похожий детект уже есть: ': 'A similar detection already exists: ',
    'Удалить детект «': 'Delete detection "',
    '» из Graylog? Действие необратимо.': '" from Graylog? This cannot be undone.',
    'Запомнить маппинг': 'Remember mapping',
    'встроенный пример': 'built-in sample',
    'демо: ': 'demo: ',
    'загружаю ': 'loading ',
    'скачиваю ': 'downloading ',
    'файл(ов)…': 'file(s)…',
    'ошибка загрузки: ': 'upload error: ',
    'ошибка источника: ': 'source error: ',
    'ошибка загрузки папки: ': 'folder upload error: ',
    'в выбранной папке нет yaml-правил': 'no YAML rules in the selected folder',
    'загружаю перетащенные файлы…': 'loading dropped files…',
    'Вставьте правило и нажмите «Конвертировать».': 'Paste a rule and press "Convert".',
    'высокий': 'high',
    'средний': 'medium',
    'низкий': 'low',
    'готов': 'ready',
    'дубль': 'duplicate',
    'изменено вручную': 'changed manually',
    'не срабатывал': 'never matched',
    'без срабатываний': 'never matched',
    'срабатывали': 'matched',
    'всего: ': 'total: ',
    '· показано: ': '· shown: ',
    'стримов с событиями: ': 'streams with events: ',
    'выбрано: ': 'selected: ',
    'покрыто ': 'covered ',
    ' из ': ' of ',
    'полей: ': 'fields: ',
    'совпадений за период: ': 'matches in period: ',
    'стр. ': 'page ',
    'ссылка': 'url',
    'файлы': 'files',
    'папка': 'folder',
    'источник: ': 'source: ',
    'Источник: ': 'Source: ',
    'скопировано': 'copied',
    'сохранено': 'saved',
    'НЕТ': 'NONE',
    'нет запроса': 'no query',
    'пустой запрос': 'empty query',
    'запрос идентичен': 'identical query',
    'укажите хотя бы одно исходное поле': 'specify at least one source field',
    'Детект создан: ': 'Detection created: ',
    'Graylog: <b>нет связи</b>': 'Graylog: <b>no connection</b>',
    '· авторизация: ': '· auth: ',
    'Текущее подключение: ': 'Current connection: ',
    'проверяю…': 'checking…',
    'загружаю ${keep.length} файлов из папки…': 'loading ${keep.length} files from the folder…',
    'создано: ${s.created}, пропущено дублей: ${s.skipped}, ошибок: ${s.failed}':
      'created: ${s.created}, skipped duplicates: ${s.skipped}, errors: ${s.failed}',
    'покрыто ${d.covered} из ${d.total_checked}': 'covered ${d.covered} of ${d.total_checked}',
    'стримов с событиями: ${streamsState.items.length}': 'streams with events: ${streamsState.items.length}',
    'всего: <b>${d.total}</b> · без срабатываний: <b>${d.stats.never_matched}</b>':
      'total: <b>${d.total}</b> · never matched: <b>${d.stats.never_matched}</b>',
    'совпадений за период: <b>${d.total_results ?? \'?\'}</b>': 'matches in period: <b>${d.total_results ?? \'?\'}</b>',
    'полей: <b>': 'fields: <b>',
    'выбрано: <b>${n}</b>': 'selected: <b>${n}</b>',
    'стр. ${d.page} из ${pages}': 'page ${d.page} of ${pages}',

    // --- страница входа ---
    'Вход в систему': 'Sign in',
    'Введите учётные данные, выданные администратором.': 'Enter the credentials issued by your administrator.',
    'Имя пользователя': 'Username',
    'Показать пароль': 'Show password',
    'Войти': 'Sign in',
    'Проверяю…': 'Checking…',
    'Вход выполнен, перенаправляю…': 'Signed in, redirecting…',
    'Не удалось войти': 'Sign-in failed',
    'Graylog 7.x · поля индексов проверяются вживую': 'Graylog 7.x · index fields are validated live',
    'Sigma → детекты Graylog': 'Sigma → Graylog detections',

    // --- фрагменты, которые собирает JS ---
    '— нет поля —': '— no field —',
    'поле Graylog': 'Graylog field',
    'Сопоставление полей': 'Field mapping',
    'копировать': 'copy',
    'в поиск ↗': 'open in search ↗',
    'Проверить запрос': 'Check query',
    'Прогон по истории': 'Run over history',
    'Создать детект': 'Create detection',
    'готовые': 'ready',
    'с ошибками': 'with errors',
    'правило': 'rule',
    'стрим': 'stream',
    'статус': 'status',
    'открыть': 'open',
    'макс. в сутки:': 'daily max:',
    'Детект создан:': 'Detection created:',
    'событий:': 'events:',
    'полей:': 'fields:',
    '· полей:': '· fields:',
    'поле': 'field',
    '· без срабатываний:': '· never matched:',
    'открыть в Graylog': 'open in Graylog',
    'копировать запрос': 'copy query',
    'удалить': 'delete',
    '← назад': '← prev',
    'вперёд →': 'next →',
    '(запрос идентичен)': '(identical query)',
    'пример ': 'sample ',
    '· из кэша': '· cached',
    'стрим:': 'stream:',
    'совпадений нет — примеров не будет': 'no matches — no samples',
    'Правил: ': 'Rules: ',
    'Детектов: ': 'Detections: ',
    'Стримов: ': 'Streams: ',
    'Всего: ': 'Total: ',
    'Показать ещё': 'Show more',
    'Нет данных': 'No data',
    'Тип': 'Type',
    'Уровень': 'Level',
    'Продукт': 'Product',
    'Действия': 'Actions',

    'выборка': 'sample',
    'правил:': 'rules:',
    'файлов:': 'files:',
    'из': 'of',
    'и ещё': 'and more',
    'совпадение': 'match',
    'пропущено дублей:': 'skipped duplicates:',
    'полей в индексах:': 'fields in indexes:',
    'событий': 'events',
    'Нет поля': 'No field',
    'не покрыто': 'not covered',
    'покрыто': 'covered',
    '· событий:': '· events:',
    '· полей:': '· fields:',
    '· выборка:': '· sample:',
    '· авторизация:': '· auth:',
    'Для них можно выбрать поле вручную в таблице —': 'You can pick a field manually in the table —',
    'маппинг сохраняется для этого стрима и используется при конвертации правил этого продукта.':
      'the mapping is saved for this stream and used when converting rules for this product.',
    'событий:': 'events:',
    'Секреты хранятся на сервере в зашифрованном виде': 'Secrets are stored encrypted on the server',
    '(`/data/settings.json`, права 600) и в браузер не возвращаются.':
      '(`/data/settings.json`, mode 600) and never returned to the browser.',
    'Пустое поле оставляет прежнее значение.': 'An empty field keeps the current value.',
    // --- служебное ---
    'Секреты': 'Secrets',
    'sigma2graylog — на главную': 'sigma2graylog — home',
    'Перечитать список полей из Graylog': 'Reload the field list from Graylog',
    'Вставьте YAML Sigma-правила (можно несколько через ---)': 'Paste Sigma rule YAML (several separated by ---)',
    'https://… YAML, zip или tar.gz с правилами': 'https://… YAML, zip or tar.gz with rules',
  };

  // составные подписи вида «демо: <правило>» — переводим только префикс
  const PREFIXES = [
    ['демо: ', 'demo: '],
    ['стрим: ', 'stream: '],
    ['источник: ', 'source: '],
    ['Источник: ', 'Source: '],
    ['Текущее подключение: ', 'Current connection: '],
    ['· авторизация: ', '· auth: '],
    ['загружаю ', 'loading '],
    ['скачиваю ', 'downloading '],
    ['пример ', 'sample '],
  ];

  // составные строки с числами: шаблон -> английский вид ($1..$9)
  const PATTERNS = [
    [/^Не покрыто (\d+) типовых полей\.\s*Для них можно выбрать поле вручную в таблице — маппинг сохраняется для этого стрима и используется при конвертации правил этого продукта\.$/s, 'No coverage for $1 common fields. You can pick a field manually in the table — the mapping is saved for this stream and used when converting rules for this product.'],
    [/^Правил: (\d+), полей: (\d+)$/, 'Rules: $1, fields: $2'],
    [/^покрыто (\d+) из (\d+)$/, 'covered $1 of $2'],
    [/^создано: (\d+), пропущено дублей: (\d+), ошибок: (\d+)$/, 'created: $1, skipped duplicates: $2, errors: $3'],
    [/^стр\. (\d+) из (\d+)$/, 'page $1 of $2'],
    [/^· событий: (.*)$/, '· events: $1'],
    [/^· полей: (.*)$/, '· fields: $1'],
    [/^· выборка: (.*)$/, '· sample: $1'],
    [/^всего за (\d+) дн\.: (.*)$/, 'total over $1 days: $2'],
    [/^· авторизация: (.*)$/, '· auth: $1'],
    [/^загружено (\d+) правил(.*)$/, 'loaded $1 rules$2'],
    [/^пропущено (\d+)$/, 'skipped $1'],
    [/^\u2026 и ещё (\d+)$/, '… and $1 more'],
  ];

  const ATTRS = ['placeholder', 'title', 'aria-label'];
  const originals = new WeakMap();
  const attrOriginals = new WeakMap();
  const SKIP = new Set(['SCRIPT', 'STYLE', 'TEXTAREA', 'CODE', 'PRE']);

  let lang = 'ru';
  let observer = null;
  let translating = false;

  function dict() { return EN; }

  function t(text) {
    if (lang === 'ru' || typeof text !== 'string') return text;
    const hit = Object.prototype.hasOwnProperty.call(dict(), text) ? dict()[text] : null;
    return hit !== null ? hit : text;
  }

  function translateTextNode(node) {
    const value = node.nodeValue;
    if (!value || !/[А-Яа-яЁё]/.test(value)) return;
    if (node.parentElement && node.parentElement.closest('script,style,textarea,code,pre')) return;
    if (!originals.has(node)) originals.set(node, value);
    const base = originals.get(node);
    const lead = base.match(/^\s*/)[0];
    const trail = base.match(/\s*$/)[0];
    const core = base.trim();
    if (!core) return;
    if (lang === 'ru') { node.nodeValue = base; return; }
    let out = t(core);
    if (out === core) {
      for (const [re, repl] of PATTERNS) {
        if (re.test(core)) { out = core.replace(re, repl); break; }
      }
    }
    if (out === core) {
      for (const [ru, en] of PREFIXES) {
        if (core.startsWith(ru)) { out = en + core.slice(ru.length); break; }
      }
    }
    node.nodeValue = lead + out + trail;
  }

  function translateAttrs(root) {
    const els = root.querySelectorAll ? root.querySelectorAll('[' + ATTRS.join('],[') + ']') : [];
    els.forEach((el) => {
      if (!attrOriginals.has(el)) {
        const saved = {};
        ATTRS.forEach((a) => { if (el.hasAttribute(a)) saved[a] = el.getAttribute(a); });
        attrOriginals.set(el, saved);
      }
      const saved = attrOriginals.get(el);
      ATTRS.forEach((a) => {
        if (!(a in saved)) return;
        el.setAttribute(a, lang === 'ru' ? saved[a] : t(saved[a]));
      });
    });
  }

  function apply(root) {
    const scope = root || document.body;
    if (!scope) return;
    translating = true;
    if (observer) observer.disconnect();
    try {
      const walker = document.createTreeWalker(scope, NodeFilter.SHOW_TEXT);
      const nodes = [];
      while (walker.nextNode()) nodes.push(walker.currentNode);
      nodes.forEach(translateTextNode);
      translateAttrs(scope);
      document.documentElement.lang = lang;
      document.querySelectorAll('.lang-switch button').forEach((b) => {
        b.classList.toggle('active', b.dataset.lang === lang);
      });
    } finally {
      translating = false;
      if (observer) observer.observe(document.body, { childList: true, subtree: true, characterData: true });
    }
  }

  function setLang(next, opts) {
    lang = next === 'en' ? 'en' : 'ru';
    try { localStorage.setItem('s2g_lang', lang); } catch (e) { /* приватный режим */ }
    apply();
    if (document.dispatchEvent) document.dispatchEvent(new CustomEvent('langchange', { detail: { lang } }));
    if (!opts || opts.render !== false) {
      // перерисовываем то, что генерируется из данных
      if (window.renderGuide) window.renderGuide(lang);
      document.querySelectorAll('img[data-src-ru]').forEach((img) => {
        img.src = lang === 'en' && img.dataset.srcEn ? img.dataset.srcEn : img.dataset.srcRu;
      });
    }
  }

  function detectLang() {
    try {
      const saved = localStorage.getItem('s2g_lang');
      if (saved) return saved === 'en' ? 'en' : 'ru';
    } catch (e) { /* ignore */ }
    const q = new URLSearchParams(location.search).get('lang');
    if (q) return q === 'en' ? 'en' : 'ru';
    return 'ru';
  }

  function boot() {
    observer = new MutationObserver((list) => {
      if (translating || lang === 'ru') return;
      translating = true;
      observer.disconnect();
      try {
        list.forEach((m) => {
          if (m.type === 'childList') {
            m.addedNodes.forEach((n) => {
              if (n.nodeType === 3) translateTextNode(n);
              else if (n.nodeType === 1) apply(n);
            });
          } else if (m.type === 'characterData') {
            translateTextNode(m.target);
          }
        });
      } finally {
        translating = false;
        observer.observe(document.body, { childList: true, subtree: true, characterData: true });
      }
    });
    observer.observe(document.body, { childList: true, subtree: true, characterData: true });

    lang = detectLang();
    apply();
    if (window.renderGuide) window.renderGuide(lang);
    document.querySelectorAll('.lang-switch button').forEach((b) => {
      b.addEventListener('click', () => setLang(b.dataset.lang));
      b.classList.toggle('active', b.dataset.lang === lang);
    });
  }

  window.I18N = { t, apply, setLang, lang: () => lang, boot, has: (s) => Object.prototype.hasOwnProperty.call(dict(), s) };
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', boot);
  else boot();
})();
