/* Руководство как данные: одна структура, два языка, рендер в #guide-root. */
(function () {
  const S = (ru, en) => ({ ru, en });

  const STEPS = [
    {
      n: '1', id: 'guide-1',
      title: S('Подключитесь к Graylog', 'Connect to Graylog'),
      lead: S('Вкладка <b>«Настройки»</b>. Укажите адрес Graylog и способ авторизации — сервисный пользователь с паролем или API-токен.',
              'The <b>Settings</b> tab. Enter the Graylog address and how to authenticate — a service user with a password, or an API token.'),
      img: 'g1-connection', marks: { ru: [{ x: 3.1, y: 11.3 }, { x: 3.1, y: 85.7 }], en: [{ x: 3.1, y: 11.3 }, { x: 3.1, y: 85.7 }] },
      bullets: [
        S('<b>1</b> — URL и авторизация. Публичный URL нужен для ссылок «в поиск» и «открыть детект».',
          '<b>1</b> — URL and credentials. The public URL is used for "open in search" and "open detection" links.'),
        S('<b>2</b> — «Проверить соединение» проверяет введённое <i>до сохранения</i> и показывает версию и число полей.',
          '<b>2</b> — "Test connection" validates what you typed <i>before saving</i> and shows the version and field count.'),
      ],
      tip: S('<b>Секреты</b> хранятся на сервере в зашифрованном виде и в браузер не возвращаются. Пустое поле при сохранении оставляет прежнее значение.',
             '<b>Secrets</b> are stored encrypted on the server and never returned to the browser. An empty field keeps the current value when saving.'),
    },
    {
      n: '2', id: 'guide-2',
      title: S('Возьмите Sigma-правило', 'Get a Sigma rule'),
      lead: S('Вкладка <b>«Конвертер»</b>. Правило можно получить четырьмя способами.',
              'The <b>Converter</b> tab. There are four ways to get a rule.'),
      img: 'g2-sources', marks: { ru: [{ x: 3.8, y: 53.0 }], en: [{ x: 3.8, y: 53.0 }] },
      bullets: [
        S('<b>1</b> — строка загрузки из каталога: «известные источники…» (SigmaHQ: все правила, core, master; ThreatHunting Keywords; SIGMA detection rules), фильтры по продукту и уровню, и кнопка <b>«Загрузить»</b> — качает набор (первый раз ~6 секунд), кэш на сутки.',
          '<b>1</b> — the catalog row: "known sources…" (SigmaHQ: all rules, core, master; ThreatHunting Keywords; SIGMA detection rules), filters by product and level, and the <b>Load</b> button — downloads the set (~6 seconds the first time), cached for a day.'),
        S('Ещё два пути: <b>«Пример ↻»</b> подставляет случайное правило из встроенных, а <b>«Файлы…» / «Папка…»</b> и drag&amp;drop берут ваши YAML, zip или tar.gz.',
          'Two more ways: <b>Sample ↻</b> inserts a random built-in rule, and <b>Files… / Folder…</b> plus drag&amp;drop take your YAML, zip or tar.gz.'),
      ],
    },
    {
      n: '3', id: 'guide-3',
      title: S('Сконвертируйте и прочитайте результат', 'Convert and read the result'),
      lead: S('Нажмите <b>«Конвертировать»</b> — справа появится запрос для Graylog.',
              'Press <b>Convert</b> — the Graylog query appears on the right.'),
      img: 'g3-result', marks: { ru: [{ x: 2.8, y: 64.2 }, { x: 2.8, y: 88.1 }], en: [{ x: 2.8, y: 67.4 }, { x: 2.8, y: 88.3 }] },
      bullets: [
        S('<b>1</b> — сам запрос. Кнопки <b>«копировать»</b> и <b>«в поиск ↗»</b> — вторая открывает готовый поиск в Graylog с нужным периодом и стримом.',
          '<b>1</b> — the query itself. The <b>copy</b> and <b>open in search ↗</b> buttons — the latter opens a ready-made Graylog search with the right period and stream.'),
        S('<b>2</b> — <b>«Создать детект»</b>. Рядом — «Проверить запрос» и «Прогон по истории».',
          '<b>2</b> — <b>Create detection</b>. Next to it: "Check query" and "Run over history".'),
        S('Цветные плашки над запросом — предупреждения: ненайденные поля, неоднозначный маппинг, переписанные модификаторы.',
          'Coloured chips above the query are warnings: missing fields, ambiguous mapping, rewritten modifiers.'),
      ],
      tip: S('Правило помечено производительным предупреждением? Это не ошибка — инструмент честно говорит, что <code>contains</code>/<code>endswith</code> пришлось перевести в regex, потому что ведущий wildcard Graylog не принимает.',
             'A rule flagged with a "heavy query" warning? That is not an error — the tool is telling you that <code>contains</code>/<code>endswith</code> had to become a regex, because Graylog rejects a leading wildcard.'),
    },
    {
      n: '4', id: 'guide-4',
      title: S('Проверьте сопоставление полей', 'Check the field mapping'),
      lead: S('Таблица под результатом показывает, какое поле Sigma во что превратилось и насколько инструмент уверен.',
              'The table below the result shows how each Sigma field was mapped and how confident the tool is.'),
      img: 'g4-mapping', marks: { ru: [{ x: 2.8, y: 67.0 }], en: [{ x: 2.8, y: 62.5 }] },
      bullets: [
        S('<b>1</b> — выпадающий список: можно выбрать другое поле вручную.',
          '<b>1</b> — the dropdown: pick a different field manually.'),
        S('Уверенность ниже 85% подсвечивается — стоит посмотреть глазами.',
          'Confidence below 85% is highlighted — worth a look.'),
        S('<b>«Запомнить маппинг»</b> сохраняет выбор и подставляет его в следующих конвертациях.',
          '<b>Remember mapping</b> saves the choice and reuses it in later conversions.'),
      ],
      tip: S('Поля нет вовсе (красное предупреждение)? Идём в шаг 7 — во вкладке «Стримы» видно, чего не хватает в вашем стриме и как это добавить.',
             'No such field at all (red warning)? Go to step 7 — the Streams tab shows what your stream is missing and how to add it.'),
    },
    {
      n: '5', id: 'guide-5',
      title: S('Прогоните правило по истории', 'Run the rule over history'),
      lead: S('Прежде чем создавать детект, посмотрите, как правило вело себя последние 30 дней.',
              'Before creating a detection, see how the rule behaved over the last 30 days.'),
      img: 'g5-history', marks: { ru: [{ x: 2.8, y: 40.9 }], en: [{ x: 2.8, y: 18.9 }] },
      bullets: [
        S('<b>1</b> — гистограмма по дням, сумма и максимум за сутки.',
          '<b>1</b> — a daily histogram, the total and the daily maximum.'),
        S('Вердикт: «не срабатывает ни разу» — правило смотрит не туда; «очень шумно» — это не детект, а поток.',
          'Verdict: "never matches" means the rule looks at the wrong thing; "very noisy" means it is a stream, not a detection.'),
        S('Ниже — три реальных события: по ним видно, что именно ловит правило.',
          'Below are three real events — they show exactly what the rule catches.'),
      ],
    },
    {
      n: '6', id: 'guide-6',
      title: S('Создайте детект', 'Create a detection'),
      lead: S('Один — кнопкой <b>«Создать детект»</b> в карточке правила. Пачку — через пакетный режим.',
              'One — with the <b>Create detection</b> button in the rule card. A batch — via batch mode.'),
      img: 'g7-detect', marks: { ru: [{ x: 2.0, y: 32.0 }], en: [{ x: 2.0, y: 32.0 }] },
      bullets: [
        S('В пакетном режиме таблица правил с фильтрами «все / готовые / с ошибками / high+».',
          'Batch mode shows a rule table with filters "all / ready / with errors / high+".'),
        S('Кнопка <b>«Создать выбранные»</b> спрашивает подтверждение и показывает отчёт «создано / пропущено дублей / ошибок».',
          'The <b>Create selected</b> button asks for confirmation and reports "created / skipped duplicates / errors".'),
        S('Дубли (совпадение ≥ 80% по запросу или названию) пропускаются автоматически.',
          'Duplicates (≥ 80% match by query or title) are skipped automatically.'),
        S('Созданные детекты видны во вкладке <b>«Детекты»</b> — там же поиск и удаление.',
          'Created detections appear in the <b>Detections</b> tab — with search and deletion.'),
      ],
      tip: S('Детект создаётся с <b>alert: false</b> и без уведомлений. Включить нотификации можно в самом Graylog — инструмент намеренно этого не делает.',
             'A detection is created with <b>alert: false</b> and no notifications. Enable them in Graylog itself — the tool deliberately does not.'),
    },
    {
      n: '7', id: 'guide-7',
      title: S('Разберитесь со стримами', 'Understand your streams'),
      lead: S('Вкладка <b>«Стримы»</b> показывает, насколько ваши данные вообще подходят для правил Sigma.',
              'The <b>Streams</b> tab shows how well your data fits Sigma rules in the first place.'),
      img: 'g6-streams', marks: { ru: [{ x: 1.7, y: 23.0 }, { x: 1.7, y: 76.5 }], en: [{ x: 1.7, y: 23.0 }, { x: 1.7, y: 76.5 }] },
      bullets: [
        S('<b>1</b> — стрим: продукт определён по полям, видно объём и число полей.',
          '<b>1</b> — a stream: the product is inferred from its fields, with volume and field count.'),
        S('<b>2</b> — покрытие типовых полей Sigma и ручной маппинг именно для этого стрима.',
          '<b>2</b> — coverage of common Sigma fields and manual mapping for this stream.'),
        S('У непокрытого поля есть кнопка <b>«сделать экстрактор»</b>: она собирает готовое правило pipeline для Graylog, которое создаёт недостающее поле.',
          'An uncovered field has a <b>create extractor</b> button: it builds a ready Graylog pipeline rule that creates the missing field.'),
      ],
      tip: S('Классический случай: в auditd путь разбит на <code>cwd</code> и <code>name</code>, поэтому <code>TargetFilename</code> не работает. Экстрактор собирает <code>file_path_full</code> из двух полей — и правило начинает находить события.',
             'A classic case: in auditd the path is split into <code>cwd</code> and <code>name</code>, so <code>TargetFilename</code> does not work. The extractor builds <code>file_path_full</code> from the two fields — and the rule starts finding events.'),
    },
  ];

  const CHIPS = {
    ru: ['1. Подключение', '2. Правило', '3. Конвертация', '4. Маппинг', '5. История', '6. Детект', '7. Стримы'],
    en: ['1. Connect', '2. Rule', '3. Convert', '4. Mapping', '5. History', '6. Detection', '7. Streams'],
  };

  const HEAD = {
    ru: { title: 'Как пользоваться', badge: '7 шагов · 5 минут',
          lead: 'Путь от подключения к Graylog до работающего детекта, который уже проверен на ваших данных. Всё, что нажимается, отмечено пульсирующими указателями.' },
    en: { title: 'How to use', badge: '7 steps · 5 minutes',
          lead: 'The path from connecting to Graylog to a working detection that is already validated on your data. Everything clickable is marked with pulsing pointers.' },
  };

  const TAIL = {
    ru: { title: 'Полезно знать', items: [
      'За раз конвертируется до <b>60</b> правил, загружается до <b>300</b>, создаётся до <b>50</b>.',
      'Вкладки доступны по ссылке: <code>#streams</code>, <code>#detect</code>, <code>#settings</code>, <code>#guide</code>.',
      'Регистронезависимость включается в настройках: буквы раскрываются в <code>[Pp]</code>.',
      'Фильтры и список полей кэшируются — «Обновить поля» в шапке сбрасывает кэш.',
    ], links: [['#settings', 'Перейти в настройки', 'Open settings'], ['#convert', 'К конвертеру', 'To converter'], ['#streams', 'К стримам', 'To streams']] },
    en: { title: 'Good to know', items: [
      'Up to <b>60</b> rules are converted at once, <b>300</b> loaded, <b>50</b> created.',
      'Tabs are linkable: <code>#streams</code>, <code>#detect</code>, <code>#settings</code>, <code>#guide</code>.',
      'Case-insensitivity is switched in settings: letters expand to <code>[Pp]</code>.',
      'Filters and the field list are cached — "Refresh fields" in the header clears the cache.',
    ], links: [['#settings', 'Open settings', 'Open settings'], ['#convert', 'To converter', 'To converter'], ['#streams', 'To streams', 'To streams']] },
  };

  function pick(pair, lang) { return pair && (pair[lang] || pair.ru); }

  function imgFor(base, lang) {
    return lang === 'en' ? `/static/guide/${base}.en.png` : `/static/guide/${base}.png`;
  }

  function render(lang) {
    const L = lang === 'en' ? 'en' : 'ru';
    const root = document.getElementById('guide-root');
    if (!root) return;
    const head = HEAD[L];
    const chips = CHIPS[L].map((label, i) =>
      `<a href="#guide-${i + 1}">${label}</a>`).join('');

    const steps = STEPS.map((s) => {
      const marks = (s.marks && (s.marks[L] || s.marks.ru)) || [];
      const halos = marks.map((m) =>
        `<span class="halo" style="left:${m.x}%;top:${m.y}%"></span>`).join('');
      const bullets = s.bullets.map((b) => `<li>${pick(b, L)}</li>`).join('');
      const tip = s.tip ? `<div class="tip">${pick(s.tip, L)}</div>` : '';
      return `<div class="step" id="${s.id}">
        <span class="num">${s.n}</span>
        <h3>${pick(s.title, L)}</h3>
        <p>${pick(s.lead, L)}</p>
        <div class="shot">
          <img src="${imgFor(s.img, L)}" data-src-ru="${imgFor(s.img, 'ru')}" data-src-en="${imgFor(s.img, 'en')}" alt="">
          ${halos}
        </div>
        <ul>${bullets}</ul>
        ${tip}
      </div>`;
    }).join('');

    const tail = TAIL[L];
    const tailItems = tail.items.map((t) => `<li>${t}</li>`).join('');
    const links = tail.links.map(([href, ru, en]) =>
      `<a class="btn-link" href="${href}">${L === 'en' ? en : ru}</a>`).join('');

    root.innerHTML = `
      <div class="guide-head">
        <h2>${head.title}</h2>
        <span class="badge">${head.badge}</span>
      </div>
      <p class="guide-lead">${head.lead}</p>
      <nav class="steps-nav">${chips}</nav>
      ${steps}
      <div class="step">
        <span class="num">✓</span>
        <h3>${tail.title}</h3>
        <ul>${tailItems}</ul>
        <div class="guide-foot">${links}</div>
      </div>`;
  }

  window.renderGuide = render;
  document.addEventListener('langchange', (e) => render(e.detail.lang));
  if (window.I18N) render(window.I18N.lang());
})();
