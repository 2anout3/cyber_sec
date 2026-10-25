# Отчет о ДЗ. Поиск уязвимостей с помощью SAST-сканера

## 1. Описание внедренной уязвимости

[Ссылка на отчет о ДЗ 1](https://github.com/2anout3/cyber_sec/blob/main/practice/practice1/report.md)

## 2. Параметры запуска

| Параметр | Значение |
| --- | --- |
| Сканер | semgrep |
| Наборы правил | p/java|

Команды запуска:

```bash
docker run --rm -v "${PWD}/src:/src" -e SEMGREP_APP_TOKEN=44887e740cc7ca759d865856bd1b6c23534f5bab8bbb065d9145b34e53f8752e  semgrep/semgrep semgrep scan --config p/java --sarif --output /src/semgrep-report.sarif


docker run --rm -v "${PWD}/src:/src" -v "${PWD}/rules:/rules" -e SEMGREP_APP_TOKEN=44887e740cc7ca759d865856bd1b6c23534f5bab8bbb065d9145b34e53f8752e  semgrep/semgrep semgrep scan --config p/java --config /rules/rules.yaml --sarif --output /src/semgrep-report.sarif
```

Проверка покрытия: файл с уязвимостью присутствует в списке просканированных файлов, ошибок парсинга нет. 

Приложенные отчеты сканера:

- Уязвимая/исправленная версия: [`semgrep-report.sarif`](practice/practice1/demo/demoapplication/src/semgrep-report.sarif)
- Расширенная версия: [`semgrep-report-ext.sarif`](practice/practice1/demo/demoapplication/src/semgrep-report-ext.sarif)

## 3. Результаты сканирования

| Версия | Результат | Правило |
| --- | --- | --- |
| Уязвимая | FN | [`tainted-html-string`](https://github.com/semgrep/semgrep-rules/blob/16b9e6d45f10649f6a531ec4838ed9924372c3bc/java/spring/security/injection/tainted-html-string.yaml) |

### 3.1. Уязвимая версия

Обоснование классификации: FN, так как сканер не обнаружил уязвимость

### 3.2. Исправленная версия

Обоснование классификации: -

## 4. Анализ результатов

### Почему не найдена уязвимость
- **Покрывающее правило**: [tainted-html-string](https://github.com/semgrep/semgrep-rules/blob/16b9e6d45f10649f6a531ec4838ed9924372c3bc/java/spring/security/injection/tainted-html-string.yaml)
- **Причина рассхождения**: синк не входит в правило
- **Подробное объяснение**: 
Код:
``` java
@GetMapping(value = "/searchX", produces = MediaType.TEXT_HTML_VALUE)
    public String getXss(@RequestParam String query) {
        return "<html><body>" +
               "<h1>Result</h1>" +
               "<p>" + query + "</p>" +
               "</body></html>";
    }
```
Совпавшие источники:
``` yaml
  pattern-sources:
  - label: INPUT
    patterns:
    - pattern-either:
      - pattern-inside: |
          $METHODNAME(..., @$REQ(...) $TYPE $SOURCE,...) {
            ...
          }
      - pattern-inside: |
          $METHODNAME(..., @$REQ $TYPE $SOURCE,...) {
            ...
          }
    - metavariable-regex:
        metavariable: $TYPE
        regex: ^(?!(Integer|Long|Float|Double|Char|Boolean|int|long|float|double|char|boolean))
    - metavariable-regex:
        metavariable: $REQ
        regex: (RequestBody|PathVariable|RequestParam|RequestHeader|CookieValue|ModelAttribute)
    - focus-metavariable: $SOURCE
  - label: CONCAT
    by-side-effect: true
    requires: INPUT
    patterns:
    - pattern-either:
      - pattern: |
          "$HTMLSTR" + ...
      - pattern: |
          "$HTMLSTR".concat(...)
      - patterns:
        - pattern-inside: |
            StringBuilder $SB = new StringBuilder("$HTMLSTR");
            ...
        - pattern: $SB.append(...)
      - patterns:
        - pattern-inside: |
            $VAR = "$HTMLSTR";
            ...
        - pattern: $VAR += ...
      - pattern: String.format("$HTMLSTR", ...)
      - patterns:
        - pattern-inside: |
            String $VAR = "$HTMLSTR";
            ...
        - pattern: String.format($VAR, ...)
    - metavariable-regex:
        metavariable: $HTMLSTR
        regex: ^<\w+
```

Синк:
``` yaml
pattern-sinks:
  - requires: CONCAT
    patterns:
    - pattern-either:
      - pattern: new ResponseEntity<>($PAYLOAD, ...)
      - pattern: new ResponseEntity<$ERROR>($PAYLOAD, ...)
      - pattern: ResponseEntity. ... .body($PAYLOAD)
      - patterns:
        - pattern: |
            ResponseEntity.$RESPFUNC($PAYLOAD). ...
        - metavariable-regex:
            metavariable: $RESPFUNC
            regex: ^(ok|of)$
    - focus-metavariable: $PAYLOAD
```

Не полность совпал: `CONCAT` выполняется(`INPUT` + `"$HTMLSTR" + ...`), но отсутствует `ResponseEntity`


## 5. Доработка (если подходящего правила нет)

Выбранный вариант: А

### Вариант А. Собственное правило

Файл правила: [`rules.yaml`](practice/practice1/demo/demoapplication/rules/rules.yaml)

```yaml
rules:
- id: tainted-html-string
  languages:
  - java
  severity: ERROR
  message: >-
    Detected user input flowing into a manually constructed HTML string.
    You may be accidentally bypassing secure methods of rendering HTML by
    manually constructing HTML and this could create a cross-site scripting
    vulnerability, which could let attackers steal sensitive user data. To be
    sure this is safe, check that the HTML is rendered safely. You can use
    the OWASP ESAPI encoder if you must render user data.
  metadata:
    cwe:
    - "CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')"
    owasp:
    - A07:2017 - Cross-Site Scripting (XSS)
    - A03:2021 - Injection
    - A05:2025 - Injection
    references:
    - https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html
    category: security
    technology:
    - java
    - spring
    cwe2022-top25: true
    cwe2021-top25: true
    subcategory:
    - vuln
    likelihood: HIGH
    impact: MEDIUM
    confidence: MEDIUM
  mode: taint
  pattern-sources:
  - label: INPUT
    patterns:
    - pattern-either:
      - pattern-inside: |
          $METHODNAME(..., @$REQ(...) $TYPE $SOURCE,...) {
            ...
          }
      - pattern-inside: |
          $METHODNAME(..., @$REQ $TYPE $SOURCE,...) {
            ...
          }
    - metavariable-regex:
        metavariable: $TYPE
        regex: ^(?!(Integer|Long|Float|Double|Char|Boolean|int|long|float|double|char|boolean))
    - metavariable-regex:
        metavariable: $REQ
        regex: (RequestBody|PathVariable|RequestParam|RequestHeader|CookieValue|ModelAttribute)
    - focus-metavariable: $SOURCE
  - label: CONCAT
    by-side-effect: true
    requires: INPUT
    patterns:
    - pattern-either:
      - pattern: |
          "$HTMLSTR" + ...
      - pattern: |
          "$HTMLSTR".concat(...)
      - patterns:
        - pattern-inside: |
            StringBuilder $SB = new StringBuilder("$HTMLSTR");
            ...
        - pattern: $SB.append(...)
      - patterns:
        - pattern-inside: |
            $VAR = "$HTMLSTR";
            ...
        - pattern: $VAR += ...
      - pattern: String.format("$HTMLSTR", ...)
      - patterns:
        - pattern-inside: |
            String $VAR = "$HTMLSTR";
            ...
        - pattern: String.format($VAR, ...)
    - metavariable-regex:
        metavariable: $HTMLSTR
        regex: ^<\w+
  pattern-propagators:
  - pattern: (StringBuilder $SB).append($...TAINTED)
    from: $...TAINTED
    to: $SB
  - pattern: $VAR += $...TAINTED
    from: $...TAINTED
    to: $VAR
  pattern-sinks:
  - requires: CONCAT
    patterns:
    - pattern-either:
      - pattern: new ResponseEntity<>($PAYLOAD, ...)
      - pattern: new ResponseEntity<$ERROR>($PAYLOAD, ...)
      - pattern: ResponseEntity. ... .body($PAYLOAD)
      - patterns:
        - pattern: |
            ResponseEntity.$RESPFUNC($PAYLOAD). ...
        - metavariable-regex:
            metavariable: $RESPFUNC
            regex: ^(ok|of)$
    - focus-metavariable: $PAYLOAD
  - requires: CONCAT
    patterns:
    - pattern-either:
      - pattern-inside: |
          @GetMapping(...)
          $RET $METHOD(...) { ... }
      - pattern-inside: |
          @PostMapping(...)
          $RET $METHOD(...) { ... }
      - pattern-inside: |
          @RequestMapping(...)
          $RET $METHOD(...) { ... }
    - metavariable-regex:
        metavariable: $RET
        regex: ^(?!ResponseEntity)
    - pattern: return $X;
    - focus-metavariable: $X
  pattern-sanitizers:
  - pattern-either:
    - pattern: Encode.forHtml(...)
    - pattern: (PolicyFactory $POLICY).sanitize(...)
    - pattern: (AntiSamy $AS).scan(...)
    - pattern: JSoup.clean(...)
```

Доработанное `tainted-html-string` правило

Логика правила:

- **Источник:** источник двухступенчатый. Сначала метку INPUT получают параметры контроллера Spring, принимающие данные из HTTP-запроса, кроме числовых и логических типов. Затем метку CONCAT получает строка, в которой такой ввод склеивается с HTML-литералом, начинающимся с открывающего тега
- **Синк:** тело HTTP-ответа контроллера: аргумент ResponseEntity или значение, возвращаемое через return из метода с @GetMapping, @PostMapping или @RequestMapping. Срабатывает только на данные с меткой CONCAT
- **Санитайзер:** HTML-экранирование или очистка пользовательского ввода





Результаты запуска правила:

| Версия | Результат | Комментарий |
| --- | --- | --- |
| Уязвимая | TP | сработал недостающий синк |
| Исправленная | TN | в синк попал источник, к которому был применён санитайзер |

Фрагмент находки (заполняется для TP):

| Поле | Значение |
| --- | --- |
| ID правила | `tainted-html-string` |
| CWE | 79 |
| Файл | `main/java/nsu/security/demoapplication/controller/XssController.java` |
| Строка | 21 |
| Сообщение сканера | Detected user input flowing into a manually constructed HTML string. You may be accidentally bypassing secure methods of rendering HTML by manually constructing HTML and this could create a cross-site scripting vulnerability, which could let attackers steal sensitive user data. To be sure this is safe, check that the HTML is rendered safely. You can use the OWASP ESAPI encoder if you must render user data. |

Обоснование классификации: это TP, поскольку сканер верно определил тип уязвимости, локацию в коде, и уязвимость действительно эксплуатируется

## 6. Выводы
Сканирование semgrep с набором p/java не обнаружило внедрённую XSS (FN), хотя покрывающее правило tainted-html-string в наборе есть: источник и метка CONCAT совпали, но стоком правило считает только ResponseEntity, а уязвимый метод возвращает String напрямую. Это показывает главное ограничение SAST на основе правил: сканер находит только те варианты уязвимости, которые явно описаны в модели правила (источники, стоки, санитайзеры), и пропускает эквивалентные по смыслу конструкции. После добавления недостающего стока — значения, возвращаемого через return из метода-обработчика Spring, — правило дало TP на уязвимой версии и TN на исправленной. Для практики это значит, что отсутствие находок не доказывает отсутствие уязвимостей: готовые наборы правил стоит проверять на собственных тестовых примерах и дополнять правилами под используемые в проекте фреймворки и способы формирования ответа.
