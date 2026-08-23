# Сборка `misery-24826585-ue5.4.4-0eef3715244b`

Базовая (baseline) запись о конкретной установленной сборке MISERY, зафиксированная
на этапе **M0**. Всё, что здесь лежит, получено обходом установки **исключительно в
режиме чтения** — decision **D-01**: папка игры является read-only объектом
исследования, в неё ничего не создаётся, не изменяется, не перемещается и не удаляется.

> **Версия движка 5.4.4 в имени этой директории — PROVISIONAL до M1.**
> Значение взято из двух независимых источников на этапе recon (UTF-16 строки внутри
> Shipping-образа и `CrashContext.runtime-xml` из отчётов о падениях), но формальная
> процедура подтверждения (plan.md 4.2, требование confidence >= 0.90 и >= 3
> независимых источников) выполняется только в M1. В `install-inventory.json` это
> отражено полем `engine_version.provisional = true`. Не подавайте `5.4.4` как
> установленный факт.

---

## 1. Что лежит в этой директории

| Файл | Статус | Что это |
|---|---|---|
| `install-inventory.json` | **есть** | Полная инвентаризация установки: по строке на каждый файл (`path`, `size`, `mtime`, `mtime_epoch`, `sha256`, `sha1`), блок `steam`, ключи идентичности, `tree_hash`. Схема: `research/schema/install-inventory.schema.json`. |
| `notes.md` | **есть** | Этот файл. |
| `install.json` | **ОТСУТСТВУЕТ** | Результат работы discovery (plan.md 2.2). Не сгенерирован: инструмент `tools/discovery/find_misery.py` на момент прогона M0 отсутствует в репозитории. Осознанно не создавался вручную, чтобы не выдавать рукописный файл за вывод инструмента. |
| `fingerprint.json` | ожидается в M1 | plan.md 3.1, задачи F-01..F-05. |
| `anomalies.md` | ожидается в M1 | Список аномалий, обязательно включая **A-05**. |

Эта сборка зарегистрирована в реестре `research/builds/index.json` по своему
`build_key`.

---

## 2. Идентичность сборки: `build_key`, `content_key`, `build_id`

Определения — plan.md 3.2. Смысл разделения: Steam `buildid` может измениться без
изменения исполняемого файла, и наоборот, поэтому Steam-номер **не** является
идентичностью.

### `build_key` — первичная, каноническая идентичность

```
build_key = sha256( MISERY/Binaries/Win64/MISERY-Win64-Shipping.exe )
```

Значение для этой сборки:

```
sha256:0eef3715244b467c830022c4260a0e2c29c7def1429cb34aa37fdf9b7e14a383
```

Хранится с префиксом `sha256:` — это форма, требуемая
`kb-record.schema.json#/$defs/build_key`, и она же используется как имя ключа в
`research/builds/index.json`. **Все записи базы знаний ссылаются на `build_key`, а не
на `build_id`**, потому что `build_key` не меняется при переименованиях директорий.

Источник — именно Shipping-образ (134 658 048 байт, 9 PE-секций). Второй файл
`MISERY/Binaries/Win64/MISERY.exe` (282 826 240 байт, 10 секций, включая `.uedbg`)
идентичностью **не** является: decision **D-04** — только read-only оracle, и тезис
«Development build» остаётся HYPOTHESIS (confidence 0.65), а не фактом.

### `content_key` — идентичность контента

```
content_key = sha256( concat( sha256 всех .utoc ) )
```

Значение:

```
sha256:55ff0e5f605d4777863bd6b061332eaf351da5800dc80c6f826547c2722f9039
```

Правило упорядочивания (зафиксировано и в поле `notes` самого артефакта): конкатенация
lowercase hex-дайджестов sha256 каждого `.utoc`, в ASCII, без разделителей, при
сортировке по нормализованному пути по возрастанию. Вклад дали два файла:
`MISERY/Content/Paks/MISERY-Windows.utoc`, затем `MISERY/Content/Paks/global.utoc`.

Зачем отдельно: если exe не изменился, а контейнеры изменились — это **патч только
контента**, и он виден как новый `content_key` при том же `build_key`. Обратный случай
(патч кода) даёт новый `build_key`.

### `build_id` — читаемое имя и имя директории

```
build_id = "misery-" + <steam_buildid> + "-ue" + <engine_version> + "-" + <build_key[0:12]>
         = "misery-" + 24826585 + "-ue" + 5.4.4 + "-" + 0eef3715244b
         = misery-24826585-ue5.4.4-0eef3715244b
```

`build_key[0:12]` — это первые 12 символов **чистого hex-дайджеста**, без префикса
`sha256:`. Важное следствие: `build_id` содержит `ue5.4.4`, то есть **provisional**
версию движка. Если M1 уточнит версию, `build_id` изменится, а прежнее имя обязано
попасть в `aliases` соответствующей записи `research/builds/index.json`.

### `tree_hash`

```
4bc6d70c6bb6d47af6817d42b699f818609625af81f2c61d98e678661bc09959
```

sha256 по канонической сериализации строк инвентаря: для каждой строки, отсортированной
по `path`, байты `'<path>\n<size>\n<sha256>\n'` в UTF-8. Должен совпасть с
`layout.tree_hash` в `fingerprint.json`, когда тот появится в M1 — это встроенная
перекрёстная проверка.

---

## 3. Наблюдаемые факты этой сборки (OBSERVED)

| Поле | Значение |
|---|---|
| `file_count` | 53 |
| `total_size` | 5 057 001 973 байт |
| `install_dir` | `D:\Games\Steam\steamapps\common\MISERY` |
| Steam `app_id` | 2119830 |
| Steam `steam_buildid` | 24826585 |
| Steam `depot_id` / `depot_manifest_id` | 2119831 / `3002776385514127223` |
| Steam `shared_depots` | 228989, 228990, 229007 (все из app 228980, Steamworks redist) |
| Steam `size_on_disk` | 5 057 001 973 байт — совпадает с суммой размеров файлов |
| Steam `last_updated_epoch` | 1787394913 |
| `generated_at` артефакта | 2026-08-22T12:19:17Z |

Совпадение `total_size` и `size_on_disk` — не округление, а именно совпадение:
расхождение здесь считалось бы находкой.

---

## 4. Как воспроизвести каждый артефакт

Все команды выполняются из корня репозитория `D:\Dev\MiseryFramework`.
Интерпретатор — `C:\Python314\python.exe` (венв `D:\Tools\venv-research` нужен только
для PyGhidra, здесь он не требуется).

### 4.1 `install-inventory.json`

```
C:\Python314\python.exe tools\inventory\snapshot_install.py ^
    --out research\builds\misery-24826585-ue5.4.4-0eef3715244b\install-inventory.json
```

Значения по умолчанию уже соответствуют этой машине (`--install-dir
D:\Games\Steam\steamapps\common\MISERY`, `--app-id 2119830`, `--expected-file-count 53`,
`--engine-version 5.4.4`). Инструмент печатает в stdout ровно одну строку —
`build_id=<значение>`, а человекочитаемую сводку в stderr.

Хеширование потоковое, буфер 1 MiB, sha256 и sha1 за один проход, поэтому файл на
4,3 ГБ (`MISERY-Windows.ucas`) читается один раз и пиковая память остаётся малой.

### 4.2 Проверка воспроизводимости

Критерий выхода: два прогона по неизменному дереву дают **побайтово одинаковый** вывод,
за исключением поля `generated_at`.

```
C:\Python314\python.exe tools\inventory\snapshot_install.py --out %TEMP%\inv-a.json
C:\Python314\python.exe tools\inventory\snapshot_install.py --out %TEMP%\inv-b.json
fc /b %TEMP%\inv-a.json %TEMP%\inv-b.json
```

Ожидаемый результат: расхождение ровно в одной строке — `generated_at`. Проверено
2026-08-22: два прогона дали 2 изменённые строки в `diff` (по одной `-`/`+`), и после
удаления `generated_at` документы совпали побайтово; `tree_hash` был стабилен.

### 4.3 Проверка целостности установки против baseline

```
C:\Python314\python.exe tools\inventory\verify_install.py ^
    research\builds\misery-24826585-ue5.4.4-0eef3715244b\install-inventory.json
```

Полный режим перехеширует все файлы. Быстрый режим — `--fast` (сравнивает только
`size` + `mtime` и потому **не** доказывает целостность содержимого). Код возврата 0
означает совпадение с baseline. Проверено 2026-08-22: `RESULT: MATCH`, exit code 0.

### 4.4 Валидация базы знаний

```
C:\Python314\python.exe tools\kb\validate.py research
```

Проверено 2026-08-22: 0 violations, 0 warnings, в том числе с `--strict`.

### 4.5 `install.json` (пока невозможно)

Как только `tools/discovery/find_misery.py` появится в репозитории:

```
C:\Python314\python.exe tools\discovery\find_misery.py ^
    --out research\builds\misery-24826585-ue5.4.4-0eef3715244b\install.json
```

Точные флаги нужно сверить с `--help` инструмента — приведённая строка является
ожиданием, а не проверенной командой. После генерации следует заполнить
`artifacts.install_json` в `research/builds/index.json`.

---

## 5. Что про эту сборку ещё НЕ известно (UNKNOWN до M1)

Ни один из пунктов ниже не должен подаваться как факт до закрытия M1.

| Тема | Состояние | Где будет закрыто |
|---|---|---|
| **PE-метаданные** | UNKNOWN. Инвентарь знает только размер и хеши образов. Секции, импорты, экспорты, debug directory, timestamp компоновки, наличие/отсутствие PDB-пути — не разобраны. Число секций (9 у Shipping, 10 у `MISERY.exe`) получено при recon и требует перепроверки инструментом. | F-01, `tools/fingerprint/pe_info.py` |
| **RTTI** | UNKNOWN. Присутствует ли RTTI в Shipping-образе, и если да — в каком объёме, не установлено. Ответ является частью exit criteria M1. | M1, S-10 |
| **Анти-отладка / анти-чит** | UNKNOWN и это **гейт**. Наличие анти-чита (вопрос Q-8.3) блокирует весь раздел plan.md 8 (инструментирование). До получения ответа не следует планировать работу с процессом. | M1, Q-8.2 / Q-8.3 |
| **Directory index контейнера** | UNKNOWN. `MISERY-Windows.utoc` имеет `ContainerFlags 0x0A` = Encrypted \| Indexed, содержимое высокоэнтропийное, то есть зашифровано. Decision **D-02**: ключ шифрования не извлекается и основной контейнер не расшифровывается. Поэтому directory index этого контейнера может остаться UNKNOWN навсегда. `global.utoc` — `ContainerFlags 0x00`, `DirectoryIndexSize 0`, не зашифрован. | F-02, с учётом D-02 |
| **Имена пакетов (`/Game/...`)** | UNKNOWN. Прямое следствие предыдущего пункта: без directory index список пакетов из основного контейнера недоступен. `MISERY-Windows.pak` (версия 11) индекс не шифрует и является отдельным, более доступным источником. | plan.md 5, RF-01 |
| **Версия движка** | PROVISIONAL 5.4.4 (+ CL 35576357, branch `++UE5+Release-5.4`, configuration Shipping — всё из recon). В `install-inventory.json` поля `cl`, `branch`, `build_configuration` намеренно **отсутствуют**: `snapshot_install.py` получает версию из аргумента, а не из бинарника, и не имеет права заявлять их происхождение. | M1, plan.md 4.2, `engine-version.json` |
| **A-05** | Аномалия зафиксирована при recon: `MISERY/Binaries/Win64/MISERY.exe` отсутствует в `Manifest_NonUFSFiles_Win64.txt`. Автоматическая перепроверка ещё не реализована: блок `non_ufs_manifest` в инвентаре не заполнен. | F-05 |

---

## 6. Ограничения этого baseline

* `install-inventory.json` фиксирует состояние **на 2026-08-22T12:19:17Z**. Любое
  обновление игры через Steam делает baseline устаревшим; признак — изменение
  `build_key` (патч кода) или `content_key` (патч контента) при повторном прогоне
  `snapshot_install.py`.
* Инвентарь содержит только файлы; директории строками не являются, поэтому
  `file_count = 53` считает именно файлы.
* `mtime` в артефакте — UTC с точностью до микросекунд, вычисляется из `st_mtime_ns`
  целочисленной арифметикой, поэтому в документ не попадает погрешность float.
  Локальное время не используется намеренно: иначе инвентарь не был бы воспроизводим
  между машинами.
* Пользовательские данные (`%LOCALAPPDATA%\MISERY\Saved\...`) в инвентарь **не**
  входят — это не часть установки. Каталог `Logs` при recon был пуст, что само по себе
  является находкой (Shipping-сборка с подавленным логированием).
