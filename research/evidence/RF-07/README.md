# RF-07 — кандидат на `GEngine`

Метод RF-07 (`plan.md` строка 529 и M2s exit criterion (4)): найти кандидатный адрес глобала
`GEngine` через строки-якоря из `UnrealEngine.cpp` и корреляцию с местом присвоения в исходнике UE
5.4.4 (changelist 35576357). Цепочка метода — как предписано в задаче волны: candidate → static
структура → xrefs → строки/константы → корреляция с исходником → попытка опровержения →
build-specific сигнатура.

`build_key = sha256:0eef3715244b467c830022c4260a0e2c29c7def1429cb34aa37fdf9b7e14a383`.

## Поправка к постановке задачи, обнаруженная при чтении источника

Заданию волны и `plan.md` строка 529 называют `UnrealEngine.cpp` местом, «где `GEngine` реально
присваивается». Это неточно для CL 35576357: `UnrealEngine.cpp:371` только ОБЪЯВЛЯЕТ хранилище
(`ENGINE_API UEngine* GEngine = NULL;`) и `UnrealEngine.cpp:3487` ОБНУЛЯЕТ его при
`UEngine::FinishDestroy()`. Реальное присваивание ненулевого значения — `GEngine = NewObject<UEngine>(GetTransientPackage(), EngineClass);` —
находится в `Engine/Source/Runtime/Launch/Private/LaunchEngineLoop.cpp:4830`, внутри
`FEngineLoop::Init()`, в ветке `if (!GIsEditor)` (путь пакетированной игры). `UnrealEngine.cpp`
остаётся ценным, но как файл с большинством ПОТРЕБИТЕЛЕЙ `GEngine` (87 упоминаний, 70 через
`GEngine->`), а не как место записи. Это тот самый тип расхождения, о котором явно предупреждает
контекст волны («layouts drift… a remembered offset is exactly the failure mode»), только для
исходника, а не для бинарника — и он зафиксирован здесь, а не тихо исправлен без объяснения.

## Кандидат

**Адрес глобала: `0x147bf5c18` (VA), RVA `0x7bf5c18`.**

Функция-место-присваивания: `FUN_143d96240` (entry `0x143d96240`, RVA `0x3d96240`), с размером 2137
байт, 482 инструкции, **1 входящий вызов** (соответствует тому, что `FEngineLoop::Init()`
вызывается ровно один раз из точки входа игры).

## Цепочка метода

### 1. Строки-якоря → xrefs (RF-04)

`pyghidra_scripts/dump_xrefs_for_string.py` по шести иглам, выбранным чтением
`LaunchEngineLoop.cpp:4804-4877` (макросы `SCOPED_BOOT_TIMING(x)` разворачиваются в
`TRACE_CPUPROFILER_EVENT_SCOPE_STR(x); FScopedBootTiming …(x);` — `CoreGlobals.h:91` — и передают
`x` как реальный аргумент рантайм-конструктору `FScopedBootTiming::FScopedBootTiming(const ANSICHAR*)`,
так что литерал обязан существовать в `.rdata`, даже притом что сама реализация обёрнута в
`#define USE_BOOT_PROFILING 0` — `CoreGlobals.cpp:530` — и имеет пустое тело в этой конфигурации):

| Игла | Найдено | Значение |
|---|---|---|
| `"FEngineLoop::Init"` | да | `DECLARE_SCOPE_CYCLE_COUNTER` на первой строке функции |
| `"Create GEngine"` | да | `SCOPED_BOOT_TIMING`, `LaunchEngineLoop.cpp:4821` |
| `"GEngine->ParseCommandline"` | да, как `"GEngine->ParseCommandline()"` | `LaunchEngineLoop.cpp:4861` |
| `"GEngine->Init"` | да | `LaunchEngineLoop.cpp:4875` |
| `"GEngine"` (голая, substring) | да, 5 значений | ловит и «`GEngine->Start()`» (не искалась отдельно, но нашлась) и одно совсем не связанное вхождение (см. «Опровержение» ниже) |
| `"LaunchEngineLoop.cpp"` | да, 7 xref-ов в 5 функциях | путь `__FILE__`, подтверждает, что эта TU скомпилирована в Shipping |

Ключевой результат: **все пять якорей `"FEngineLoop::Init"`, `"Create GEngine"`,
`"GEngine->ParseCommandline()"`, `"GEngine->Init"`, `"GEngine->Start()"`** обнаружены как xref из
**одной и той же функции** `FUN_143d96240`, по адресам `143d96268 < 143d96329 < 143d96452 < 143d96532 < 143d9670c`
— то есть в том же порядке, что и соответствующие операторы в `LaunchEngineLoop.cpp:4810-…` (строка
за строкой). Один из семи xref-ов `"LaunchEngineLoop.cpp"` тоже landing в `FUN_143d96240`
(`143d963ba`), остальные шесть — в четырёх ДРУГИХ функциях той же TU (не расследовались, не по теме
этой волны).

Полный результат: `gengine-xrefs.json` (сводка), JSONL — `workspace/xrefs/gengine.jsonl`
(не коммитится, C-13; sha256 `8a08bfe22a11a931f2a069b8b9048964ccd18f99a76a6d811a2ddab2f6c3d921`,
16 записей). Второй прогон с фиксированным `--recorded-at` дал **побайтово идентичный** JSONL —
детерминизм подтверждён.

### 2. Декомпиляция кандидатной функции

`fun-143d96240.json` (`dump_function.py`, полный текст — `workspace/functions/fun-143d96240.c`,
не коммитится). Построчное соответствие исходнику (адрес → строка Object.h/LaunchEngineLoop.cpp):

| Адрес | Что в дизассемблере | Строка исходника |
|---|---|---|
| `143d96324` CALL, `143d96329` LEA "Create GEngine" | вход в `SCOPED_BOOT_TIMING("Create GEngine")` | `LaunchEngineLoop.cpp:4821` |
| `143d96339` MOV RCX,[GConfig-подобное], `143d96364` LEA "`/Script/Engine.Engine`", далее второй литерал "`GameEngine`" | `GConfig->GetString(TEXT("/Script/Engine.Engine"), TEXT("GameEngine"), GameEngineClassName, GEngineIni)` — оба литерала совпадают ДОСЛОВНО | `LaunchEngineLoop.cpp:4824` |
| `143d9639d` CALL `0x1412da240` | `StaticLoadClass(UGameEngine::StaticClass(), nullptr, *GameEngineClassName)` | `LaunchEngineLoop.cpp:4825` |
| `143d963b5` MOV EDX,**0x12dc** (=4828 dec), `143d963ba` LEA "LaunchEngineLoop.cpp", `143d963ca` CALL `0x14102d3c0` | `UE_LOG(LogInit, Fatal, TEXT("Failed to load UnrealEd Engine class '%s'."), …)` — номер строки в аргументе **точно** совпадает с номером строки этого `UE_LOG` в исходнике | `LaunchEngineLoop.cpp:4826-4829`, сам `UE_LOG` на строке **4828** |
| `143d963f9` CALL `0x141132ff0`, `143d96403` **`MOV qword ptr [0x147bf5c18], RAX`** | `GEngine = NewObject<UEngine>(GetTransientPackage(), EngineClass);` — прямая запись в фиксированный адрес сразу после вызова, чья сигнатура вызова (Outer, Class, Name=0, Flags=0) совпадает с `NewObject<T>(Outer,Class,Name,Flags)` | `LaunchEngineLoop.cpp:4830` |
| `143d96452` LEA "GEngine->ParseCommandline()", `143d96462` **`MOV RCX, qword ptr [0x147bf5c18]`**, `143d96469` CALL `0x143c75170` (прямой, не через vtable) | `GEngine->ParseCommandline();` | `LaunchEngineLoop.cpp:4861-4862` |
| `143d96532` LEA "GEngine->Init", `143d96542` **`MOV RCX, qword ptr [0x147bf5c18]`**, `143d9654c` `MOV RAX,[RCX]`, `143d9654f` **`CALL qword ptr [RAX+0x2d8]`** (виртуальный вызов) | `GEngine->Init(this);` | `LaunchEngineLoop.cpp:4875-4876` |
| decompiled line 204-205, "GEngine->Start()", `(**(code**)(*DAT_147bf5c18+0x2e0))()` | `GEngine->Start();` | далее в той же функции |

`FUN_143d96240` не содержит НИ ОДНОЙ ветки `GIsEditor==true` (нет `GEditor`/`GUnrealEd`, нет
`UUnrealEdEngine`) — весь `#if WITH_EDITOR … #else check(0) #endif`-блок исходника вырезан, что
согласуется с тем, что это именно **Shipping**-компиляция non-editor пути.

### 3. Опровержение

Задача требует явной попытки опровергнуть кандидата, а не только собрать подтверждения.

* **Альтернативное объяснение для `0x147bf5c18`?** Проверено: значение пишется СРАЗУ после вызова с
  сигнатурой NewObject-семейства (4 аргумента: Outer/Class/Name=0/Flags=0), и читается ИМЕННО в тех
  местах, что помечены строками "GEngine->ParseCommandline()" / "GEngine->Init" / "GEngine->Start()"
  — три разных согласованных факта, а не один. Чтобы это было НЕ `GEngine`, реальный исходник должен
  был бы иметь другую переменную, присваиваемую в той же позиции и читаемую в тех же трёх местах —
  что противоречит прочитанному тексту `LaunchEngineLoop.cpp`. Не опровергнуто.
* **Второй, независимый источник чтения того же адреса.** `dump_xrefs_for_string.py` с иглой
  `"GEngine"` попутно нашёл строку `"Cannot create GameplayScreenshotInstance - either GEngine or
  GameViewport is null!"` по адресу `146cd8140`, в функции `FUN_144bc1590` — **совершенно другой
  подсистеме** (скриншоты геймплея), не связанной с загрузкой движка. Декомпиляция
  (`fun-144bc1590.json`, `workspace/functions/fun-144bc1590.c`) показала:
  ```c
  if ((DAT_147bf5c18 != 0) && (*(longlong *)(DAT_147bf5c18 + 0xa80) != 0)) {
  ```
  — **тот же самый адрес** `0x147bf5c18`, идиома `!= 0`-проверки, немедленно за которой следует
  разыменование по фиксированному смещению `0xa80` — ровно то, что предсказывает сообщение об
  ошибке двумя строками ниже ("either GEngine or GameViewport is null"): проверка `GEngine != nullptr
  && GEngine->GameViewport != nullptr`. Это **второе, структурно независимое подтверждение** того же
  кандидата, найденное в функции, ничем не связанной с загрузкой движка — ровно то «чтение из
  большого числа несвязанных мест в разных подсистемах», которое задание называет ожидаемым
  признаком `GEngine` как бареного указателя-глобала. Не опровергнуто, наоборот, усиливает кандидата.
* Более широкий количественный обзор ВСЕХ xref на `0x147bf5c18` (не только тех, что нашлись через
  строковые иглы) не проводился — см. «Следующий дешёвый шаг» ниже.

## Оценка

* **Evidence level: HYPOTHESIS.** Не выше — независимо от силы статического совпадения, у проекта
  нет runtime-доступа (Q-8, уровень 2 недопустим), а `plan.md` прямо требует: «офсеты… фиксируются
  только при `evidence_level = OBSERVED` из runtime-дампа» и «HYPOTHESIS-level claim is ALWAYS class I
  regardless of oracle». Здесь заявление — про то, ЧТО означает адрес `0x147bf5c18` в рантайме, то
  есть class I.
* **Confidence: 0.7.** Не выше класса I на уровне HYPOTHESIS (потолок задачи), но не ниже, чем
  «типичная нижняя граница HYPOTHESIS» — потому что это одна из самых плотно скоррелированных
  находок этого проекта: пять последовательных строковых якорей в правильном порядке в ОДНОЙ
  функции, точное совпадение номера строки `UE_LOG` (4828), дословное совпадение двух литералов
  `GConfig->GetString`, и НЕЗАВИСИМОЕ подтверждение чтения того же адреса в полностью не связанной
  функции. Не 0.99, потому что это по-прежнему единственный (статический) метод.
* **Claim class: I** (что означает адрес, а не просто что по нему лежит).
* **Oracle: `binary-analysis`.**
* **Build:** `build_key=sha256:0eef3715244b467c830022c4260a0e2c29c7def1429cb34aa37fdf9b7e14a383`.

## Что нужно для перехода выше HYPOTHESIS

Runtime-наблюдение (внешний инспектор уровня 1, Q-8 §8.4) должно показать: (1) значение по VA
`0x147bf5c18` (RVA `0x7bf5c18`) равно `NULL` до завершения `FEngineLoop::Init()` и не-`NULL` после;
(2) первые 8 байт объекта, на который указывает это значение, сами являются адресом внутри
исполняемой секции (то есть похожи на vtable-указатель); (3) в идеале — разыменование через этот
vtable на смещении `0x2d8` (слот кандидата на `UEngine::Init`) при вызове с семантически валидным
`IEngineLoop*` не приводит к падению и/или вызов чего-то по смещению `0xa80` от объекта (кандидат на
`GameViewport`) ведёт себя как указатель на `UGameViewportClient`.

## Сигнатуры

`tools/static/sigmake.py` по обеим функциям (полные протоколы — `signatures.json`/`.jsonl`,
переносимая библиотека — `library.json`):

| RVA | Метка | Длина | Маскировано | Уникальна |
|---|---|---:|---:|---|
| `0x3d96240` | `RF07_GEngine_AssignmentSite_FEngineLoopInit` | 24 | 0 | да, 1 вхождение во всём образе |
| `0x4bc1590` | `RF07_GEngine_Consumer_GameplayScreenshot` | 20 | 0 | да, 1 вхождение во всём образе |

Обе сигнатуры приняты (2 из 2 запрошенных), обе с нулевой маскированной долей (в исполняемых
секциях `.reloc` пуст — 0 из 941132 записей, см. те же пять проб на опровержение, что и у S-06/S-07,
воспроизведённые здесь без изменений в самом инструменте).

## Команды

```
python pyghidra_scripts\dump_xrefs_for_string.py ^
  --project-root D:\tools\ghidra-projects --project-name T05-primary-default-analysis ^
  --program /MISERY-Win64-Shipping.exe ^
  --needle "GEngine" --needle "GEngine->Init" --needle "GEngine->ParseCommandline" ^
  --needle "Create GEngine" --needle "FEngineLoop::Init" --needle "LaunchEngineLoop.cpp" ^
  --out research\evidence\RF-07\gengine-xrefs.json --jsonl-out workspace\xrefs\gengine.jsonl

python pyghidra_scripts\dump_function.py ^
  --project-root D:\tools\ghidra-projects --project-name T05-primary-default-analysis ^
  --program /MISERY-Win64-Shipping.exe --function 143d96240 ^
  --out research\evidence\RF-07\fun-143d96240.json --c-out workspace\functions\fun-143d96240.c

python tools\static\sigmake.py <MISERY-Win64-Shipping.exe> ^
  --rva 0x3d96240=RF07_GEngine_AssignmentSite_FEngineLoopInit ^
  --rva 0x4bc1590=RF07_GEngine_Consumer_GameplayScreenshot --chunk-index ^
  --out research\evidence\RF-07\signatures.json --jsonl-out research\evidence\RF-07\signatures.jsonl ^
  --library-out research\evidence\RF-07\library.json
```
(PowerShell — Git Bash mangles the backslash-leading `D:\tools\...` project-root argument.)

Детерминизм: `dump_xrefs_for_string.py` перезапущен с `--recorded-at` фиксированным; JSONL
побайтово совпал (sha256 `8a08bfe22a11a931f2a069b8b9048964ccd18f99a76a6d811a2ddab2f6c3d921` у обоих
прогонов). `sigmake.py` — тот же 100%-детерминированный механизм, что уже подтверждён у S-06/S-07,
повторный прогон здесь не делался отдельно.

## Следующий дешёвый шаг

Полный перечень ВСЕХ xref на данные `0x147bf5c18` (не только тех, что находятся рядом со строкой)
количественно измерил бы утверждение «читается из большого числа несвязанных мест» вместо двух
найденных вручную примеров. Готового инструмента для xref по произвольному адресу ДАННЫХ (в отличие
от функции) в этом проекте пока нет — `dump_callgraph.py` работает с графом вызовов ФУНКЦИЙ.
Дополнительно: файл `research/evidence/RF-07/uengine-vtable-crosscheck.json` (не факт про сам
`GEngine`, а перекрёстная проверка метода подсчёта слотов vtable, построенная на смещениях `0x2d8`
и `0x2e0`, найденных здесь) может быть полезен как готовый вход для RF-08 (восстановление layout
`UEngine`), если та работа продолжится.
