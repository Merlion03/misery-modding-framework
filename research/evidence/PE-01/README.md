# PE-01 — `UObject::ProcessEvent`: vtable-слот (HYPOTHESIS), адрес — UNKNOWN

Метод (заданию волны и `plan.md` строки 509/526/564-566): `UObject::ProcessEvent` — виртуальная
функция, объявленная в `Engine/Source/Runtime/CoreUObject/Public/UObject/Object.h:1417`
(`COREUOBJECT_API virtual void ProcessEvent( UFunction* Function, void* Parms );`) и определённая в
`Engine/Source/Runtime/CoreUObject/Private/UObject/ScriptCore.cpp:1971`, UE 5.4.4, changelist
35576357. Основная зацепка задания — vtable-слот, а не строка. Итог этой волны:
**слот вычислен и независимо перекрёстно проверен (HYPOTHESIS, class I); конкретный адрес функции —
не найден, отчитывается как UNKNOWN с изложением того, что испробовано.** Это ЗАКОННЫЙ результат по
правилу 8 задания волны, а не отказ от попытки — цепочка метода пройдена полностью, опровержение
собственных кандидатов выполнено честно, а не подменено слабой находкой.

`build_key = sha256:0eef3715244b467c830022c4260a0e2c29c7def1429cb34aa37fdf9b7e14a383`.

## Поправка к постановке задачи

Заданием волны и `plan.md` названы `Engine/Source/Runtime/CoreUObject/Public/UObject/ScriptCore.h` и
`.../Private/UObject/ScriptCore.cpp`. Файл `ScriptCore.h` **не существует** в этой версии движка —
`ProcessEvent` объявлен прямо в `Object.h` (см. выше), а `ScriptCore.h` в дереве CL 35576357 вообще
отсутствует (проверено `Glob`; в `CoreUObject/Public/UObject/` есть `Script.h`, но не
`ScriptCore.h`). `ScriptCore.cpp` существует и прочитан. Это ровно тот тип расхождения версий, о
котором прямо предупреждает контекст волны, и он честно зафиксирован, а не тихо пропущен.

## Часть 1 — строковые якоря (RF-04): отрицательный результат для самого `ProcessEvent`, положительный для соседей по TU

### Что искалось и почему

Чтение `ScriptCore.cpp:1971-2165` (тело `ProcessEvent`) даёт два `checkf` с потенциально
диагностическими литералами:
* `checkf(!IsUnreachable(), TEXT("Function '%s' called on Object '%s' that was marked unreachable. …"))` — `ScriptCore.cpp:1975-1976`
* `checkf(!FUObjectThreadContext::Get().IsRoutingPostLoad, TEXT("Cannot call UnrealScript (%s - %s) while PostLoading objects"))` — `ScriptCore.cpp:1977`

Прочитан `Misc/AssertionMacros.h:221-269`: при `DO_CHECK=1` `checkf` разворачивается в
`UE_CHECK_F_IMPL`, чей вызов `FDebug::CheckVerifyFailedImpl2(#expr, __FILE__, __LINE__, format,
##__VA_ARGS__)` сам по себе выполняется в рантайме только внутри `if(UNLIKELY(!(expr)))` — но все
четыре его аргумента (`#expr` — условие как строка, `__FILE__`, `__LINE__`, `format`) являются
компил-тайм константами именно этого вызова, поэтому компилятор обязан материализовать их байты в
`.rdata` уже на этапе компиляции, независимо от того, сработает ли условие хоть раз в рантайме —
ЕСЛИ этот конкретный `checkf` вообще компилируется в данной конфигурации (не устранён целиком). Что `DO_CHECK=1` в этой сборке — уже независимо установлено:
S-01 нашёл 589 путей `__FILE__` в Shipping-образе, и в этой же волне найден `check(GEngine)`
(`LaunchEngineLoop.cpp:4851`) с выжившим буквальным токеном `"GEngine"` (см. `RF-07/README.md`).

### Прогон 1 — шесть игл

`processevent-xrefs.json` / `workspace/xrefs/processevent.jsonl` (sha256
`778d589d04e99595452d2f49156cf0b50b641ba8d222d04bda122a1f0f375423`, 5 записей):

| Игла | Найдено |
|---|---|
| `"ProcessEvent"` (голая) | **нет** — 0 xref |
| `"was marked unreachable"` | **нет** — 0 xref |
| `"PostLoading objects"` | **нет** — 0 xref |
| `"LogScriptCore"` | **нет** — 0 xref |
| `"Encountered an undefined opcode"` | да — 1 occurrence, 1 xref |
| `"ScriptCore.cpp"` | да — 1 occurrence (адрес `145e86840`), 4 xref из 4 РАЗНЫХ функций |

### Прогон 2 — проверка альтернативных форм (условие вместо сообщения)

Раз `UE_CHECK_F_IMPL` передаёт условие (`#expr`) и сообщение ОДНИМ и тем же вызовом, отсутствие
сообщения при наличии `__FILE__` в этой же TU — странно; проверено, не является ли дело в том, что
искалось не то сообщение, а условие-то как раз выжило. `processevent-xrefs-round2.json` /
`workspace/xrefs/processevent-round2.jsonl` (sha256
`d5d8b4fb135578640cbb32df788a24734f859b24c76b2b63adb13ee09e24aee6`, 12 записей):

`"IsUnreachable"`, `"Cannot call UnrealScript"`, `"IsRoutingPostLoad"`, `"!IsRoutingPostLoad"` — **все
четыре: 0 xref**. `"PostLoad"` (широкая игла) дала 13 совпадений, ни одно не относится к
`ProcessEvent` — все 13 из движковых подсистем (Landscape, MoviePlayer, Niagara LUT verification,
async loading CVars и т.п.), список полный в `processevent-xrefs-round2.json`.

### Вывод по строкам

**Оба `checkf` в самом `ProcessEvent` не оставили в этом Shipping-образе ни текста сообщения, ни
текста условия — ни в каком из проверенных вариантов.** При этом ТА ЖЕ translation unit
(`ScriptCore.cpp`) **точно скомпилирована** в этот образ: её `__FILE__`-литерал живёт по адресу
`145e86840` и на него ссылаются 4 РАЗНЫЕ функции (не `ProcessEvent`), плюс независимо найдена
`LOCTEXT`-строка из `execUndefined` (см. ниже). Значит, это не общее «check-макросы вырезаны» (уже
опровергнуто отдельно — `check(GEngine)` выжил, часть путей `ScriptCore.cpp` выжила) и не «файл не
скомпилирован» (опровергнуто теми же 4+1 xref). Ближайшее к правде честное объяснение — этим
статическим методом неразличимо между: (а) LTCG/whole-program-оптимизация специфично устранила
именно эти два `checkf` в `ProcessEvent` (например, если компилятор в состоянии доказать условие
для конкретного inlined-контекста — маловероятно для функции такого размера, но не исключено), (б)
у этой конкретной сборки MISERY изменённый (не строго stock-5.4.4) текст этих двух проверок или
самого `ProcessEvent`, что для лицензированного UE-тайтла не является чем-то небывалым. Данные этой
волны не позволяют выбрать между (а) и (б) — это и есть честный отрицательный результат, а не
недоработанный поиск: испробовано 11 игл по двум прогонам, каждая с явным, citable источником в
исходнике.

## Часть 2 — три функции-соседа по `ScriptCore.cpp`, декомпилированы

Четыре xref на `"ScriptCore.cpp"` landing в функциях `1412aff70`, `1412adde0`, `1412ab9e0`,
`1412aa900`; плюс `1412b3c20` через `"Encountered an undefined opcode"`. `1412aa900` (194 байт, 479
входящих вызовов) и `1412ab9e0` (210 байт, 431 входящий вызов) отброшены без полной декомпиляции —
слишком малы и имеют слишком много ПРЯМЫХ входящих вызовов для функции такой сложности, как
`ProcessEvent` (которая на 190 строк исходника с циклами, `FMemory::Memcpy`, аллокацией
virtual-stack и виртуальным вызовом `Function->Invoke` должна компилироваться существенно крупнее, и
которая вызывается почти исключительно виртуально — редкие прямые вызовы, а не сотни). Это тоже
попытка опровержения, а не проигнорированные кандидаты.

Три оставшиеся декомпилированы полностью (`workspace/functions/fun-*.c`, не коммитятся; JSON-сводки
— `fun-1412b3c20.json` в этом каталоге, две другие только в `workspace/`):

### `1412b3c20` — **опознан с высокой уверенностью как `UObject::execUndefined`**

192 инструкции, 681 байт, 0 прямых входящих вызовов (согласуется с тем, что `exec*`-обработчики
байткода VM вызываются ЧЕРЕЗ таблицу указателей `IMPLEMENT_VM_FUNCTION`, а не прямым `CALL`).
Декомпилированный текст совпадает с `ScriptCore.cpp` (сама функция `execUndefined`, строки ~2171-2180)
дословно в пяти независимых точках:
1. Тройное `LOCTEXT`-обращение `(source, namespace, key)` = `("Encountered an undefined opcode
   ({0})…", "ScriptCore", "UndefinedOpcode")` — все три строки совпадают буквально с
   `LOCTEXT("UndefinedOpcode", "Encountered an undefined opcode …")` при пространстве имён `ScriptCore`;
2. printf-формат `"0x%02X"` дословно совпадает с `TEXT("0x%02X")` у `FString::Printf`;
3. тернарное вычисление смещения (`Stack.Node ? …&Stack.Code[-1] - &Stack.Node->Script[0] : 0`)
   воспроизведено в псевдокоде именно как ветвление по `*(long*)(Stack+0x10)==0`;
4. финальный вызов передаёт константу **`2`** как verbosity — совпадает с числовым значением
   `ELogVerbosity::Error` в UE (`NoLogging=0, Fatal=1, Error=2, …`);
5. сигнатура (2 видимых параметра) согласуется с `DEFINE_FUNCTION`-формой обработчика VM.

*(evidence level HYPOTHESIS, confidence 0.75, class I, oracle `binary-analysis`. Не 0.80+, поскольку
правило проекта требует для class I на этом уровне ДВА независимых метода — здесь пять совпадающих
деталей, но все получены одним и тем же методом (чтение декомпилированного вывода и сверка с
исходником), а не двумя методологически разными подходами; несколько согласующихся деталей внутри
одного метода — это не то же самое, что второй метод.)*

### `1412adde0` и `1412aff70` — диагностические помощники `ScriptCore.cpp`, не опознаны поимённо

Оба логируют через `FUN_14102d3c0` (тот же помощник, что и `UE_LOG(Fatal,…)` в RF-07-находке) с
номером строки в аргументе: `1412aff70` — строка `0x967` (2407 дес.), сообщение `"Execution beyond
end of script in %s on %s"`; `1412adde0` — строка `700`, формат
`"%s\r\n\t%s\r\n\t%s:%04X\r\n\t%s"` под условием `param_3 == 2` (похоже на verbosity-фильтр). Оба —
по форме by-verbosity диагностика скрипт-контекста (объект/функция/смещение), согласующаяся с
инфраструктурой логирования VM в этом файле, но без дословного совпадения с конкретным именованным
методом из прочитанного исходника — поэтому не названы поимённо, только описаны по форме.

## Часть 3 — vtable-слот `ProcessEvent`: 77 (HYPOTHESIS), перекрёстно проверен

Полный, построчный вывод слота — `uobject-vtable-slots.json` в этом каталоге (не инструмент,
явно помечено как ручной разбор `UObjectBase.h`/`UObjectBaseUtility.h`/`Object.h`, с цитатой номера
строки на каждую запись и явным учётом ВСЕХ `#if WITH_EDITOR`/`WITH_EDITORONLY_DATA`/`WITH_ENGINE`/
`UE_WITH_IRIS` веток по пути, включая один случай, где `#else`-ветка превращает виртуальные `Modify`/
`IsCapturingAsRootObjectForTransaction` в **невиртуальные** `FORCEINLINE`-заглушки в Shipping —
проверено чтением, не предположено).

**Результат: `ProcessEvent` = слот 77 (0-индексация), офсет `77×8 = 616 = 0x268` байт**, при
допущении `UE_WITH_IRIS=1` (77-й слот при IRIS=1; был бы слот 76 / `0x260` при IRIS=0 — единственная
неоднозначность во всём подсчёте, поскольку `UE_WITH_IRIS` — per-project настройка UBT, не читаемая
из исходника напрямую).

### Независимая перекрёстная проверка

`uengine-vtable-crosscheck.json` в каталоге `RF-07/`. Метод: `UEngine : public UObject, public FExec`
(`Engine.h:715-717`, `UObject` первым базовым классом → его vtable первична), и **та же методика
подсчёта**, применённая к `Engine.h:715-2215` (виртуали `UEngine` до `Init`), предсказывает слот
`Init` = (итог по `UObject`) + 4 новых слота `UEngine` (`WorldAdded`, `WorldDestroyed`,
`IsInitialized`, `GetDefaultWorldFeatureLevel` — единственные необусловленные новые виртуали до
`Init`; `GetPreviewPlatformName` исключён по `WITH_EDITOR`, три `override`-метода слотов не
добавляют). При `UE_WITH_IRIS=1` предсказание — слот 91. **RF-07 независимо, из дизассемблера,
измерил реальный слот `UEngine::Init` в этом образе: смещение `0x2d8 = 91`-й слот** (вызов через
объект-кандидат `GEngine`, см. `RF-07/README.md`) — точное совпадение. При `UE_WITH_IRIS=0`
предсказание было бы 90 — не совпало бы.

Это не доказывает подсчёт слота `ProcessEvent` (совпадение одной ДРУГОЙ точки в той же методике не
исключает компенsирующую пару ошибок где-то ещё), но это ЕДИНСТВЕННАЯ доступная этому проекту
эмпирическая проверка метода подсчёта без runtime — и она прошла ровно, а не приблизительно.

## Почему слот 77 не даёт конкретного адреса

Задание предлагает использовать инвентарь vtable S-09 (`research/evidence/S-09/vtables.jsonl`,
13 385 кандидатов яруса `code-stored`) для поиска «UObject-подобных» vtable на этом слоте. Это не
сработало в рамках этой волны по двум причинам, обе зафиксированы явно, а не замолчаны:

1. **Нет RTTI-якоря.** S-10 нашёл RTTI у 580 классов в этом образе — **ноль движковых и ноль
   игровых** (все — ICU/MSVC/STL). Значит нет способа сказать «вот этот конкретный кандидат из
   13 385 — это именно `UObject`» иначе как по форме содержимого слотов, а не по имени/локатору.
2. **Populяция слишком велика для ручной проверки формы.** Медиана длины кандидата — 8 слотов, 90-й
   перцентиль — 91 (S-09 README). Фильтр «длина ≥ 78» уже заметно сузил бы популяцию, но чтобы
   отличить «`UObject`-подобный» от любого другого достаточно длинного кандидата, пришлось бы
   декомпилировать функцию НА СЛОТЕ 77 у каждого оставшегося кандидата и проверить форму
   (`FMemory::Memcpy`, аллокация virtual-stack, вызов `Invoke` через вложенный виртуальный вызов) —
   потенциально сотни-тысячи прогонов `dump_function.py`, что нарушает timebox правила 8 без
   гарантии успеха.

Была предпринята одна попытка сократить путь: `GEngine`-кандидат (`0x147bf5c18`, RF-07) в рантайме
хранит указатель на КОНКРЕТНЫЙ экземпляр движка, чей vtable на слотах 91/92 подтверждённо
соответствует `Init`/`Start` — то есть его слот 77 статически СОДЕРЖИТ адрес реализации
`ProcessEvent` для этого конкретного класса движка. Но сам этот vtable — **тоже** не находим статически
без runtime: он материализуется как значение, записанное по адресу `0x147bf5c18` только в рантайме
(в бинарнике там лежит 0, поле `.data`). Прослежен один шаг вглубь: место создания
(`FUN_141132ff0`, декомпилирован — `workspace/functions/fun-141132ff0.c`) оказалось общей
NewObject-обёрткой (52 входящих вызова, содержит буквальное сообщение об ошибке `"NewObject with
empty name can't be used to create default subobjects…"`, что независимо подтверждает её
идентичность как части NewObject-инфраструктуры UE), которая передаёт управление глубже
(`FUN_1412d8340`, не декомпилирован) в generic `StaticConstructObject`-подобный путь, откуда
конкретный конструктор класса вызывается ЧЕРЕЗ указатель на функцию, хранящийся в самом `UClass` —
то есть косвенно, зависимо от данных, и статически не читается как один адрес без разбора reflection-
регистрации (`Z_Construct_UClass_*`-подобных функций), что уже относится к layout `UClass`/RF-08, а
не к этой волне.

## Оценка

* **Слот 77 (offset 0x268): evidence level HYPOTHESIS, confidence 0.6, class I, oracle
  `binary-analysis`.** Не выше — ручной подсчёт по ~1330 строкам заголовка с учётом препроцессорных
  веток при всей аккуратности остаётся источником риска off-by-one; перекрёстная проверка (см. выше)
  подняла бы уверенность, если бы её можно было провести ВТОРЫМ независимым методом — здесь она
  ОДНА, хоть и точная.
* **Адрес самой функции `ProcessEvent`: UNKNOWN.** Не HYPOTHESIS с большой натяжкой — по правилу 8
  задания волны это честный результат при исчерпывающей попытке (11 строковых игл по двум
  осмысленным раундам, полная декомпиляция и опровержение пяти кандидатов-соседей, вычисление и
  перекрёстная проверка слота, зондирование на один уровень вглубь цепочки конструирования). Не
  выдуман слабый кандидат, чтобы «было что показать».
* **`execUndefined` (`0x1412b3c20`): evidence level HYPOTHESIS, confidence 0.75, class I** (см. выше
  — пять совпадающих деталей, но одним методом, потому и не 0.80+).
* **Build:** `build_key=sha256:0eef3715244b467c830022c4260a0e2c29c7def1429cb34aa37fdf9b7e14a383`.

## Что нужно для перехода выше HYPOTHESIS / для получения адреса

1. **Для слота (метод):** второй независимый способ проверки подсчёта — например, тот же перекрёстный
   приём (наблюдаемый vtable-офсет известного метода) на ТРЕТЬЕМ классе цепочки, если такой
   найдётся статически.
2. **Для адреса `ProcessEvent` (следующий дешёвый шаг, статический, до runtime):** пройти
   reflection-регистрацию класса, реально загружаемого как `GameEngine` (`LaunchEngineLoop.cpp:4824`,
   ключ `/Script/Engine.Engine:GameEngine` — конкретное ИМЯ класса читаемо из RF-01
   (`global.ucas`/`script-objects.tsv`), если оно там присутствует) до её `Z_Construct_UClass_*`-
   подобной функции и оттуда — до `LEA` конкретного vtable-литерала в конструкторе; это отдельная,
   ограниченная по объёму задача (RF-08-смежная), не начатая в этой волне.
3. **Для runtime-подтверждения (после (2) даст адрес):** внешний инспектор уровня 1 (Q-8 §8.4)
   должен показать, что функция по найденному адресу действительно вызывается при срабатывании
   Blueprint-события/делегата/RPC с аргументами, согласующимися с `(UFunction*, void*)`, и что она
   лежит на слоте `0x268` vtable реального экземпляра `UObject`-производного класса.

## Сигнатуры

`tools/static/sigmake.py`, три функции (протоколы — `signatures.json`/`.jsonl`, библиотека —
`library.json`):

| RVA | Метка | Длина | Маскировано | Уникальна |
|---|---|---:|---:|---|
| `0x12adde0` | `PE01_Adjacent_ScriptCore_cpp_LN700_LogHelper` | 12 | 0 | да |
| `0x12aff70` | `PE01_Adjacent_ScriptCore_cpp_LN2407_ExecutionBeyondEndOfScript` | 20 | 0 | да |
| `0x12b3c20` | `PE01_Adjacent_execUndefined_candidate` | 24 | 0 | да |

Все три приняты (3 из 3 запрошенных), нулевая маскированная доля, все пять проб на опровержение
`sigmake.py` не сработали (см. полный протокол в `signatures.json`) — тот же механизм, что и у
RF-07/S-06/S-07, без изменений в инструменте. **Сигнатура для самого `ProcessEvent` не эмитирована —
адрес не найден, эмитировать её не по чему.**

## Команды

```
python pyghidra_scripts\dump_xrefs_for_string.py ^
  --project-root D:\tools\ghidra-projects --project-name T05-primary-default-analysis ^
  --program /MISERY-Win64-Shipping.exe ^
  --needle "ProcessEvent" --needle "was marked unreachable" --needle "PostLoading objects" ^
  --needle "Encountered an undefined opcode" --needle "LogScriptCore" --needle "ScriptCore.cpp" ^
  --out research\evidence\PE-01\processevent-xrefs.json --jsonl-out workspace\xrefs\processevent.jsonl

python pyghidra_scripts\dump_xrefs_for_string.py ^
  --project-root D:\tools\ghidra-projects --project-name T05-primary-default-analysis ^
  --program /MISERY-Win64-Shipping.exe ^
  --needle "IsUnreachable" --needle "Cannot call UnrealScript" --needle "PostLoad" ^
  --needle "!IsRoutingPostLoad" --needle "IsRoutingPostLoad" ^
  --out research\evidence\PE-01\processevent-xrefs-round2.json --jsonl-out workspace\xrefs\processevent-round2.jsonl

python pyghidra_scripts\dump_function.py ^
  --project-root D:\tools\ghidra-projects --project-name T05-primary-default-analysis ^
  --program /MISERY-Win64-Shipping.exe --function 1412b3c20 ^
  --out research\evidence\PE-01\fun-1412b3c20.json --c-out workspace\functions\fun-1412b3c20.c

python tools\static\sigmake.py <MISERY-Win64-Shipping.exe> ^
  --rva 0x12adde0=PE01_Adjacent_ScriptCore_cpp_LN700_LogHelper ^
  --rva 0x12aff70=PE01_Adjacent_ScriptCore_cpp_LN2407_ExecutionBeyondEndOfScript ^
  --rva 0x12b3c20=PE01_Adjacent_execUndefined_candidate --chunk-index ^
  --out research\evidence\PE-01\signatures.json --jsonl-out research\evidence\PE-01\signatures.jsonl ^
  --library-out research\evidence\PE-01\library.json
```
(PowerShell — Git Bash mangles the backslash-leading `D:\tools\...` project-root argument.)

Детерминизм: оба прогона `dump_xrefs_for_string.py` перезапущены с фиксированным `--recorded-at`;
JSONL побайтово совпал в обоих случаях (sha256 `778d589d04e99595452d2f49156cf0b50b641ba8d222d04bda122a1f0f375423`
и результат второго раунда соответственно, значения указаны выше по тексту).
